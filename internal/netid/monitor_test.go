package netid

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeNet drives a Monitor: which default route the Mac has, and how the AS
// lookup answers for it.
type fakeNet struct {
	mu      sync.Mutex
	route   string // "iface|gw", "" = offline
	asn     map[string]int
	block   chan struct{} // when set, lookups wait for it
	changes []struct{ old, cur Info }
}

func (f *fakeNet) monitor() *Monitor {
	m := &Monitor{cache: map[string]Info{}}
	m.route = func() (string, string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.route == "" {
			return "", "", errors.New("no default route")
		}
		for i := range f.route {
			if f.route[i] == '|' {
				return f.route[:i], f.route[i+1:], nil
			}
		}
		return f.route, "", nil
	}
	m.mac = func(gw string) string { return "aa:bb:" + gw }
	m.lookup = func(ctx context.Context) (int, string, error) {
		f.mu.Lock()
		r, block := f.route, f.block
		f.mu.Unlock()
		if block != nil {
			select {
			case <-block:
			case <-ctx.Done():
				return 0, "", ctx.Err()
			}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if n, ok := f.asn[r]; ok {
			return n, "TEST", nil
		}
		return 0, "", errors.New("lookup failed")
	}
	m.OnChange = func(old, cur Info) {
		f.mu.Lock()
		f.changes = append(f.changes, struct{ old, cur Info }{old, cur})
		f.mu.Unlock()
	}
	return m
}

func (f *fakeNet) setRoute(r string) { f.mu.Lock(); f.route = r; f.mu.Unlock() }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestProvisionalKeyThenASN(t *testing.T) {
	f := &fakeNet{route: "en0|192.168.1.1", asn: map[string]int{"en0|192.168.1.1": 15897}}
	m := f.monitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.poll(ctx)
	prov := m.Current()
	if !prov.Provisional || prov.Key[:3] != "gw:" || !prov.Online {
		t.Fatalf("first sight: %+v", prov)
	}
	waitFor(t, func() bool { return m.Current().Key == "asn:15897" })
	cur := m.Current()
	if cur.Provisional || cur.ASN != 15897 || cur.Label != "AS15897 TEST" {
		t.Fatalf("identified: %+v", cur)
	}
	if cur.GatewayKey != prov.Key || prov.GatewayKey != prov.Key {
		t.Fatalf("identified info must name the provisional key it replaces: prov %+v cur %+v", prov, cur)
	}

	// Offline and back on the same network: same key, no change event.
	f.setRoute("")
	m.poll(ctx)
	if m.Current().Online {
		t.Fatal("still online without a default route")
	}
	f.setRoute("en0|192.168.1.1")
	m.poll(ctx)
	if c := m.Current(); !c.Online || c.Key != "asn:15897" {
		t.Fatalf("back online: %+v", c)
	}
	f.mu.Lock()
	n := len(f.changes)
	f.mu.Unlock()
	if n != 2 { // "" -> gw, gw -> asn
		t.Fatalf("%d change events, want 2", n)
	}
}

func TestKnownNetworkComesFromCache(t *testing.T) {
	f := &fakeNet{route: "en0|10.0.0.1", asn: map[string]int{"en0|10.0.0.1": 9121, "en5|172.20.10.1": 15897}}
	m := f.monitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.poll(ctx)
	waitFor(t, func() bool { return m.Current().Key == "asn:9121" })
	homeGw := m.Current().GatewayKey
	f.setRoute("en5|172.20.10.1")
	m.poll(ctx)
	waitFor(t, func() bool { return m.Current().Key == "asn:15897" })
	f.setRoute("en0|10.0.0.1")
	m.poll(ctx)
	if c := m.Current(); c.Key != "asn:9121" || c.Provisional || c.GatewayKey != homeGw {
		t.Fatalf("a known network must be named at once: %+v", c)
	}
}

// The route moves while the AS lookup runs and the monitor has not polled the
// new one yet: the lookup answers for the new network. That answer must not be
// filed under the old network's fingerprint (where the cache would keep it
// until a restart), and the old network must still be identified once it is
// back.
func TestResolveDropsAnswerForUnpolledRoute(t *testing.T) {
	f := &fakeNet{route: "en0|10.0.0.1", asn: map[string]int{"en0|10.0.0.1": 9121, "en5|172.20.10.1": 15897}, block: make(chan struct{})}
	m := f.monitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.poll(ctx) // provisional en0, lookup waiting
	fp := m.fp
	f.setRoute("en5|172.20.10.1") // moved, not polled
	close(f.block)                // the lookup answers for en5: AS 15897
	time.Sleep(200 * time.Millisecond)
	if c := m.Current(); c.Key == "asn:15897" || !c.Provisional {
		t.Fatalf("en0 named after the network the route moved to: %+v", c)
	}
	m.mu.RLock()
	got, cached := m.cache[fp]
	m.mu.RUnlock()
	if cached {
		t.Fatalf("en0's fingerprint cached as %+v", got)
	}
	f.setRoute("en0|10.0.0.1") // back before any poll: the retry answers for en0
	waitFor2(t, 6*time.Second, func() bool { return m.Current().Key == "asn:9121" })
	m.mu.RLock()
	got = m.cache[fp]
	m.mu.RUnlock()
	if got.Key != "asn:9121" {
		t.Fatalf("en0's fingerprint cached as %+v", got)
	}
}

// poll reads the cache while resolve goroutines of earlier sightings write
// it. Flapping between two networks while lookups are slow makes a stale
// resolve land right as poll reads; the race detector (and, on a real
// collision, the runtime's concurrent map check) catches an unlocked read.
func TestCacheIsSafeUnderFlapping(t *testing.T) {
	f := &fakeNet{asn: map[string]int{"en0|10.0.0.1": 9121, "en0|10.0.0.2": 15897}}
	m := f.monitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 400; i++ {
		block := make(chan struct{})
		f.mu.Lock()
		f.block = block
		f.mu.Unlock()
		m.mu.Lock()
		m.cache = map[string]Info{} // forget, so every sighting resolves again
		m.mu.Unlock()
		f.setRoute("en0|10.0.0.1")
		m.poll(ctx) // resolve A pending
		f.setRoute("en0|10.0.0.2")
		m.poll(ctx) // resolve B pending
		f.setRoute("en0|10.0.0.1")
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); close(block) }() // the stale resolve A wakes...
		m.poll(ctx)                                   // ...while poll looks A up in the cache
		wg.Wait()
	}
}
