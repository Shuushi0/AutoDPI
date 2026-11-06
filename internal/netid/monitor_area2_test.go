package netid

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Area 2 review tests for the network monitor. TestArea2Bug_* fail today and
// reproduce a confirmed finding.

// resolve() publishes its result by replacing the whole Info, including Online,
// from the snapshot taken when the network was first seen. If the default
// route vanished meanwhile (poll already set Online=false), a lookup that
// completes afterwards flips the network back to online until the next poll.
func TestArea2Bug_ResolveResurrectsOnlineFlag(t *testing.T) {
	f := &fakeNet{route: "en0|192.168.1.1"}
	m := f.monitor()
	release := make(chan struct{})
	m.lookup = func(ctx context.Context) (int, string, error) { // answers for the network it was started on
		select {
		case <-release:
			return 15897, "TEST", nil
		case <-ctx.Done():
			return 0, "", ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.poll(ctx) // provisional, lookup blocked
	f.setRoute("")
	m.poll(ctx)
	if m.Current().Online {
		t.Fatal("setup: still online")
	}
	close(release) // the lookup finishes now
	// With no route there is no telling which network answered: the answer is
	// dropped, and the network stays offline and provisional.
	time.Sleep(200 * time.Millisecond)
	if c := m.Current(); c.Online || !c.Provisional {
		t.Fatalf("after the AS lookup landed without a default route: %+v", c)
	}
	// Back on the same attachment, the next try identifies it.
	f.setRoute("en0|192.168.1.1")
	m.poll(ctx)
	waitFor2(t, 6*time.Second, func() bool { return m.Current().Key == "asn:15897" })
	if !m.Current().Online {
		t.Fatal("identified network reported offline with a default route")
	}
}

// A gateway whose MAC is not in the ARP cache on first sight and appears later
// changes the fingerprint (iface|gw|mac) although nothing changed: the
// monitor announces a new network, with a provisional key, in the middle of a
// perfectly stable attachment.
func TestArea2Bug_LateARPEntryLooksLikeNetworkChange(t *testing.T) {
	f := &fakeNet{route: "en0|192.168.1.1", asn: map[string]int{"en0|192.168.1.1": 15897}}
	m := f.monitor()
	var mu sync.Mutex
	mac := ""
	m.mac = func(string) string { mu.Lock(); defer mu.Unlock(); return mac }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.poll(ctx)
	waitFor(t, func() bool { return m.Current().Key == "asn:15897" })
	f.mu.Lock()
	before := len(f.changes)
	f.mu.Unlock()
	mu.Lock()
	mac = "aa:bb:cc:dd:ee:ff" // ARP entry shows up (or expires and comes back)
	mu.Unlock()
	m.poll(ctx)
	f.mu.Lock()
	n := len(f.changes) - before
	var last Info
	if n > 0 {
		last = f.changes[len(f.changes)-1].cur
	}
	f.mu.Unlock()
	if n > 0 && last.Provisional {
		t.Fatalf("same iface and gateway, only the ARP entry appeared: announced %d network change(s), now %q provisional", n, last.Key)
	}
}

// Offline between two different networks, then online on the other: exactly the
// events a consumer needs, with the right old/cur pairs.
func TestArea2_OfflineThenOtherNetwork(t *testing.T) {
	f := &fakeNet{route: "en0|10.0.0.1", asn: map[string]int{"en0|10.0.0.1": 9121, "en5|172.20.10.1": 15897}}
	m := f.monitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.poll(ctx)
	waitFor(t, func() bool { return m.Current().Key == "asn:9121" })
	f.setRoute("")
	m.poll(ctx)
	f.setRoute("en5|172.20.10.1")
	m.poll(ctx)
	cur := m.Current()
	if !cur.Online || !cur.Provisional || cur.Iface != "en5" || cur.Gateway != "172.20.10.1" {
		t.Fatalf("after switching while offline: %+v", cur)
	}
	waitFor(t, func() bool { return m.Current().Key == "asn:15897" })
	f.mu.Lock()
	defer f.mu.Unlock()
	last := f.changes[len(f.changes)-1]
	if last.old.Key != cur.GatewayKey || last.cur.Key != "asn:15897" || last.cur.GatewayKey != cur.GatewayKey {
		t.Fatalf("identification event: old %+v cur %+v", last.old, last.cur)
	}
}

// Two networks of the same ISP (same AS): switching between them goes through
// the other's provisional key, so consumers see the list swap to an empty
// provisional list and back although the ISP did not change. (Documented
// behaviour of the current design; the test pins it.)
func TestArea2_SameASDifferentGatewayPassesThroughProvisional(t *testing.T) {
	f := &fakeNet{route: "en0|10.0.0.1", asn: map[string]int{"en0|10.0.0.1": 9121, "en0|10.0.1.1": 9121}}
	m := f.monitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.poll(ctx)
	waitFor(t, func() bool { return m.Current().Key == "asn:9121" })
	f.mu.Lock()
	before := len(f.changes)
	f.mu.Unlock()
	f.setRoute("en0|10.0.1.1")
	m.poll(ctx)
	waitFor(t, func() bool { return m.Current().Key == "asn:9121" && !m.Current().Provisional })
	f.mu.Lock()
	defer f.mu.Unlock()
	evs := f.changes[before:]
	for _, e := range evs {
		t.Logf("  %s -> %s", e.old.Key, e.cur.Key)
	}
	if len(evs) != 2 || !evs[0].cur.Provisional || evs[1].cur.Key != "asn:9121" || evs[1].cur.GatewayKey != evs[0].cur.Key {
		t.Fatalf("unexpected events %+v", evs)
	}
}

// Failing lookups leave the network provisional and a later success still
// identifies it (retry loop).
func TestArea2_LookupFailureThenSuccess(t *testing.T) {
	f := &fakeNet{route: "en0|192.168.1.1", asn: map[string]int{}}
	m := f.monitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.poll(ctx)
	time.Sleep(100 * time.Millisecond)
	if c := m.Current(); !c.Provisional || !c.Online {
		t.Fatalf("%+v", c)
	}
	f.mu.Lock()
	f.asn["en0|192.168.1.1"] = 1
	f.mu.Unlock()
	waitFor2(t, 6*time.Second, func() bool { return m.Current().Key == "asn:1" }) // next try is after 2s
}

func waitFor2(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Heavy flapping with slow lookups. Invariants: Current() ends up naming the
// last route polled, every announced change moves between keys, and the race
// detector stays quiet.
func TestArea2_FlappingInvariants(t *testing.T) {
	asn := map[string]int{}
	var routes []string
	for i := 0; i < 5; i++ {
		r := fmt.Sprintf("en0|10.0.%d.1", i)
		routes = append(routes, r)
		asn[r] = 100 + i
	}
	f := &fakeNet{asn: asn}
	m := f.monitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for round := 0; round < 150; round++ {
		f.setRoute(routes[round%5])
		m.poll(ctx)
		if round%7 == 0 {
			f.setRoute("")
			m.poll(ctx)
		}
		if round%11 == 0 {
			wg.Add(1)
			go func() { defer wg.Done(); _ = m.Current() }()
		}
	}
	last := routes[149%5]
	f.setRoute(last)
	m.poll(ctx)
	// The answer for the last route lands at once (or came from the cache). A
	// lookup that answered for a route polled later must never have reached
	// the cache: it would name another network here for good. The bound is
	// generous only for slow -race runs.
	waitFor2(t, 20*time.Second, func() bool {
		c := m.Current()
		return c.Online && !c.Provisional && c.Key == fmt.Sprintf("asn:%d", asn[last])
	})
	wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, e := range f.changes {
		if e.old.Key == e.cur.Key {
			t.Fatalf("change %d announced without a key change: %+v", i, e)
		}
	}
}

// Context cancel stops pending lookups; nothing is identified afterwards.
func TestArea2_CancelStopsResolve(t *testing.T) {
	f := &fakeNet{route: "en0|10.9.9.1", asn: map[string]int{"en0|10.9.9.1": 5}, block: make(chan struct{})}
	m := f.monitor()
	ctx, cancel := context.WithCancel(context.Background())
	m.poll(ctx)
	cancel()
	time.Sleep(50 * time.Millisecond)
	close(f.block)
	time.Sleep(100 * time.Millisecond)
	if m.Current().Key == "asn:5" {
		t.Fatal("identified after the context ended")
	}
}

func TestArea2_RunStopsOnCancel(t *testing.T) {
	f := &fakeNet{route: "en0|10.9.9.1", asn: map[string]int{"en0|10.9.9.1": 5}}
	m := f.monitor()
	m.Interval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	waitFor(t, func() bool { return m.Current().Key == "asn:5" })
	f.setRoute("") // exercise the offline log path
	waitFor(t, func() bool { return !m.Current().Online })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// Ready tells the first look from "offline": closed only once Run polled.
func TestReadyAfterTheFirstPoll(t *testing.T) {
	f := &fakeNet{route: "en0|10.9.9.1", asn: map[string]int{}}
	m := f.monitor()
	select {
	case <-m.Ready():
		t.Fatal("ready before Run")
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	select {
	case <-m.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("not ready after Run's first poll")
	}
	if c := m.Current(); !c.Online || c.Iface != "en0" {
		t.Fatalf("ready, but the first poll's result is not in: %+v", c)
	}
}

// With Idle set the timer is only a safety net; Poke makes the monitor look at
// the routing table at once.
func TestPokeWakesAnIdleMonitor(t *testing.T) {
	f := &fakeNet{route: "en0|10.9.9.1", asn: map[string]int{"en0|10.9.9.1": 5}}
	m := f.monitor()
	m.Interval = 5 * time.Millisecond
	m.Idle = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitFor(t, func() bool { return m.Current().Key == "asn:5" })
	f.setRoute("")
	time.Sleep(100 * time.Millisecond)
	if !m.Current().Online {
		t.Fatal("the idle timer must not poll every Interval")
	}
	m.Poke()
	waitFor(t, func() bool { return !m.Current().Online })
}
