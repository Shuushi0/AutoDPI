//go:build !windows

package daemon

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/hoststate"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/paths"
)

func openRig(t *testing.T) (*Daemon, *fakeSys) {
	t.Helper()
	d, f := rig(t, Options{})
	d.obs = observer.New(observer.Options{})
	return d, f
}

func openHost(d *Daemon, host string) {
	for i := 0; i < hoststate.Promote; i++ {
		d.onEvent(ev(host, observer.Direct))
	}
}

func TestThreeDirectsInARowOpenAHost(t *testing.T) {
	d, _ := openRig(t)
	d.onEvent(ev("www.example.org", observer.Direct))
	d.onEvent(ev("www.example.org", observer.Direct))
	if d.mode("www.example.org") != observer.Full {
		t.Fatal("open after two")
	}
	d.onEvent(ev("www.example.org", observer.Direct))
	if d.mode("www.example.org") != observer.Light {
		t.Fatal("not open after three")
	}
	if d.mode("example.org") != observer.Full || d.mode("cdn.example.org") != observer.Full {
		t.Fatal("openness inferred for another name")
	}
	if got := d.status().Open; got != 1 {
		t.Fatalf("status.open = %d", got)
	}
}

func TestFailedOrRepairedConnectionClosesAHost(t *testing.T) {
	for _, o := range []observer.Outcome{observer.Fallback, observer.Failed} {
		d, _ := openRig(t)
		openHost(d, "www.example.org")
		d.onEvent(ev("www.example.org", o))
		if d.mode("www.example.org") != observer.Full {
			t.Fatalf("still open after %s", o)
		}
		// and the count starts over
		d.onEvent(ev("www.example.org", observer.Direct))
		d.onEvent(ev("www.example.org", observer.Direct))
		if d.mode("www.example.org") != observer.Full {
			t.Fatalf("count survived a %s", o)
		}
		for _, j := range d.journal {
			if strings.HasPrefix(j.Kind, "open") {
				t.Fatalf("open-state bookkeeping in the journal: %+v", j)
			}
		}
	}
}

func TestEventsWithoutUsableSNIOrNetworkAreIgnored(t *testing.T) {
	d, f := openRig(t)
	for _, h := range []string{"", "localhost", "10.1.2.3", "WWW.Example.Org", "example.org."} {
		openHost(d, h)
	}
	if d.status().Open != 0 {
		t.Fatalf("unusable names were counted: %d", d.status().Open)
	}
	f.set(func(f *fakeSys) { f.net.Online = false })
	openHost(d, "www.offline.example.org")
	f.set(func(f *fakeSys) { f.net.Online = true })
	if d.mode("www.offline.example.org") != observer.Full {
		t.Fatal("counted while offline")
	}
	// An event of a flow that began before the network switched belongs to the old one.
	old := observer.Event{Time: time.Now().Add(-time.Hour), SNI: "www.early.example.org", Dest: "203.0.113.5:443", Outcome: observer.Direct}
	for i := 0; i < 3; i++ {
		d.onEvent(old)
	}
	if d.mode("www.early.example.org") != observer.Full {
		t.Fatal("event from before the switch was counted")
	}
}

// Open names are kept per network: switching networks switches tables, and the
// provisional network's table is dropped when it is folded into the stable one.
func TestOpenNamesArePerNetwork(t *testing.T) {
	d, f := openRig(t)
	openHost(d, "www.a.example.org")
	if d.mode("www.a.example.org") != observer.Light {
		t.Fatal("not open on the first network")
	}
	f.set(func(f *fakeSys) { f.net = netid.Info{Key: "asn:2", Label: "AS2", Online: true} })
	d.onNetChange(netid.Info{Key: "asn:15897"}, netid.Info{Key: "asn:2", Label: "AS2", Online: true})
	if d.mode("www.a.example.org") != observer.Full || d.status().Open != 0 {
		t.Fatal("open name leaked to the other network")
	}
	openHost(d, "www.b.example.org")
	f.set(func(f *fakeSys) { f.net = netid.Info{Key: "asn:15897", Label: "AS15897", Online: true} })
	d.onNetChange(netid.Info{Key: "asn:2"}, netid.Info{Key: "asn:15897", Label: "AS15897", Online: true})
	if d.mode("www.a.example.org") != observer.Light {
		t.Fatal("first network's open name forgotten on return")
	}
	if d.mode("www.b.example.org") != observer.Full {
		t.Fatal("second network's open name leaked")
	}

	// provisional -> stable of the same attachment
	f.set(func(f *fakeSys) { f.net = netid.Info{Key: "gw:x", Provisional: true, GatewayKey: "gw:x", Online: true} })
	d.onNetChange(netid.Info{Key: "asn:15897"}, netid.Info{Key: "gw:x", Provisional: true, GatewayKey: "gw:x", Online: true})
	openHost(d, "www.p.example.org")
	f.set(func(f *fakeSys) { f.net = netid.Info{Key: "asn:3", GatewayKey: "gw:x", Online: true} })
	d.onNetChange(netid.Info{Key: "gw:x", Provisional: true, GatewayKey: "gw:x"}, netid.Info{Key: "asn:3", GatewayKey: "gw:x", Online: true})
	d.mu.Lock()
	_, kept := d.caches["gw:x"]
	d.mu.Unlock()
	if kept || d.mode("www.p.example.org") != observer.Full {
		t.Fatal("the provisional network's table survived being folded")
	}
}

func TestOpenResetAndStatusCount(t *testing.T) {
	d, _ := openRig(t)
	openHost(d, "www.a.example.org")
	openHost(d, "www.b.example.org")
	d.onEvent(ev("www.c.example.org", observer.Direct)) // still counting: not open
	if got := d.status().Open; got != 2 {
		t.Fatalf("status.open = %d, want 2", got)
	}
	r, err := call(t, d, ipc.Request{Cmd: "open-reset"})
	if err != nil || r["removed"] != float64(2) {
		t.Fatalf("open-reset: %v %v", r, err)
	}
	if d.status().Open != 0 || d.mode("www.a.example.org") != observer.Full {
		t.Fatal("not empty after reset")
	}
	if _, err := call(t, d, ipc.Request{Cmd: "clean-list"}); err == nil {
		t.Fatal("the clean-list command still exists")
	}
	d.openCur.Store(nil)
	if _, err := call(t, d, ipc.Request{Cmd: "open-reset"}); err != errNoNetwork {
		t.Fatalf("reset without a network: %v", err)
	}
}

// Nothing about the open state reaches the disk.
func TestOpenStateIsNotPersisted(t *testing.T) {
	d, _ := openRig(t)
	_, _ = d.st.Touch("asn:15897", "AS15897")
	openHost(d, "www.secret.example.org")
	b, err := readFile(d.p.State)
	if err == nil && contains(string(b), "secret") {
		t.Fatalf("state.json mentions an open name: %s", b)
	}
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// The observer asks this for every flow; for an open name it must be a lookup
// and nothing else (no network lock, no normalisation, no allocation).
func BenchmarkMode(b *testing.B) {
	d, _ := benchRig(b)
	openHost(d, "www.example.org")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d.mode("www.example.org") != observer.Light {
			b.Fatal("not light")
		}
	}
}

func TestModeAllocatesNothing(t *testing.T) {
	d, _ := openRig(t)
	openHost(d, "www.example.org")
	if n := testing.AllocsPerRun(100, func() { _ = d.mode("www.example.org") }); n != 0 {
		t.Fatalf("mode allocates %v times per flow", n)
	}
	if n := testing.AllocsPerRun(100, func() { _ = d.mode("unknown.example.org") }); n != 0 {
		t.Fatalf("mode of an unknown name allocates %v times per flow", n)
	}
}

func benchRig(b *testing.B) (*Daemon, *fakeSys) {
	b.Helper()
	d := New(config.Default(), paths.Set{}, "", quietLog())
	d.sys.network = func() netid.Info { return netid.Info{Key: "asn:1", Online: true} }
	d.obs = observer.New(observer.Options{})
	d.useNetwork("asn:1")
	return d, nil
}

// Connections that work directly leave no trace: no journal line, whether the
// name is counting, becomes open or stays open. Only the counter changes.
func TestDirectConnectionsAreNotJournalled(t *testing.T) {
	d, _ := openRig(t)
	for i := 0; i < 10; i++ {
		d.onEvent(ev("www.quiet.example.org", observer.Direct))
	}
	_, _ = d.openReset()
	if len(d.journal) != 0 {
		t.Fatalf("journal after direct connections and an open-state reset: %+v", d.journal)
	}
	// A connection no path could open is not journalled either; the repaired one is.
	failed := ev("www.quiet.example.org", observer.Failed)
	failed.Results = map[string]string{"direct": "read: connection reset by peer (5ms)"}
	d.onEvent(failed)
	if len(d.journal) != 0 {
		t.Fatalf("journal = %+v, want nothing for a failed connection", d.journal)
	}
	hedged := ev("www.quiet.example.org", observer.Fallback) // the engine was only faster
	d.onEvent(hedged)
	if len(d.journal) != 0 {
		t.Fatalf("journal = %+v, want nothing for a hedge win", d.journal)
	}
	repaired := ev("www.quiet.example.org", observer.Fallback)
	repaired.Blocked = true
	d.onEvent(repaired)
	if len(d.journal) != 1 || d.journal[0].Kind != "repaired" {
		t.Fatalf("journal = %+v, want just the repaired connection", d.journal)
	}
}

// A connection no path could open is not journalled, but it still closes an
// open name: that is the only thing the observer reports it for.
func TestFailedConnectionIsNotJournalledButClosesAnOpenHost(t *testing.T) {
	d, _ := openRig(t)
	openHost(d, "www.example.org")
	f := ev("www.example.org", observer.Failed)
	f.Results = map[string]string{"direct": "read: connection reset by peer (5ms)"}
	d.onEvent(f)
	if d.mode("www.example.org") != observer.Full {
		t.Fatal("still open after a failed connection")
	}
	if len(d.journal) != 0 {
		t.Fatalf("journal = %+v", d.journal)
	}
	if len(d.cands) != 0 {
		t.Fatal("a failed connection was queued for validation")
	}
}
