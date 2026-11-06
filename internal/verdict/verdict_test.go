package verdict

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fakenet"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/probe"
)

type world struct {
	roots  *x509.CertPool
	censor *fakenet.Censor
	engine *fakenet.SplitEngine
	ip     netip.Addr
}

// The Validator probes port 443, so the tests point it at a Dial that always
// lands on the censor, whatever address it is given.
func newWorld(t *testing.T, mode fakenet.Mode) *world {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	t.Cleanup(origin.Close)
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	censor, err := fakenet.NewCensor(origin.Listener.Addr().String(), mode, func(n string) bool { return n == "example.com" })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(censor.Close)
	eng, err := fakenet.NewSplitEngine()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	eng.Rewrite = map[string]string{"203.0.113.7:443": censor.Addr()}
	return &world{roots: roots, censor: censor, engine: eng, ip: netip.MustParseAddr("203.0.113.7")}
}

func (w *world) validator(engines ...observer.Engine) *Validator {
	toCensor := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, w.censor.Addr())
	}
	return &Validator{
		Direct:  &probe.Prober{Dial: toCensor, Roots: w.roots, Timeout: time.Second},
		Engines: func() []observer.Engine { return engines },
	}
}

func TestBlockedIsRepairedByEngine(t *testing.T) {
	w := newWorld(t, fakenet.Reset)
	v := w.validator(observer.Engine{Name: "split", Addr: w.engine.Addr()})
	got := v.Check(context.Background(), "example.com", []netip.Addr{w.ip}, false)
	if got.Kind != Blocked || got.Engine != "split" {
		t.Fatalf("got %+v", got)
	}
	if len(got.Direct) != 2 {
		t.Fatalf("expected two real-path tries, got %d", len(got.Direct))
	}
}

func TestCleanTarget(t *testing.T) {
	w := newWorld(t, fakenet.Reset)
	v := w.validator()
	// Neutral name is not on the censor's list, so the origin answers (its cert
	// is for example.com, so use that and a censor that allows it).
	w.censor.Blocked = func(string) bool { return false }
	got := v.Check(context.Background(), "example.com", []netip.Addr{w.ip}, false)
	if got.Kind != Clean {
		t.Fatalf("got %+v", got)
	}
}

func TestUnfixedWhenNoEngineHelps(t *testing.T) {
	w := newWorld(t, fakenet.Reset)
	v := w.validator() // no engines
	got := v.Check(context.Background(), "example.com", []netip.Addr{w.ip}, false)
	// The control probe (neutral SNI) reaches the origin and gets a cert
	// mismatch: that still counts as the address being reachable.
	if got.Kind != Unfixed {
		t.Fatalf("got %+v", got)
	}
}

func TestUnreachableWhenEverythingFails(t *testing.T) {
	w := newWorld(t, fakenet.Reset)
	w.censor.Blocked = func(string) bool { return true }
	v := w.validator()
	got := v.Check(context.Background(), "example.com", []netip.Addr{w.ip}, false)
	if got.Kind != Unreachable {
		t.Fatalf("got %+v", got)
	}
}

func TestAllModeReportsEveryEngine(t *testing.T) {
	w := newWorld(t, fakenet.Reset)
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	v := w.validator(
		observer.Engine{Name: "broken", Addr: deadAddr},
		observer.Engine{Name: "split", Addr: w.engine.Addr()},
	)
	got := v.Check(context.Background(), "example.com", []netip.Addr{w.ip}, true)
	if got.Kind != Blocked || got.Engine != "split" || len(got.Engines) != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestNetworkChangeDiscardsVerdict(t *testing.T) {
	w := newWorld(t, fakenet.Reset)
	v := w.validator(observer.Engine{Name: "split", Addr: w.engine.Addr()})
	v.Same = func() bool { return false }
	if got := v.Check(context.Background(), "example.com", []netip.Addr{w.ip}, false); got.Kind != Unknown {
		t.Fatalf("got %+v", got)
	}
}

// A re-test that started on one network and finished on another must not
// report the new network's clean path as the old network's: the daemon would
// drop a still-blocked entry from the old network's list.
func TestNetworkChangeDiscardsCleanVerdict(t *testing.T) {
	w := newWorld(t, fakenet.Reset)
	w.censor.Blocked = func(string) bool { return false } // the new network does not block
	v := w.validator()
	v.Same = func() bool { return false }
	if got := v.Check(context.Background(), "example.com", []netip.Addr{w.ip}, false); got.Kind != Unknown {
		t.Fatalf("got %v after a network change, want unknown", got.Kind)
	}
}

// A stalling link makes the real path time out too; that alone is not what a
// DPI does, so the target is only Suspect (the caller re-checks later).
func TestTimeoutOnlyIsSuspect(t *testing.T) {
	w := newWorld(t, fakenet.Drop)
	v := w.validator(observer.Engine{Name: "split", Addr: w.engine.Addr()})
	got := v.Check(context.Background(), "example.com", []netip.Addr{w.ip}, false)
	if got.Kind != Suspect || got.Engine != "split" {
		t.Fatalf("got %+v", got)
	}
	for _, r := range got.Direct {
		if r.Outcome != probe.Timeout {
			t.Fatalf("direct outcomes %v, want timeouts", got.Direct)
		}
	}
}

// Silence on the real path and on the neutral control means the link is down
// or stalling, not that the name is blocked, even if an engine got through.
func TestTimeoutOnlyWithDeadControlIsUnknown(t *testing.T) {
	w := newWorld(t, fakenet.Drop)
	w.censor.Blocked = func(string) bool { return true }
	v := w.validator(observer.Engine{Name: "split", Addr: w.engine.Addr()})
	got := v.Check(context.Background(), "example.com", []netip.Addr{w.ip}, false)
	if got.Kind != Unknown || got.Engine != "" {
		t.Fatalf("got %+v", got)
	}
}

func TestIsBlockEvidence(t *testing.T) {
	for o, want := range map[probe.Outcome]bool{
		probe.Reset: true, probe.Injected: true,
		probe.Timeout: false, probe.Refused: false, probe.Other: false,
		probe.OK: false, probe.Alert: false, probe.CertMismatch: false,
	} {
		if got := IsBlockEvidence(probe.Result{Outcome: o}); got != want {
			t.Errorf("%v: got %v, want %v", o, got, want)
		}
	}
}
