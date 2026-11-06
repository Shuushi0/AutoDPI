package verdict

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fakenet"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/probe"
)

// a3env: a TLS origin valid for "example.com" (so the neutral SNI
// www.example.com yields CertMismatch, i.e. a live control) plus scripted dials.
type a3env struct {
	roots  *x509.CertPool
	origin string
	engine *fakenet.SplitEngine
	mu     sync.Mutex
	dialed []string
	script []string // behaviour of successive Direct dials
}

func a3newEnv(t *testing.T) *a3env {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	eng, err := fakenet.NewSplitEngine()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	e := &a3env{roots: roots, origin: srv.Listener.Addr().String(), engine: eng}
	eng.Rewrite = map[string]string{}
	return e
}

// injected: a server that answers any ClientHello with plain HTTP.
func a3injector(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
				time.Sleep(50 * time.Millisecond)
			}()
		}
	}()
	return ln.Addr().String()
}

// dial runs one scripted behaviour per call: ok, certmismatch is "ok" against
// the origin (the cert is for example.com, so any other SNI mismatches).
func (e *a3env) dialer(t *testing.T) probe.Dial {
	inj := a3injector(t)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		e.mu.Lock()
		i := len(e.dialed)
		e.dialed = append(e.dialed, addr)
		b := "ok"
		if i < len(e.script) {
			b = e.script[i]
		}
		e.mu.Unlock()
		switch b {
		case "reset":
			return nil, &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
		case "refused":
			return nil, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
		case "timeout":
			return nil, context.DeadlineExceeded
		case "other":
			return nil, errors.New("weird")
		case "inject":
			return (&net.Dialer{}).DialContext(ctx, network, inj)
		}
		return (&net.Dialer{}).DialContext(ctx, network, e.origin)
	}
}

// engineOK returns a working engine (rewrites any target to the origin).
func (e *a3env) engineOK(name string, addr netip.Addr) observer.Engine {
	e.engine.Rewrite[net.JoinHostPort(addr.String(), "443")] = e.origin
	return observer.Engine{Name: name, Addr: e.engine.Addr()}
}

func a3deadEngine(t *testing.T, name string) observer.Engine {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	return observer.Engine{Name: name, Addr: addr}
}

func (e *a3env) validator(t *testing.T, engines ...observer.Engine) *Validator {
	return &Validator{
		Direct:  &probe.Prober{Dial: e.dialer(t), Roots: e.roots, Timeout: 800 * time.Millisecond},
		Engines: func() []observer.Engine { return engines },
	}
}

var a3ip = netip.MustParseAddr("203.0.113.7")

func TestA3VerdictRuleMatrix(t *testing.T) {
	type tc struct {
		name   string
		script []string // direct#1, direct#2, control
		engine string   // ok | dead | none
		want   Kind
	}
	cases := []tc{
		{"reset,reset engine ok", []string{"reset", "reset", "ok"}, "ok", Blocked},
		{"reset,reset engine ok control dead", []string{"reset", "reset", "timeout"}, "ok", Blocked},
		{"reset,timeout engine ok", []string{"reset", "timeout", "ok"}, "ok", Blocked},
		{"timeout,reset engine ok", []string{"timeout", "reset", "ok"}, "ok", Blocked},
		{"inject,timeout engine ok", []string{"inject", "timeout", "ok"}, "ok", Blocked},
		{"timeout,timeout engine ok control alive", []string{"timeout", "timeout", "ok"}, "ok", Suspect},
		{"timeout,timeout engine ok control dead", []string{"timeout", "timeout", "timeout"}, "ok", Unknown},
		{"refused,refused engine ok control alive", []string{"refused", "refused", "ok"}, "ok", Suspect},
		{"refused,refused engine ok control dead", []string{"refused", "refused", "refused"}, "ok", Unknown},
		{"other,other engine ok control alive", []string{"other", "other", "ok"}, "ok", Suspect},
		{"reset,reset no engine control alive", []string{"reset", "reset", "ok"}, "dead", Unfixed},
		{"reset,reset no engine control dead", []string{"reset", "reset", "reset"}, "dead", Unreachable},
		{"reset,reset zero engines control alive", []string{"reset", "reset", "ok"}, "none", Unfixed},
		{"timeout,timeout zero engines control dead", []string{"timeout", "timeout", "timeout"}, "none", Unreachable},
		{"first ok", []string{"ok"}, "ok", Clean},
		{"reset then ok on 2nd try", []string{"reset", "ok"}, "ok", Clean},
		{"timeout then ok on 2nd try", []string{"timeout", "ok"}, "dead", Clean},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := a3newEnv(t)
			env.script = c.script
			var engines []observer.Engine
			switch c.engine {
			case "ok":
				engines = []observer.Engine{env.engineOK("e1", a3ip)}
			case "dead":
				engines = []observer.Engine{a3deadEngine(t, "e1")}
			}
			v := env.validator(t, engines...)
			// A host whose cert matches (example.com); the control SNI mismatches => alive.
			got := v.Check(context.Background(), "example.com", []netip.Addr{a3ip}, false)
			if got.Kind != c.want {
				t.Fatalf("got %v (direct %v control %v engines %v), want %v", got.Kind, got.Direct, got.Control, got.Engines, c.want)
			}
			if (got.Kind == Blocked || got.Kind == Suspect) != (got.Engine != "") {
				t.Fatalf("Engine %q inconsistent with kind %v", got.Engine, got.Kind)
			}
			if got.Kind == Clean && len(got.Direct) > 2 {
				t.Fatalf("too many direct tries: %v", got.Direct)
			}
		})
	}
}

// A real DPI-style cert substitution (valid TLS, wrong certificate) on the real
// path is not "hard" evidence, so it is only Suspect; check it is not lost as
// a false negative later: the same fault twice still lists via the re-check.
func TestA3CertMismatchOnRealPathIsSuspectNotClean(t *testing.T) {
	env := a3newEnv(t)
	// host "other.example.org" does not match the origin's certificate on any path
	v := env.validator(t, env.engineOK("e1", a3ip))
	got := v.Check(context.Background(), "other.example.org", []netip.Addr{a3ip}, false)
	// Direct = CertMismatch twice, engine = CertMismatch (not OK) => Unfixed, never Blocked/Clean.
	if got.Kind != Unfixed {
		t.Fatalf("got %v", got)
	}
}

func TestA3NoAddressesIsUnknownAndResolveErrorsAreTolerated(t *testing.T) {
	env := a3newEnv(t)
	v := env.validator(t)
	if got := v.Check(context.Background(), "example.com", nil, false); got.Kind != Unknown || len(got.Direct) != 0 {
		t.Fatalf("%+v", got)
	}
	v.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nxdomain") }
	if got := v.Check(context.Background(), "example.com", nil, false); got.Kind != Unknown {
		t.Fatalf("%+v", got)
	}
	// Invalid / zero addresses are ignored.
	if got := v.Check(context.Background(), "example.com", []netip.Addr{{}}, false); got.Kind != Unknown {
		t.Fatalf("%+v", got)
	}
	// Resolver alone is enough.
	v.Resolve = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{a3ip}, nil }
	if got := v.Check(context.Background(), "example.com", nil, false); got.Kind != Clean {
		t.Fatalf("%+v", got)
	}
}

func TestA3DedupeCapAndAddressOrder(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("::ffff:1.2.3.4"), netip.MustParseAddr("1.2.3.4"), {},
		netip.MustParseAddr("1.2.3.5"), netip.MustParseAddr("1.2.3.6"), netip.MustParseAddr("1.2.3.7"),
		netip.MustParseAddr("1.2.3.8"), netip.MustParseAddr("1.2.3.4"),
	}
	got := dedupe(in)
	if len(got) != 4 || got[0] != netip.MustParseAddr("1.2.3.4") || got[3] != netip.MustParseAddr("1.2.3.7") {
		t.Fatalf("%v", got)
	}
	// The address the observer saw is tried first, then resolver answers.
	env := a3newEnv(t)
	env.script = []string{"reset", "reset", "ok"}
	v := env.validator(t)
	v.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.1"), a3ip}, nil
	}
	v.Check(context.Background(), "example.com", []netip.Addr{a3ip}, false)
	want := []string{"203.0.113.7:443", "198.51.100.1:443", "203.0.113.7:443"} // direct0, direct1, control
	for i, w := range want {
		if i >= len(env.dialed) || env.dialed[i] != w {
			t.Fatalf("dial order %v, want prefix %v", env.dialed, want)
		}
	}
}

func TestA3AllModeVersusFirstMode(t *testing.T) {
	env := a3newEnv(t)
	env.script = []string{"reset", "reset", "ok"}
	e1, e2, e3 := a3deadEngine(t, "bad"), env.engineOK("good1", a3ip), env.engineOK("good2", a3ip)
	v := env.validator(t, e1, e2, e3)
	got := v.Check(context.Background(), "example.com", []netip.Addr{a3ip}, false)
	if got.Kind != Blocked || got.Engine != "good1" || len(got.Engines) != 2 {
		t.Fatalf("first mode: %+v", got)
	}
	env.mu.Lock()
	env.dialed = nil
	env.mu.Unlock()
	env.script = []string{"reset", "reset", "ok"}
	got = v.Check(context.Background(), "example.com", []netip.Addr{a3ip}, true)
	if got.Kind != Blocked || got.Engine != "good1" || len(got.Engines) != 3 || got.Engines["good2"] != "ok" || got.Engines["bad"] == "ok" {
		t.Fatalf("all mode: %+v", got)
	}
}

func TestA3NetworkChangeAtEveryStage(t *testing.T) {
	// changes after the direct tries but before engines; and at the very end
	for _, flipAt := range []int{1, 2} { // Same is consulted twice on the failing path
		env := a3newEnv(t)
		env.script = []string{"reset", "reset", "ok"}
		v := env.validator(t, env.engineOK("e", a3ip))
		calls := 0
		v.Same = func() bool { calls++; return calls < flipAt }
		got := v.Check(context.Background(), "example.com", []netip.Addr{a3ip}, false)
		if got.Kind != Unknown || got.Engine != "" {
			t.Errorf("flipAt=%d: %+v", flipAt, got)
		}
	}
	// stable network: Same is only consulted, never decisive
	env := a3newEnv(t)
	env.script = []string{"reset", "reset", "ok"}
	v := env.validator(t, env.engineOK("e", a3ip))
	v.Same = func() bool { return true }
	if got := v.Check(context.Background(), "example.com", []netip.Addr{a3ip}, false); got.Kind != Blocked {
		t.Fatalf("%+v", got)
	}
}

func TestA3CanceledContextNeverLists(t *testing.T) {
	env := a3newEnv(t)
	v := env.validator(t, env.engineOK("e", a3ip))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := v.Check(ctx, "example.com", []netip.Addr{a3ip}, false)
	if got.Kind == Blocked || got.Kind == Suspect || got.Kind == Clean {
		t.Fatalf("a cancelled check produced %v", got.Kind)
	}
}

// Characterisation of a residual false-positive risk (LOW): two consecutive
// connection resets/EOFs from a flaky or rate-limiting server, with the third
// attempt (through an engine) succeeding, is indistinguishable from a DPI and
// is verdict Blocked. io.EOF is classified as Reset too.
func TestA3FlakyServerResetsLookLikeABlock(t *testing.T) {
	env := a3newEnv(t)
	env.script = []string{"reset", "reset", "ok"}
	v := env.validator(t, env.engineOK("e", a3ip))
	if got := v.Check(context.Background(), "example.com", []netip.Addr{a3ip}, false); got.Kind != Blocked {
		t.Fatalf("%v", got)
	}
}

func TestA3KindStringsAndVerdictString(t *testing.T) {
	want := map[Kind]string{Clean: "clean", Blocked: "blocked", Unfixed: "unfixed", Unreachable: "unreachable", Unknown: "unknown", Suspect: "suspect"}
	for k, s := range want {
		if k.String() != s {
			t.Errorf("%d -> %q want %q", k, k.String(), s)
		}
	}
	if got := (Verdict{Kind: Blocked, Engine: "tlsrec"}).String(); got != "blocked via tlsrec" {
		t.Error(got)
	}
	// The zero Verdict is Clean: callers must never act on a zero value.
	if (Verdict{}).Kind != Clean {
		t.Error("zero Verdict is no longer Clean")
	}
}

// With two addresses, the first silent and the second reset, the control and
// the engines go to the second: the block lives there.
func TestA3ProbesFollowTheBlockedAddress(t *testing.T) {
	env := a3newEnv(t)
	env.script = []string{"timeout", "reset", "ok"}
	second := netip.MustParseAddr("198.51.100.1")
	v := env.validator(t, env.engineOK("split", second))
	v.Resolve = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{second}, nil }
	got := v.Check(context.Background(), "example.com", []netip.Addr{a3ip}, false)
	if got.Kind != Blocked || got.Engine != "split" {
		t.Fatalf("verdict %v", got)
	}
	want := []string{"203.0.113.7:443", "198.51.100.1:443", "198.51.100.1:443"} // direct0, direct1, control
	for i, w := range want {
		if i >= len(env.dialed) || env.dialed[i] != w {
			t.Fatalf("dial order %v, want prefix %v", env.dialed, want)
		}
	}
}

// When both direct tries and the control on the first address are silent, the
// other address gets a control of its own before the target is given up.
func TestA3SilentFirstAddressTriesTheOtherControl(t *testing.T) {
	env := a3newEnv(t)
	env.script = []string{"timeout", "timeout", "timeout", "ok"}
	second := netip.MustParseAddr("198.51.100.1")
	v := env.validator(t, env.engineOK("split", second))
	v.Resolve = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{second}, nil }
	got := v.Check(context.Background(), "example.com", []netip.Addr{a3ip}, false)
	if got.Kind != Suspect || got.Engine != "split" {
		t.Fatalf("verdict %v (dials %v)", got, env.dialed)
	}
	if len(env.dialed) < 4 || env.dialed[3] != "198.51.100.1:443" {
		t.Fatalf("dials %v", env.dialed)
	}
}
