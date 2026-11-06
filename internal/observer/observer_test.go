package observer

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fakenet"
	"github.com/Shuushi0/AutoDPI/internal/socks"
)

type rig struct {
	t      *testing.T
	obs    *Observer
	addr   string // observer listen address
	events chan Event
	origin *httptest.Server
	engine *fakenet.SplitEngine
}

func newRig(t *testing.T, mode fakenet.Mode, mut func(*Options)) (*rig, *fakenet.Censor) {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hello") }))
	t.Cleanup(origin.Close)
	censor, err := fakenet.NewCensor(origin.Listener.Addr().String(), mode, func(n string) bool { return n == "blocked.test" })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(censor.Close)
	eng, err := fakenet.NewSplitEngine()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)

	r := &rig{t: t, events: make(chan Event, 16), origin: origin, engine: eng}
	opt := Options{
		Engines:        func() []Engine { return []Engine{{Name: "split", Addr: eng.Addr()}} },
		Dial:           (&net.Dialer{}).DialContext,
		Events:         func(e Event) { r.events <- e },
		HelloWait:      time.Second,
		ConnectTimeout: time.Second,
		FirstByte:      time.Second,
		Hedge:          150 * time.Millisecond,
		AllowLoopback:  true,
	}
	if _, ps, err := net.SplitHostPort(censor.Addr()); err == nil {
		port, _ := net.LookupPort("tcp", ps)
		opt.Ports = []int{port}
	}
	if mut != nil {
		mut(&opt)
	}
	r.obs = New(opt)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.addr = ln.Addr().String()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = r.obs.Serve(ln) }()
	t.Cleanup(func() { r.obs.Close(); wg.Wait() })
	return r, censor
}

// fetch dials host:port through the observer and does a full TLS+HTTP exchange.
func (r *rig) fetch(target, sni string) (string, error) {
	r.t.Helper()
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := net.LookupPort("tcp", portStr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := socks.Dial(ctx, nil, r.addr, host, port)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		return "", err
	}
	if _, err := io.WriteString(tc, "GET / HTTP/1.0\r\nHost: x\r\n\r\n"); err != nil {
		return "", err
	}
	body, err := io.ReadAll(tc)
	if len(body) == 0 && err != nil {
		return "", err
	}
	return string(body), nil
}

func (r *rig) event() Event {
	r.t.Helper()
	select {
	case e := <-r.events:
		return e
	case <-time.After(3 * time.Second):
		r.t.Fatal("no event")
		return Event{}
	}
}

func TestCleanTargetGoesDirect(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, nil)
	body, err := r.fetch(censor.Addr(), "fine.test")
	if err != nil || len(body) == 0 {
		t.Fatalf("fetch: %v %q", err, body)
	}
	e := r.event()
	if e.Outcome != Direct || e.SNI != "fine.test" {
		t.Fatalf("event = %+v", e)
	}
	select {
	case h := <-r.engine.Hits:
		t.Fatalf("engine should stay idle, got hit %s", h)
	default:
	}
}

func TestResetIsRepairedOnFirstConnection(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, nil)
	body, err := r.fetch(censor.Addr(), "blocked.test")
	if err != nil || len(body) == 0 {
		t.Fatalf("first connection must open: %v %q", err, body)
	}
	e := r.event()
	if e.Outcome != Fallback || e.Engine != "split" || e.SNI != "blocked.test" {
		t.Fatalf("event = %+v", e)
	}
	if e.Results["direct"] == "" {
		t.Fatalf("direct result missing: %+v", e.Results)
	}
	if !e.Blocked {
		t.Fatalf("a reset on the direct attempt is a block: %+v", e)
	}
}

func TestBlackholeIsHedged(t *testing.T) {
	r, censor := newRig(t, fakenet.Drop, func(o *Options) {
		o.FirstByte = 3 * time.Second // direct would sit here for 3s
		o.Hedge = 100 * time.Millisecond
	})
	t0 := time.Now()
	if _, err := r.fetch(censor.Addr(), "blocked.test"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > 1500*time.Millisecond {
		t.Fatalf("hedge should beat the first-byte timeout, took %v", d)
	}
	// The engine won the hedge against a direct attempt that was only slow:
	// it delivered, but nothing says the direct path was blocked.
	if e := r.event(); e.Outcome != Fallback || e.Blocked {
		t.Fatalf("event = %+v", e)
	}
}

func TestNoEngineMeansFailure(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, func(o *Options) { o.Engines = nil })
	if _, err := r.fetch(censor.Addr(), "blocked.test"); err == nil {
		t.Fatal("expected failure")
	}
	noEvent(t, r) // nothing opened it, and nothing is worth reporting
	if r.obs.DeadLen() != 0 {
		t.Fatal("no engine was configured, so nothing was learned about the server")
	}
}

func TestNonTLSPassesThrough(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	host, ps, _ := net.SplitHostPort(echo.Addr().String())
	port, _ := net.LookupPort("tcp", ps)
	r, _ := newRig(t, fakenet.Reset, func(o *Options) { o.Ports = append(o.Ports, port) })
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	c, err := socks.Dial(context.Background(), nil, r.addr, host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "PING")
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "PING" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	if got := r.obs.Stats().Passthrough; got != 1 {
		t.Fatalf("passthrough = %d", got)
	}
}

func TestPolicy(t *testing.T) {
	r, _ := newRig(t, fakenet.Reset, func(o *Options) { o.AllowLoopback = false; o.Ports = []int{443} })
	for _, c := range []struct {
		host string
		port int
		code byte
	}{
		{"127.0.0.1", 443, socks.RepNotAllowed}, // loopback is never a valid target
		{"8.8.8.8", 80, socks.RepNotAllowed},    // only observed ports
		{"169.254.1.1", 443, socks.RepNotAllowed},
	} {
		_, err := socks.Dial(context.Background(), nil, r.addr, c.host, c.port)
		re, ok := err.(*socks.ReplyError)
		if !ok || re.Code != c.code {
			t.Errorf("%s:%d => %v, want reply %d", c.host, c.port, err, c.code)
		}
	}
}

func TestDomainTargetIsResolvedFirst(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, func(o *Options) {
		o.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
	})
	_, ps, _ := net.SplitHostPort(censor.Addr())
	port, _ := net.LookupPort("tcp", ps)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := socks.Dial(ctx, nil, r.addr, "blocked.example", port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: "blocked.test", InsecureSkipVerify: true})
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if e := r.event(); e.Outcome != Fallback {
		t.Fatalf("event = %+v", e)
	}
}

func TestCloseDropsLiveFlows(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, nil)
	host, ps, _ := net.SplitHostPort(censor.Addr())
	port, _ := net.LookupPort("tcp", ps)
	c, err := socks.Dial(context.Background(), nil, r.addr, host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan struct{})
	go func() { r.obs.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung on a live flow")
	}
}

// Flows beyond the per-destination racing cap must not use engines: that is
// what stops a recaptured engine connection from multiplying forever. The cap
// counts flows that escalated and are still racing, so the engine here never
// answers and the first two flows hold their slots while the third arrives.
func TestRacingCapStopsEscalation(t *testing.T) {
	stuck, err := net.Listen("tcp", "127.0.0.1:0") // an engine that accepts and says nothing
	if err != nil {
		t.Fatal(err)
	}
	defer stuck.Close()
	var tried atomic.Int32 // flows that reached the engine
	go func() {
		for {
			c, err := stuck.Accept()
			if err != nil {
				return
			}
			tried.Add(1)
			defer c.Close()
		}
	}()
	r, censor := newRig(t, fakenet.Reset, func(o *Options) {
		o.MaxRacing = 2
		o.ConnectTimeout = 2 * time.Second // how long an escalated flow holds its slot
		o.FirstByte = 400 * time.Millisecond
		o.Hedge = 10 * time.Second
		o.Engines = func() []Engine { return []Engine{{Name: "split", Addr: stuck.Addr().String()}} }
	})
	host, ps, _ := net.SplitHostPort(censor.Addr())
	port, _ := net.LookupPort("tcp", ps)

	open := func() net.Conn {
		c, err := socks.Dial(context.Background(), nil, r.addr, host, port)
		if err != nil {
			t.Fatal(err)
		}
		tc := tls.Client(c, &tls.Config{ServerName: "blocked.test", InsecureSkipVerify: true})
		go func() { _ = tc.Handshake() }()
		return c
	}
	for i := 0; i < 3; i++ {
		defer open().Close()
		time.Sleep(50 * time.Millisecond)
	}
	// The direct attempts are reset (DPI evidence, so the flows may use the
	// engines); the first two flows take the two slots and sit in the stuck
	// engine, the third finds none. Nothing is reported for any of them.
	time.Sleep(time.Second)
	if n := tried.Load(); n != 2 {
		t.Fatalf("engine used by %d flows; want 2 (the third is over the cap)", n)
	}
	noEvent(t, r)

}

// Flows the direct attempt serves never take a racing slot: with a cap of one,
// many concurrent healthy flows to one destination all open and the cap never
// trips.
func TestDirectFlowsDoNotCountAgainstRacingCap(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, func(o *Options) { o.MaxRacing = 1 })
	go func() {
		for range r.events {
		}
	}()
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b, err := r.fetch(censor.Addr(), "fine.test"); err != nil || b == "" {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 || r.obs.capped.Load() != 0 {
		t.Fatalf("%d flows failed, cap tripped %d times", bad.Load(), r.obs.capped.Load())
	}
	r.obs.mu.Lock()
	defer r.obs.mu.Unlock()
	if len(r.obs.racing) != 0 {
		t.Fatalf("racing slots leaked: %v", r.obs.racing)
	}
}

// The daemon spawns Serve in a goroutine and calls Close on shutdown; when
// shutdown comes first (an early failure), Serve must not block in Accept
// forever, or the daemon's final wait never returns.
func TestCloseBeforeServe(t *testing.T) {
	o := New(Options{})
	o.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() { done <- o.Serve(ln) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve after Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve blocked forever after Close")
	}
}

// lightOpts puts the named hosts in Light mode.
func lightOpts(hosts ...string) func(*Options) {
	return func(o *Options) {
		o.Mode = func(h string) Mode {
			for _, c := range hosts {
				if c == h {
					return Light
				}
			}
			return Full
		}
	}
}

func noEvent(t *testing.T, r *rig) {
	t.Helper()
	select {
	case e := <-r.events:
		t.Fatalf("unexpected event %+v", e)
	case <-time.After(200 * time.Millisecond):
	}
}

// An open (Light) host is dialed directly and relayed: no event, no engine, no hedge
// even when the direct path is slower than the hedge timer.
func TestCleanHostIsRelayedLightly(t *testing.T) {
	mut := lightOpts("fine.test")
	r, censor := newRig(t, fakenet.Reset, func(o *Options) {
		mut(o)
		o.Hedge = 50 * time.Millisecond
		dial := o.Dial
		o.Dial = func(ctx context.Context, n, a string) (net.Conn, error) {
			time.Sleep(300 * time.Millisecond) // six hedge intervals
			return dial(ctx, n, a)
		}
	})
	body, err := r.fetch(censor.Addr(), "fine.test")
	if err != nil || len(body) == 0 {
		t.Fatalf("fetch: %v %q", err, body)
	}
	noEvent(t, r)
	select {
	case h := <-r.engine.Hits:
		t.Fatalf("an open host must not start engine attempts, got %s", h)
	default:
	}
	if st := r.obs.Stats(); st.Direct != 1 || st.Fallback != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// The host got blocked while it was open: the very same connection must
// still open (full path), and the host is reported so it leaves the list.
func TestCleanHostThatGetsBlockedIsRepairedAtOnce(t *testing.T) {
	for name, mode := range map[string]fakenet.Mode{"reset": fakenet.Reset, "silence": fakenet.Drop} {
		t.Run(name, func(t *testing.T) {
			mut := lightOpts("blocked.test")
			r, censor := newRig(t, mode, func(o *Options) {
				mut(o)
				o.FirstByte = 700 * time.Millisecond
				o.Hedge = time.Hour // only the explicit escalation can start the engine
			})
			t0 := time.Now()
			body, err := r.fetch(censor.Addr(), "blocked.test")
			if err != nil || len(body) == 0 {
				t.Fatalf("the connection must open through the engine: %v %q", err, body)
			}
			if d := time.Since(t0); d > 3*time.Second {
				t.Fatalf("took %v", d)
			}
			e := r.event() // the full path reports as usual: this is how the daemon learns the name is no longer open
			if e.Outcome != Fallback || e.Engine != "split" || e.SNI != "blocked.test" || e.Results["direct"] == "" {
				t.Fatalf("event = %+v", e)
			}
			select {
			case <-r.engine.Hits:
			default:
				t.Fatal("engine never carried the retry")
			}
			// The failed light attempt is the only direct one: no second try.
			if n := len(censor.Seen); n != 1 {
				t.Fatalf("censor saw %d direct ClientHellos for blocked.test, want 1", n)
			}
		})
	}
}

// Without Mode (or for other names) nothing changes.
func TestNonLightHostsKeepTheFullPath(t *testing.T) {
	mut := lightOpts("other.test")
	r, censor := newRig(t, fakenet.Reset, mut)
	if _, err := r.fetch(censor.Addr(), "fine.test"); err != nil {
		t.Fatal(err)
	}
	if e := r.event(); e.Outcome != Direct || e.SNI != "fine.test" {
		t.Fatalf("event = %+v", e)
	}
}

// silentListener accepts connections and never says a word.
func silentListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				c.Close()
			}
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	return ln
}

// A stalled link (the server answers nothing on any path, as ocsp2.apple.com
// did) is not worth the whole ladder: after silence on the direct attempt one
// engine is tried; when it is silent too the flow is given up with no event
// and no report.
func TestLinkStallTriesOneEngineAndReportsNothing(t *testing.T) {
	srv := silentListener(t)
	second, err := fakenet.NewSplitEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	r, _ := newRig(t, fakenet.Reset, func(o *Options) {
		o.FirstByte = 400 * time.Millisecond
		o.Hedge = 100 * time.Millisecond
	})
	first := r.engine
	r.obs.opt.Engines = func() []Engine {
		return []Engine{{Name: "split", Addr: first.Addr()}, {Name: "second", Addr: second.Addr()}}
	}
	_, ps, _ := net.SplitHostPort(srv.Addr().String())
	port, _ := net.LookupPort("tcp", ps)
	r.obs.opt.Ports = []int{port}
	t0 := time.Now()
	if _, err := r.fetch(srv.Addr().String(), "ocsp.example.org"); err == nil {
		t.Fatal("a silent server cannot open")
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("gave up after %v", d)
	}
	select {
	case <-first.Hits:
	case <-time.After(time.Second):
		t.Fatal("the first engine was not tried")
	}
	select {
	case h := <-second.Hits:
		t.Fatalf("a second engine was tried without DPI evidence: %s", h)
	case <-time.After(300 * time.Millisecond):
	}
	noEvent(t, r)
	if st := r.obs.Stats(); st.Conns != 1 || st.Direct != 0 || st.Fallback != 0 {
		t.Fatalf("stats %+v", st)
	}
	if r.obs.DeadLen() != 0 {
		t.Fatal("a stall (timeouts only) is not a rejection and must not be remembered")
	}
}

// With DPI evidence (the direct attempt reset) the ladder stays open: the first
// engine stalls, the hedge moves on to the next one, and the very first
// connection opens.
func TestResetOpensTheWholeLadder(t *testing.T) {
	stuck := silentListener(t)
	r, censor := newRig(t, fakenet.Reset, func(o *Options) {
		o.FirstByte = 2 * time.Second
		o.Hedge = 150 * time.Millisecond
	})
	split := r.engine
	r.obs.opt.Engines = func() []Engine {
		return []Engine{{Name: "stuck", Addr: stuck.Addr().String()}, {Name: "split", Addr: split.Addr()}}
	}
	body, err := r.fetch(censor.Addr(), "blocked.test")
	if err != nil || body == "" {
		t.Fatalf("first connection must open through the second engine: %v", err)
	}
	e := r.event()
	if e.Outcome != Fallback || e.Engine != "split" || e.Results["direct"] == "" {
		t.Fatalf("event %+v", e)
	}
}

// A DPI box that ends the flow with a FIN (EOF before the server's first byte)
// is as much evidence as a reset: the ladder opens, the flow is repaired, and
// the event says the direct path was blocked.
func TestCleanCloseIsEvidenceToo(t *testing.T) {
	stuck := silentListener(t)
	r, censor := newRig(t, fakenet.Close, func(o *Options) {
		o.FirstByte = 2 * time.Second
		o.Hedge = 150 * time.Millisecond
	})
	split := r.engine
	r.obs.opt.Engines = func() []Engine {
		return []Engine{{Name: "stuck", Addr: stuck.Addr().String()}, {Name: "split", Addr: split.Addr()}}
	}
	body, err := r.fetch(censor.Addr(), "blocked.test")
	if err != nil || body == "" {
		t.Fatalf("first connection must open through the second engine: %v", err)
	}
	if e := r.event(); e.Outcome != Fallback || e.Engine != "split" || !e.Blocked {
		t.Fatalf("event %+v", e)
	}
}

// With EscalateOnSilence a silent block climbs the ladder: the first engine is
// silent too, and the next hedge tick starts the second one.
func TestEscalateOnSilenceOpensTheLadder(t *testing.T) {
	srv := silentListener(t)
	second, err := fakenet.NewSplitEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	r, _ := newRig(t, fakenet.Reset, func(o *Options) {
		o.FirstByte = 400 * time.Millisecond
		o.Hedge = 100 * time.Millisecond
		o.EscalateOnSilence = true
	})
	stuck := silentListener(t)
	r.obs.opt.Engines = func() []Engine {
		return []Engine{{Name: "stuck", Addr: stuck.Addr().String()}, {Name: "second", Addr: second.Addr()}}
	}
	_, ps, _ := net.SplitHostPort(srv.Addr().String())
	port, _ := net.LookupPort("tcp", ps)
	r.obs.opt.Ports = []int{port}
	_, _ = r.fetch(srv.Addr().String(), "quiet.example.org")
	select {
	case <-second.Hits:
	case <-time.After(2 * time.Second):
		t.Fatal("the second engine was not tried on silence")
	}
}
