//go:build !windows

package daemon

// The design guarantees (README, "How it works"), exercised end to end: a real
// observer in front of a loopback "DPI" (fakenet.Censor) with a real bypass
// engine stand-in, wired to the daemon's own event handling, open-state and
// judging. Only the verdict.Check probes are faked.

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fakenet"
	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/socks"
	"github.com/Shuushi0/AutoDPI/internal/store"
	"github.com/Shuushi0/AutoDPI/internal/verdict"
)

type gRig struct {
	t       *testing.T
	d       *Daemon
	f       *fakeSys
	obsAddr string
	censor  *fakenet.Censor
	engine  *fakenet.SplitEngine

	mu      sync.Mutex
	blocked map[string]bool
}

func (g *gRig) block(names ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blocked = map[string]bool{}
	for _, n := range names {
		g.blocked[n] = true
	}
}

func newGRig(t *testing.T, mode fakenet.Mode) *gRig {
	t.Helper()
	d, f := rig(t, Options{})
	d.cands = make(chan candidate, 32)
	if _, err := d.st.Touch("asn:15897", "AS15897"); err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hello") }))
	t.Cleanup(origin.Close)
	g := &gRig{t: t, d: d, f: f, blocked: map[string]bool{}}
	censor, err := fakenet.NewCensor(origin.Listener.Addr().String(), mode, func(n string) bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.blocked[n]
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(censor.Close)
	eng, err := fakenet.NewSplitEngine()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	g.censor, g.engine = censor, eng
	_, ps, _ := net.SplitHostPort(censor.Addr())
	port, _ := net.LookupPort("tcp", ps)

	d.obs = observer.New(observer.Options{
		Engines:        func() []observer.Engine { return []observer.Engine{{Name: "tlsrec", Addr: eng.Addr()}} },
		Dial:           (&net.Dialer{}).DialContext,
		Events:         d.onEvent,
		Mode:           d.mode,
		HelloWait:      time.Second,
		ConnectTimeout: time.Second,
		FirstByte:      700 * time.Millisecond,
		Hedge:          150 * time.Millisecond,
		AllowLoopback:  true,
		Ports:          []int{port},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g.obsAddr = ln.Addr().String()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = d.obs.Serve(ln) }()
	t.Cleanup(func() { d.obs.Close(); wg.Wait() })
	return g
}

// fetch does a TLS+HTTP exchange with the server name sni through the observer.
func (g *gRig) fetch(sni string) error {
	g.t.Helper()
	host, ps, _ := net.SplitHostPort(g.censor.Addr())
	port, _ := net.LookupPort("tcp", ps)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := socks.Dial(ctx, nil, g.obsAddr, host, port)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		return err
	}
	if _, err := io.WriteString(tc, "GET / HTTP/1.0\r\nHost: x\r\n\r\n"); err != nil {
		return err
	}
	body, err := io.ReadAll(tc)
	if len(body) == 0 {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (g *gRig) nextCandidate() candidate {
	g.t.Helper()
	select {
	case c := <-g.d.cands:
		return c
	case <-time.After(4 * time.Second):
		g.t.Fatal("no candidate was queued for the repaired connection")
		return candidate{}
	}
}

func (g *gRig) noCandidate() {
	g.t.Helper()
	select {
	case c := <-g.d.cands:
		g.t.Fatalf("unexpected candidate %+v", c)
	case <-time.After(300 * time.Millisecond):
	}
}

// G1: a blocked site opens on the first connection with nothing learned and
// nothing seeded: the observer repairs the very same ClientHello.
func TestG1BlockedSiteOpensFirstTimeWithEmptyState(t *testing.T) {
	for name, mode := range map[string]fakenet.Mode{"RST": fakenet.Reset, "silence": fakenet.Drop} {
		t.Run(name, func(t *testing.T) {
			g := newGRig(t, mode)
			g.block("discord.test")
			if n := len(g.d.st.List("asn:15897")); n != 0 {
				t.Fatalf("state is not empty: %d entries", n)
			}
			if err := g.fetch("discord.test"); err != nil {
				t.Fatalf("first connection to a blocked site: %v", err)
			}
			c := g.nextCandidate()
			if c.host != "discord.test" || c.engine != "tlsrec" {
				t.Fatalf("candidate %+v", c)
			}
		})
	}
}

// G2: a site that opened directly (open) and is blocked later opens on the
// next attempt, and is judged and listed, so after that it goes to the engine
// without waiting for an RST. (Names avoid the .test suffix: it is not a
// public name and is never tracked or listed.)
func TestG2OpenSiteThatGetsBlockedOpensAndIsListed(t *testing.T) {
	g := newGRig(t, fakenet.Reset)
	g.block("api.later.example.org")
	for i := 0; i < 3; i++ {
		if err := g.fetch("www.later.example.org"); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "open", func() bool { return g.d.mode("www.later.example.org") == observer.Light })
	g.block("www.later.example.org")
	if err := g.fetch("www.later.example.org"); err != nil {
		t.Fatalf("first attempt after the block appeared: %v", err)
	}
	waitFor(t, "closed", func() bool { return g.d.mode("www.later.example.org") == observer.Full })
	c := g.nextCandidate()
	g.f.set(func(f *fakeSys) {
		f.checkFn = func(string, string) verdict.Verdict { return verdict.Verdict{Kind: verdict.Blocked, Engine: "tlsrec"} }
	})
	g.d.judge(context.Background(), c)
	if e, ok := g.d.st.Match("asn:15897", "cdn.later.example.org"); !ok || e.Domain != "example.org" {
		t.Fatalf("not listed after the judge: %+v %v", e, ok)
	}
}

// G3: a stalled link is not a block. A server nothing can open yields no
// candidate at all; a silent-only symptom that an engine does repair is at best
// one Suspect, which lists only if the second look, minutes later, agrees.
func TestG3StallIsNeverListed(t *testing.T) {
	t.Run("nothing opens it", func(t *testing.T) {
		g := newGRig(t, fakenet.Drop)
		g.block("hung.example.org")
		g.engine.Rewrite = map[string]string{g.censor.Addr(): "127.0.0.1:1"} // the engine cannot reach it either
		if err := g.fetch("hung.example.org"); err == nil {
			t.Fatal("expected the connection to fail")
		}
		g.noCandidate()
		if n := len(g.d.st.List("asn:15897")); n != 0 {
			t.Fatalf("listed %d entries", n)
		}
	})
	t.Run("silent only, engine opens it", func(t *testing.T) {
		g := newGRig(t, fakenet.Drop)
		g.block("slow.example.org")
		if err := g.fetch("slow.example.org"); err != nil {
			t.Fatal(err)
		}
		c := g.nextCandidate()
		g.f.set(func(f *fakeSys) {
			f.checkFn = func(string, string) verdict.Verdict { return verdict.Verdict{Kind: verdict.Suspect, Engine: "tlsrec"} }
		})
		g.d.judge(context.Background(), c)
		if _, ok := g.d.st.Match("asn:15897", "slow.example.org"); ok {
			t.Fatal("listed on a single Suspect")
		}
		ageJudgment(g.d, "asn:15897", "example.org", 6*time.Minute)
		g.d.judge(context.Background(), c)
		if _, ok := g.d.st.Match("asn:15897", "slow.example.org"); !ok {
			t.Fatal("not listed after the second Suspect")
		}
	})
	t.Run("unstable network", func(t *testing.T) {
		g := newGRig(t, fakenet.Reset)
		g.block("rst.example.org")
		if err := g.fetch("rst.example.org"); err != nil {
			t.Fatal(err)
		}
		c := g.nextCandidate()
		g.d.mu.Lock()
		g.d.badAt = time.Now()
		g.d.mu.Unlock()
		g.f.set(func(f *fakeSys) {
			f.checkFn = func(string, string) verdict.Verdict { return verdict.Verdict{Kind: verdict.Blocked, Engine: "tlsrec"} }
		})
		g.d.judge(context.Background(), c)
		if _, ok := g.d.st.Match("asn:15897", "rst.example.org"); ok {
			t.Fatal("listed while the health checks were failing")
		}
	})
}

// G5: lists and open names belong to one network.
func TestG5ListsAreNetworkSpecific(t *testing.T) {
	g := newGRig(t, fakenet.Reset)
	g.block("a.example.org")
	if err := g.fetch("a.example.org"); err != nil {
		t.Fatal(err)
	}
	c := g.nextCandidate()
	g.f.set(func(f *fakeSys) {
		f.checkFn = func(string, string) verdict.Verdict { return verdict.Verdict{Kind: verdict.Blocked, Engine: "tlsrec"} }
	})
	g.d.judge(context.Background(), c)
	if _, ok := g.d.st.Match("asn:15897", "a.example.org"); !ok {
		t.Fatal("not listed on its own network")
	}
	// Move to another network.
	other := netid.Info{Key: "asn:9121", Label: "AS9121", Online: true}
	g.f.set(func(f *fakeSys) { f.net = other })
	g.d.onNetChange(netid.Info{Key: "asn:15897"}, other)
	if _, ok := g.d.st.Match("asn:9121", "a.example.org"); ok {
		t.Fatal("the other network inherited the entry")
	}
	before := len(g.f.get().checks)
	g.d.judge(context.Background(), netCand("a.example.org"))
	if len(g.f.get().checks) != before+1 {
		t.Fatal("the other network did not judge the site itself")
	}
	if _, ok := g.d.st.Match("asn:9121", "a.example.org"); !ok {
		t.Fatal("not listed on the second network after its own verdict")
	}
	if len(g.d.st.List("asn:15897")) != 1 || len(g.d.st.List("asn:9121")) != 1 {
		t.Fatal("lists got mixed up")
	}
}

func netCand(host string) candidate {
	return candidate{host: host, ip: netip.MustParseAddr("203.0.113.5"), engine: "tlsrec"}
}

var _ = store.SourceAuto
