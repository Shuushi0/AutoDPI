package observer

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fakenet"
)

// rejector is a server that reads whatever a client sends and then closes, or,
// once Open is set, relays to target: a server that rejects the request, and one
// that recovers.
type rejector struct {
	ln       net.Listener
	accepted atomic.Int32
	open     atomic.Bool
}

func newRejector(t *testing.T, target string) *rejector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &rejector{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			go func() {
				defer c.Close()
				if !s.open.Load() {
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					_, _ = c.Read(make([]byte, 4096)) // the ClientHello, then nothing
					return
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				var wg sync.WaitGroup
				wg.Add(2)
				cp := func(dst, src net.Conn) {
					defer wg.Done()
					_, _ = io.Copy(dst, src)
					if cw, ok := dst.(interface{ CloseWrite() error }); ok {
						_ = cw.CloseWrite()
					}
				}
				go cp(up, c)
				go cp(c, up)
				wg.Wait()
			}()
		}
	}()
	return s
}

func (s *rejector) addr() string { return s.ln.Addr().String() }

// deadRig is a rig whose observer also accepts the rejector's port.
func deadRig(t *testing.T, mut func(*Options)) (*rig, *fakenet.Censor, *rejector) {
	t.Helper()
	r, censor := newRig(t, fakenet.Reset, mut)
	srv := newRejector(t, censor.Addr())
	_, ps, _ := net.SplitHostPort(srv.addr())
	port, _ := net.LookupPort("tcp", ps)
	r.obs.opt.Ports = append(r.obs.opt.Ports, port)
	return r, censor, srv
}

func settleAccepted(srv *rejector, want int32) int32 {
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) && srv.accepted.Load() < want {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // anything extra would show up now
	return srv.accepted.Load()
}

// A server that rejects the request (here: closes after the ClientHello) fails
// on the direct attempt and on an engine that reached it. That is remembered:
// the first flow tries both and reports nothing, the following ones only dial
// directly, until the entry expires.
func TestRejectedDestinationIsRemembered(t *testing.T) {
	r, _, srv := deadRig(t, nil)

	if _, err := r.fetch(srv.addr(), "nope.test"); err == nil {
		t.Fatal("a rejecting server opened")
	}
	if n := settleAccepted(srv, 2); n != 2 {
		t.Fatalf("first flow made %d connections, want direct + engine", n)
	}
	noEvent(t, r)
	if r.obs.DeadLen() != 1 {
		t.Fatalf("DeadLen = %d", r.obs.DeadLen())
	}

	for i := 0; i < 3; i++ {
		if _, err := r.fetch(srv.addr(), "nope.test"); err == nil {
			t.Fatal("a rejecting server opened")
		}
	}
	if n := settleAccepted(srv, 5); n != 5 {
		t.Fatalf("%d connections after 3 repeats, want 5 (direct only)", n)
	}
	noEvent(t, r)
	if st := r.obs.Stats(); st.Fallback != 0 || st.Direct != 0 {
		t.Fatalf("stats %+v", st)
	}

	// Another name on the same address is another destination: engines again.
	if _, err := r.fetch(srv.addr(), "other.test"); err == nil {
		t.Fatal("a rejecting server opened")
	}
	if n := settleAccepted(srv, 7); n != 7 {
		t.Fatalf("%d connections, want 7: a different name must get the full path", n)
	}
	if r.obs.DeadLen() != 2 {
		t.Fatalf("DeadLen = %d", r.obs.DeadLen())
	}
	noEvent(t, r)
}

func TestRememberedDestinationExpires(t *testing.T) {
	r, _, srv := deadRig(t, func(o *Options) { o.DeadTTL = 400 * time.Millisecond })
	_, _ = r.fetch(srv.addr(), "nope.test")
	if n := settleAccepted(srv, 2); n != 2 {
		t.Fatalf("%d connections", n)
	}
	_, _ = r.fetch(srv.addr(), "nope.test")
	if n := settleAccepted(srv, 3); n != 3 {
		t.Fatalf("%d connections, want 3 while remembered", n)
	}
	time.Sleep(500 * time.Millisecond)
	_, _ = r.fetch(srv.addr(), "nope.test")
	if n := settleAccepted(srv, 5); n != 5 {
		t.Fatalf("%d connections, want 5: the full path again after the ttl", n)
	}
}

func TestForgetDeadAndDisabledCache(t *testing.T) {
	r, _, srv := deadRig(t, nil)
	_, _ = r.fetch(srv.addr(), "nope.test")
	if n := r.obs.ForgetDead(); n != 1 {
		t.Fatalf("ForgetDead = %d", n)
	}
	settleAccepted(srv, 2)
	_, _ = r.fetch(srv.addr(), "nope.test")
	if n := settleAccepted(srv, 4); n != 4 {
		t.Fatalf("%d connections, want 4: the full path after ForgetDead", n)
	}

	r2, _, srv2 := deadRig(t, func(o *Options) { o.DeadTTL = -1 })
	for i := 0; i < 2; i++ {
		_, _ = r2.fetch(srv2.addr(), "nope.test")
	}
	if n := settleAccepted(srv2, 4); n != 4 || r2.obs.DeadLen() != 0 {
		t.Fatalf("disabled cache: %d connections, DeadLen %d", n, r2.obs.DeadLen())
	}
}

// A remembered destination whose direct attempt works again is open again: the
// entry goes and the next flow is observed normally.
func TestRememberedDestinationRecovers(t *testing.T) {
	r, _, srv := deadRig(t, nil)
	_, _ = r.fetch(srv.addr(), "fine.test")
	settleAccepted(srv, 2)
	if r.obs.DeadLen() != 1 {
		t.Fatal("not remembered")
	}
	srv.open.Store(true)
	if body, err := r.fetch(srv.addr(), "fine.test"); err != nil || body == "" {
		t.Fatalf("recovered server did not open: %v", err)
	}
	if r.obs.DeadLen() != 0 {
		t.Fatal("entry kept after the direct attempt worked")
	}
	noEvent(t, r) // the recovery flow itself was the cheap direct-only one
	if body, err := r.fetch(srv.addr(), "fine.test"); err != nil || body == "" {
		t.Fatal(err)
	}
	if e := r.event(); e.Outcome != Direct || e.SNI != "fine.test" {
		t.Fatalf("event %+v", e)
	}
}

// What proves nothing about the server is not remembered: an engine that is
// down (nothing listens), no engine at all.
func TestUnreachableEngineIsNotRemembered(t *testing.T) {
	gone, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := gone.Addr().String()
	gone.Close()
	r, _, srv := deadRig(t, func(o *Options) {
		o.Engines = func() []Engine { return []Engine{{Name: "split", Addr: addr}} }
	})
	_, _ = r.fetch(srv.addr(), "nope.test")
	_, _ = r.fetch(srv.addr(), "nope.test")
	if r.obs.DeadLen() != 0 {
		t.Fatal("a down engine says nothing about the server")
	}
	if n := settleAccepted(srv, 2); n != 2 {
		t.Fatalf("%d connections, want 2 (each flow tried direct)", n)
	}
	noEvent(t, r)
}

// A name that was open (light mode) and now fails on every path is the one
// failure that is reported, bare, so its owner can close it; the destination is
// remembered all the same.
func TestOpenNameThatFailsEverywhereIsReportedOnceThenQuiet(t *testing.T) {
	r, _, srv := deadRig(t, func(o *Options) {
		o.Mode = func(string) Mode { return Light }
	})
	_, _ = r.fetch(srv.addr(), "was-open.test")
	e := r.event()
	if e.Outcome != Failed || e.SNI != "was-open.test" || e.Results != nil {
		t.Fatalf("event %+v", e)
	}
	if n := settleAccepted(srv, 2); n != 2 { // the light direct attempt, then the engine
		t.Fatalf("%d connections, want 2", n)
	}
	if r.obs.DeadLen() != 1 {
		t.Fatal("not remembered")
	}
	before := srv.accepted.Load()
	_, _ = r.fetch(srv.addr(), "was-open.test")
	if n := settleAccepted(srv, before+1); n != before+1 {
		t.Fatalf("repeat made %d connections, want 1", n-before)
	}
	noEvent(t, r)
}

// holdServer accepts, reads the ClientHello and closes only once released: a
// flow that is still in flight while the network changes.
func holdServer(t *testing.T) (net.Listener, *atomic.Int32, chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var accepted atomic.Int32
	release := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				_, _ = c.Read(make([]byte, 4096))
				<-release
			}()
		}
	}()
	return ln, &accepted, release
}

// A flow that began before ForgetDead (the old network, or a capture being torn
// down) fails on what that network did to it. Remembering that afterwards would
// leave the destination on engine-less direct attempts on the new network, where
// a DPI block then has no way of being repaired or even seen.
func TestFlowFromBeforeForgetDeadIsNotRemembered(t *testing.T) {
	r, _ := newRig(t, fakenet.Reset, func(o *Options) { o.Hedge = 20 * time.Millisecond })
	ln, accepted, release := holdServer(t)
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := net.LookupPort("tcp", ps)
	r.obs.opt.Ports = append(r.obs.opt.Ports, port)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.fetch(ln.Addr().String(), "old-network.test")
	}()
	for deadline := time.Now().Add(3 * time.Second); accepted.Load() < 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d connections, want direct + engine in flight", accepted.Load())
		}
	}
	r.obs.ForgetDead()
	close(release) // both attempts now fail with a close: a rejection, on the old network
	<-done
	time.Sleep(50 * time.Millisecond)
	if n := r.obs.DeadLen(); n != 0 {
		t.Fatalf("DeadLen = %d: a flow from before the change was remembered after it", n)
	}
}

// A flow nothing delivered is no Event, but its attempts reach Unopened: the
// first with what each path did, the next ones marked as getting no engines.
func TestUnopenedReportsWhatFailed(t *testing.T) {
	seen := make(chan Event, 4)
	r, _, srv := deadRig(t, func(o *Options) { o.Unopened = func(e Event) { seen <- e } })
	_, _ = r.fetch(srv.addr(), "nope.test")
	e := <-seen
	if e.SNI != "nope.test" || e.Remembered || !e.Blocked || e.Results["direct"] == "" || e.Results["split"] == "" {
		t.Fatalf("first flow: %+v", e)
	}
	_, _ = r.fetch(srv.addr(), "nope.test")
	e = <-seen
	if !e.Remembered || e.Results["direct"] == "" || e.Results["split"] != "" {
		t.Fatalf("remembered flow: %+v", e)
	}
	noEvent(t, r)
}
