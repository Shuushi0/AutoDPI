package observer

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fakenet"
	"github.com/Shuushi0/AutoDPI/internal/socks"
)

// ---------- helpers ----------

type capConn struct {
	net.Conn
	mu      sync.Mutex
	buf     bytes.Buffer
	readSig chan struct{}
	once    sync.Once
}

func (c *capConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
	return len(p), nil
}
func (c *capConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.readSig) })
	return 0, io.EOF
}
func (c *capConn) Close() error                       { return nil }
func (c *capConn) SetDeadline(t time.Time) error      { return nil }
func (c *capConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *capConn) SetWriteDeadline(t time.Time) error { return nil }

// captureHello returns every byte a Go TLS client writes before its first read.
func captureHello(cfg *tls.Config) []byte {
	cc := &capConn{readSig: make(chan struct{})}
	go func() { _ = tls.Client(cc, cfg).Handshake() }()
	<-cc.readSig
	time.Sleep(20 * time.Millisecond)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return append([]byte(nil), cc.buf.Bytes()...)
}

func rec(typ byte, body []byte) []byte {
	return append([]byte{typ, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

// fragConn splits the client's first record into two records, with a gap.
type fragConn struct {
	net.Conn
	n  atomic.Int32
	at int
}

func (f *fragConn) Write(p []byte) (int, error) {
	if f.n.Add(1) == 1 && len(p) > 5+f.at && p[0] == 0x16 {
		body := p[5:]
		if _, err := f.Conn.Write(rec(p[0], body[:f.at])); err != nil {
			return 0, err
		}
		time.Sleep(20 * time.Millisecond)
		if _, err := f.Conn.Write(rec(p[0], body[f.at:])); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return f.Conn.Write(p)
}

func socksConn(t *testing.T, proxy, target string) net.Conn {
	t.Helper()
	host, ps, _ := net.SplitHostPort(target)
	port, _ := net.LookupPort("tcp", ps)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := socks.Dial(ctx, nil, proxy, host, port)
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	return c
}

func fdCount() int {
	d, err := os.ReadDir("/dev/fd")
	if err != nil {
		return -1
	}
	return len(d)
}

// settle waits for the goroutine count to return to base (+slack).
func settle(t *testing.T, base int, within time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(within)
	var n int
	for time.Now().Before(deadline) {
		n = runtime.NumGoroutine()
		if n <= base+2 {
			return n
		}
		time.Sleep(50 * time.Millisecond)
	}
	return n
}

func ourStacks() string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var keep []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "github.com/Shuushi0/AutoDPI/internal/") && !strings.Contains(g, "testing.tRunner") && !strings.Contains(g, "ourStacks") {
			keep = append(keep, g)
		}
	}
	return strings.Join(keep, "\n\n")
}

// tlsLikeServer accepts conns, runs h on each. Returns addr.
func rawServer(t *testing.T, h func(c net.Conn)) string {
	t.Helper()
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
			go func() { defer c.Close(); h(c) }()
		}
	}()
	return ln.Addr().String()
}

func obsFor(t *testing.T, target string, mut func(*Options)) (*Observer, string, chan Event) {
	t.Helper()
	_, ps, _ := net.SplitHostPort(target)
	port, _ := net.LookupPort("tcp", ps)
	evs := make(chan Event, 256)
	opt := Options{
		Dial:           (&net.Dialer{}).DialContext,
		Events:         func(e Event) { evs <- e },
		HelloWait:      500 * time.Millisecond,
		ConnectTimeout: time.Second,
		FirstByte:      time.Second,
		Hedge:          100 * time.Millisecond,
		AllowLoopback:  true,
		Ports:          []int{port},
	}
	if mut != nil {
		mut(&opt)
	}
	o := New(opt)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = o.Serve(ln) }()
	t.Cleanup(func() { o.Close(); wg.Wait() })
	return o, ln.Addr().String(), evs
}

// ---------- 1. ClientHello spread over more than one TLS record ----------

// A client (or a record-fragmenting hop) may send the ClientHello as two TLS
// records. The observer reads only the first record, sends it, and waits for a
// server byte BEFORE it relays the rest, but the server cannot answer an
// incomplete ClientHello.
func TestArea1_FragmentedClientHelloRecords(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, nil)

	do := func(addr string) error {
		var c net.Conn
		var err error
		if addr == r.addr {
			host, ps, _ := net.SplitHostPort(censor.Addr())
			port, _ := net.LookupPort("tcp", ps)
			c, err = socks.Dial(context.Background(), nil, r.addr, host, port)
		} else {
			c, err = net.Dial("tcp", addr)
		}
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
		tc := tls.Client(&fragConn{Conn: c, at: 20}, &tls.Config{ServerName: "fine.test", InsecureSkipVerify: true})
		return tc.Handshake()
	}
	if err := do(censor.Addr()); err != nil {
		t.Fatalf("control (no observer) failed, test invalid: %v", err)
	}
	t0 := time.Now()
	if err := do(r.addr); err != nil {
		t.Fatalf("handshake via observer with 2-record ClientHello failed after %v: %v", time.Since(t0), err)
	}
}

// Same with a >16 KiB ClientHello, which Go itself must split into 2 records.
func TestArea1_HugeClientHelloOver16K(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, nil)
	long := strings.Repeat("a.", 9000) + "fine.test" // ~18 KB server_name
	cfg := func() *tls.Config {
		return &tls.Config{ServerName: long, InsecureSkipVerify: true}
	}
	hello := captureHello(cfg())
	t.Logf("captured ClientHello bytes: %d", len(hello))
	if len(hello) < 17000 {
		t.Skip("could not build >16K hello")
	}
	ctl, err := net.Dial("tcp", censor.Addr())
	if err != nil {
		t.Fatal(err)
	}
	_ = ctl.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tls.Client(ctl, cfg()).Handshake(); err != nil {
		ctl.Close()
		t.Skipf("origin refuses the big hello itself (%v)", err)
	}
	ctl.Close()

	c := socksConn(t, r.addr, censor.Addr())
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	t0 := time.Now()
	if err := tls.Client(c, cfg()).Handshake(); err != nil {
		t.Fatalf("handshake via observer failed after %v: %v", time.Since(t0), err)
	}
}

// ---------- 2. server's first segment shorter than a TLS record header ----------

func TestArea1_ServerFirstReplyTrickles(t *testing.T) {
	hello := captureHello(&tls.Config{ServerName: "slow.test", InsecureSkipVerify: true})
	srv := rawServer(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		if _, err := c.Read(buf); err != nil {
			return
		}
		// a legitimate (if odd) server/path: first TCP segment carries 1 byte
		c.Write([]byte{0x16})
		time.Sleep(60 * time.Millisecond)
		c.Write([]byte{0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4})
		io.Copy(io.Discard, c)
	})
	_, addr, evs := obsFor(t, srv, nil)
	c := socksConn(t, addr, srv)
	defer c.Close()
	c.Write(hello)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, 1+7)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("client got no data: %v", err)
	}
	select {
	case e := <-evs:
		if e.Outcome != Direct {
			t.Fatalf("valid TLS reply split across segments judged %s: %v", e.Outcome, e.Results)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
}

// ---------- 3. half-close ----------

func TestArea1_HalfCloseNonTLS(t *testing.T) {
	srv := rawServer(t, func(c net.Conn) {
		b, _ := io.ReadAll(c) // waits for client EOF
		c.Write([]byte("got:" + string(b)))
	})
	_, addr, _ := obsFor(t, srv, nil)
	c := socksConn(t, addr, srv)
	defer c.Close()
	c.Write([]byte("plain-hello"))
	c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(c)
	if string(got) != "got:plain-hello" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestArea1_HalfCloseTLSPath(t *testing.T) {
	hello := captureHello(&tls.Config{ServerName: "hc.test", InsecureSkipVerify: true})
	srv := rawServer(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		if _, err := c.Read(buf); err != nil {
			return
		}
		c.Write(rec(0x16, []byte{2, 0, 0, 0}))
		b, _ := io.ReadAll(c)
		c.Write([]byte("tail:" + string(b)))
	})
	for _, clean := range []bool{false, true} {
		t.Run(fmt.Sprintf("clean=%v", clean), func(t *testing.T) {
			_, addr, _ := obsFor(t, srv, func(o *Options) {
				if clean {
					o.Mode = func(string) Mode { return Light }
				}
			})
			c := socksConn(t, addr, srv)
			defer c.Close()
			c.Write(hello)
			hdr := make([]byte, 9)
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(c, hdr); err != nil {
				t.Fatal(err)
			}
			c.Write([]byte("more"))
			c.(*net.TCPConn).CloseWrite()
			got, err := io.ReadAll(c)
			if string(got) != "tail:more" {
				t.Fatalf("got %q err %v", got, err)
			}
		})
	}
}

// server half-closes first; client must still be able to send and server side
// must see it.
func TestArea1_ServerHalfCloseFirst(t *testing.T) {
	done := make(chan string, 1)
	srv := rawServer(t, func(c net.Conn) {
		c.Write([]byte("banner"))
		c.(*net.TCPConn).CloseWrite()
		b, _ := io.ReadAll(c)
		done <- string(b)
	})
	_, addr, _ := obsFor(t, srv, nil)
	c := socksConn(t, addr, srv)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	b := make([]byte, 6)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("late-client-data"))
	c.(*net.TCPConn).CloseWrite()
	select {
	case s := <-done:
		if s != "late-client-data" {
			t.Fatalf("server saw %q", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server never saw client data after its own half-close")
	}
}

// ---------- 4. slow clients ----------

// A client that is alive and sending (1 byte / 10 ms) but needs longer than
// HelloWait in total.
func TestArea1_SlowClientHello(t *testing.T) {
	hello := captureHello(&tls.Config{ServerName: "slowclient.test", InsecureSkipVerify: true})
	srv := rawServer(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		n, err := io.ReadFull(c, buf[:len(hello)])
		_ = n
		if err != nil {
			return
		}
		c.Write(rec(0x16, []byte{2, 0, 0, 0}))
		io.Copy(io.Discard, c)
	})
	_, addr, _ := obsFor(t, srv, func(o *Options) { o.HelloWait = 300 * time.Millisecond })
	c := socksConn(t, addr, srv)
	defer c.Close()
	// ~ len(hello)*4ms
	for i := range hello {
		if _, err := c.Write(hello[i : i+1]); err != nil {
			t.Fatalf("observer dropped a live, slowly sending client after %d/%d bytes: %v", i, len(hello), err)
		}
		time.Sleep(4 * time.Millisecond)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	h := make([]byte, 9)
	if _, err := io.ReadFull(c, h); err != nil {
		t.Fatalf("slow client got no reply (total hello time %d*4ms > HelloWait): %v", len(hello), err)
	}
}

// SOCKS handshake dribbled: Accept has a 10 s overall limit; just check a
// dribbled-but-valid handshake works and a stalled one is cut.
func TestArea1_SocksStallCut(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	srv := rawServer(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	o, addr, _ := obsFor(t, srv, nil)
	base := runtime.NumGoroutine()
	var cs []net.Conn
	for i := 0; i < 20; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte{5, 1}) // never finishes greeting
		cs = append(cs, c)
	}
	time.Sleep(200 * time.Millisecond)
	if g := runtime.NumGoroutine(); g < base+15 {
		t.Logf("goroutines %d (base %d)", g, base)
	}
	start := time.Now()
	_ = cs[0].SetReadDeadline(time.Now().Add(12 * time.Second))
	_, err := cs[0].Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected close")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("stalled SOCKS client not cut after 12s: %v", err)
	}
	t.Logf("stalled client cut after %v", time.Since(start))
	for _, c := range cs {
		c.Close()
	}
	_ = o
}

// ---------- 5. huge / non-hello first flights ----------

func TestArea1_DeclaredHugeRecordPassesThrough(t *testing.T) {
	got := make(chan []byte, 1)
	srv := rawServer(t, func(c net.Conn) {
		b, _ := io.ReadAll(c)
		got <- b
		c.Write([]byte("ok"))
	})
	_, addr, _ := obsFor(t, srv, nil)
	c := socksConn(t, addr, srv)
	defer c.Close()
	payload := append([]byte{0x16, 3, 1, 0xff, 0xff}, bytes.Repeat([]byte{0xab}, 200000)...)
	go func() { c.Write(payload); c.(*net.TCPConn).CloseWrite() }()
	select {
	case b := <-got:
		if !bytes.Equal(b, payload) {
			t.Fatalf("payload corrupted: got %d bytes want %d", len(b), len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never got the payload")
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, _ := io.ReadAll(c); string(b) != "ok" {
		t.Fatalf("reply %q", b)
	}
}

func TestArea1_TLSRecordZeroLengthAndTinyRecords(t *testing.T) {
	for _, first := range [][]byte{
		{0x16, 3, 1, 0, 0},
		{0x16, 3, 1, 0, 1, 0x01},
		{0x16, 3},
		{0x16},
		{0x15, 3, 3, 0, 2, 2, 40},
	} {
		first := first
		got := make(chan []byte, 1)
		srv := rawServer(t, func(c net.Conn) {
			b, _ := io.ReadAll(c)
			got <- b
		})
		_, addr, _ := obsFor(t, srv, func(o *Options) { o.HelloWait = 200 * time.Millisecond; o.FirstByte = 300 * time.Millisecond })
		c := socksConn(t, addr, srv)
		c.Write(first)
		c.(*net.TCPConn).CloseWrite()
		select {
		case b := <-got:
			// either forwarded intact or dropped; must never be mangled
			if len(b) != 0 && !bytes.Equal(b, first) {
				t.Errorf("first=%x forwarded as %x", first, b)
			}
			if len(b) == 0 {
				t.Logf("first=%x was dropped (not forwarded)", first)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("first=%x: server never saw EOF (observer hung)", first)
		}
		c.Close()
	}
}

// ---------- 6. many concurrent connections ----------

func TestArea1_ManyConcurrentFlows_NoLeak(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, func(o *Options) {
		o.HelloWait = 3 * time.Second
		o.ConnectTimeout = 3 * time.Second
		o.FirstByte = 3 * time.Second
	})
	var failedMu sync.Mutex
	var failedEvents []string
	go func() {
		for e := range r.events {
			if e.Outcome == Failed {
				failedMu.Lock()
				failedEvents = append(failedEvents, fmt.Sprintf("%s %v", e.SNI, e.Results))
				failedMu.Unlock()
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	baseG, baseF := runtime.NumGoroutine(), fdCount()
	const N = 300
	var wg sync.WaitGroup
	var fail atomic.Int32
	sem := make(chan struct{}, 40)
	for i := 0; i < N; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			sni := "fine.test"
			if i%3 == 0 {
				sni = "blocked.test"
			}
			if body, err := r.fetch(censor.Addr(), sni); err != nil || body == "" {
				fail.Add(1)
				if fail.Load() < 4 {
					t.Logf("flow %d (%s): %v", i, sni, err)
				}
			}
		}(i)
	}
	wg.Wait()
	if f := fail.Load(); f > 0 {
		time.Sleep(200 * time.Millisecond)
		failedMu.Lock()
		t.Errorf("%d/%d flows failed; Failed events: %v", f, N, failedEvents)
		failedMu.Unlock()
	}
	r.origin.CloseClientConnections()
	g := settle(t, baseG, 8*time.Second)
	if g > baseG+4 {
		t.Errorf("goroutines did not settle: base %d now %d\n%s", baseG, g, ourStacks())
	}
	time.Sleep(500 * time.Millisecond)
	if f := fdCount(); f > baseF+8 {
		t.Errorf("fd leak: base %d now %d", baseF, f)
	}
	st := r.obs.Stats()
	if st.Conns < N {
		t.Errorf("stats %+v", st)
	}
}

// ---------- 7. Close under load leaves nothing behind ----------

func TestArea1_CloseUnderLoad(t *testing.T) {
	hello := captureHello(&tls.Config{ServerName: "bh.test", InsecureSkipVerify: true})
	eng, _ := fakenet.NewSplitEngine()
	defer eng.Close()
	srv := rawServer(t, func(c net.Conn) { io.Copy(io.Discard, c) }) // blackhole
	base := runtime.NumGoroutine()
	baseF := fdCount()
	_, port, _ := net.SplitHostPort(srv)
	_ = port
	o, addr, _ := obsFor(t, srv, func(o *Options) {
		o.FirstByte = 10 * time.Second
		o.Engines = func() []Engine {
			return []Engine{{"a", eng.Addr()}, {"b", eng.Addr()}}
		}
		eng.Rewrite = map[string]string{}
	})
	var cs []net.Conn
	for i := 0; i < 40; i++ {
		c := socksConn(t, addr, srv)
		c.Write(hello)
		cs = append(cs, c)
	}
	time.Sleep(400 * time.Millisecond)
	start := time.Now()
	o.Close()
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Close took %v", d)
	}
	for _, c := range cs {
		c.Close()
	}
	eng.Close()
	g := settle(t, base, 5*time.Second)
	if g > base+3 {
		t.Errorf("goroutines after Close: base %d now %d\n%s", base, g, ourStacks())
	}
	time.Sleep(300 * time.Millisecond)
	if f := fdCount(); f > baseF+6 {
		t.Errorf("fds after Close: base %d now %d", baseF, f)
	}
}

// ---------- 8. client vanishes during the race ----------

func TestArea1_ClientGoneDuringRace(t *testing.T) {
	hello := captureHello(&tls.Config{ServerName: "bh.test", InsecureSkipVerify: true})
	var upstream atomic.Int32
	srv := rawServer(t, func(c net.Conn) {
		upstream.Add(1)
		defer upstream.Add(-1)
		io.Copy(io.Discard, c) // never answers
	})
	_, addr, _ := obsFor(t, srv, func(o *Options) { o.FirstByte = 2 * time.Second })
	c := socksConn(t, addr, srv)
	c.Write(hello)
	time.Sleep(150 * time.Millisecond)
	if upstream.Load() == 0 {
		t.Fatal("upstream attempt not started")
	}
	c.Close()
	// How soon does the observer release the upstream socket?
	t0 := time.Now()
	for upstream.Load() > 0 && time.Since(t0) < 4*time.Second {
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("upstream socket held for %v after the client left (FirstByte=2s)", time.Since(t0))
	if upstream.Load() > 0 {
		t.Fatal("upstream never released")
	}
}

// ---------- 9. large transfer integrity, both modes ----------

func TestArea1_BulkIntegrity(t *testing.T) {
	hello := captureHello(&tls.Config{ServerName: "bulk.test", InsecureSkipVerify: true})
	const size = 8 << 20
	srvGot := make(chan int64, 4)
	srv := rawServer(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		if _, err := c.Read(buf); err != nil {
			return
		}
		c.Write(rec(0x16, []byte{2, 0, 0, 0}))
		go func() {
			b := make([]byte, 1<<16)
			for i := range b {
				b[i] = byte(i * 7)
			}
			for sent := 0; sent < size; sent += len(b) {
				c.Write(b)
			}
			c.(*net.TCPConn).CloseWrite()
		}()
		n, _ := io.Copy(io.Discard, c)
		srvGot <- n
	})
	for _, clean := range []bool{false, true} {
		t.Run(fmt.Sprintf("clean=%v", clean), func(t *testing.T) {
			_, addr, _ := obsFor(t, srv, func(o *Options) {
				if clean {
					o.Mode = func(string) Mode { return Light }
				}
			})
			c := socksConn(t, addr, srv)
			defer c.Close()
			c.Write(hello)
			up := make(chan struct{})
			go func() {
				b := bytes.Repeat([]byte{9}, 1<<16)
				for s := 0; s < size; s += len(b) {
					c.Write(b)
				}
				c.(*net.TCPConn).CloseWrite()
				close(up)
			}()
			_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
			n, err := io.Copy(io.Discard, c)
			if n != size+9 || err != nil {
				t.Fatalf("client received %d (want %d) err %v", n, size+9, err)
			}
			<-up
			select {
			case g := <-srvGot:
				if g != size {
					t.Fatalf("server received %d want %d", g, size)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server never finished reading")
			}
		})
	}
}

// ---------- 10. light mode ----------

func TestArea1_LightModeFailureAccounting(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, func(o *Options) {
		o.Engines = func() []Engine { return nil }
	})
	var seenNames sync.Map
	r.obs.opt.Mode = func(h string) Mode { seenNames.Store(h, true); return Light }
	_, err := r.fetch(censor.Addr(), "BLOCKED.test") // uppercase SNI
	if err == nil {
		t.Fatal("no engines: must fail")
	}
	e := r.event()
	if e.Outcome != Failed || e.SNI != "blocked.test" {
		t.Fatalf("event %+v", e) // the one Failed event there is: it closes an open name
	}
	if _, ok := seenNames.Load("blocked.test"); !ok {
		t.Fatal("Mode did not get the lower-cased SNI")
	}
	// light ok flow: no event
	if body, err := r.fetch(censor.Addr(), "fine.test"); err != nil || body == "" {
		t.Fatal(err)
	}
	select {
	case e := <-r.events:
		t.Fatalf("light flow emitted event %+v", e)
	case <-time.After(300 * time.Millisecond):
	}
}

// Blackholed open host: direct attempt waits FirstByte, then engines run at
// once; the event reports the failed direct attempt.
func TestArea1_LightModeBlackhole(t *testing.T) {
	r, censor := newRig(t, fakenet.Drop, func(o *Options) {
		o.Mode = func(string) Mode { return Light }
		o.FirstByte = 600 * time.Millisecond
	})
	t0 := time.Now()
	body, err := r.fetch(censor.Addr(), "blocked.test")
	if err != nil || body == "" {
		t.Fatalf("fetch: %v", err)
	}
	t.Logf("took %v", time.Since(t0))
	e := r.event()
	if e.Outcome != Fallback || e.Results["direct"] == "" {
		t.Fatalf("%+v", e)
	}
}

// Many concurrent open flows to a host that starts failing: every one must be
// repaired and the racing cap must not eat them.
func TestArea1_LightModeConcurrentFailures(t *testing.T) {
	r, censor := newRig(t, fakenet.Reset, func(o *Options) {
		o.Mode = func(string) Mode { return Light }
		o.HelloWait = 3 * time.Second
	})
	var failed atomic.Int32
	go func() {
		for e := range r.events {
			if e.Outcome == Fallback && e.Results["direct"] != "" {
				failed.Add(1)
			}
		}
	}()
	const N = 40
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b, err := r.fetch(censor.Addr(), "blocked.test"); err != nil || b == "" {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Errorf("%d/%d failed (racing cap is 48/dest)", bad.Load(), N)
	}
	deadline := time.Now().Add(2 * time.Second)
	for failed.Load() != N && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if failed.Load() != N {
		t.Errorf("%d events report the failed direct attempt, want %d", failed.Load(), N)
	}
}

// ---------- 11. SOCKS edge cases through the observer ----------

func TestArea1_SocksOddRequests(t *testing.T) {
	srv := rawServer(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	resolved := atomic.Int32{}
	_, addr, _ := obsFor(t, srv, func(o *Options) {
		o.Resolve = func(ctx context.Context, h string) ([]netip.Addr, error) {
			resolved.Add(1)
			return nil, nil
		}
	})
	_, ps, _ := net.SplitHostPort(srv)
	port, _ := net.LookupPort("tcp", ps)
	pb := []byte{byte(port >> 8), byte(port)}
	try := func(name string, req []byte) byte {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte{5, 1, 0})
		io.ReadFull(c, make([]byte, 2))
		c.Write(req)
		rep := make([]byte, 10)
		if _, err := io.ReadFull(c, rep); err != nil {
			t.Logf("%s: no reply (%v)", name, err)
			return 255
		}
		return rep[1]
	}
	// empty domain name
	if r := try("empty-domain", append([]byte{5, 1, 0, 3, 0}, pb...)); r == 0 {
		t.Errorf("empty domain accepted")
	}
	// 255-byte domain
	if r := try("long-domain", append(append([]byte{5, 1, 0, 3, 255}, bytes.Repeat([]byte("a"), 255)...), pb...)); r == 0 {
		t.Errorf("garbage domain accepted")
	}
	// v4-mapped IPv6 loopback must be treated like 127.0.0.1
	m := append([]byte{5, 1, 0, 4}, net.ParseIP("::ffff:127.0.0.1").To16()...)
	if r := try("mapped", append(m, pb...)); r != 0 {
		t.Errorf("v4-mapped loopback rep=%d (AllowLoopback)", r)
	}
	// unsupported: BIND, UDP assoc
	for _, cmd := range []byte{2, 3} {
		if r := try("cmd", append([]byte{5, cmd, 0, 1, 127, 0, 0, 1}, pb...)); r != 7 && r != 255 {
			t.Errorf("cmd %d rep=%d", cmd, r)
		}
	}
	// port not allowed
	if r := try("port", []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); r != socks.RepNotAllowed {
		t.Errorf("port 80 rep=%d", r)
	}
	// loopback blocked in production mode
	_, addr2, _ := obsFor(t, srv, func(o *Options) { o.AllowLoopback = false })
	c, _ := net.Dial("tcp", addr2)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	c.Write(append([]byte{5, 1, 0, 1, 127, 0, 0, 1}, pb...))
	rep := make([]byte, 10)
	io.ReadFull(c, rep)
	if rep[1] != socks.RepNotAllowed {
		t.Errorf("loopback in prod mode rep=%d", rep[1])
	}
}

// ---------- 12. server-first protocol / silent client ----------

func TestArea1_ServerFirstSilentClient(t *testing.T) {
	srv := rawServer(t, func(c net.Conn) {
		c.Write([]byte("220 hi\r\n"))
		io.Copy(io.Discard, c)
	})
	_, addr, _ := obsFor(t, srv, func(o *Options) { o.HelloWait = 300 * time.Millisecond })
	c := socksConn(t, addr, srv)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 8)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "220 hi\r\n" {
		t.Fatalf("banner %q %v", b, err)
	}
}

// A silent client that half-closes (still expects the server's data).
func TestArea1_SilentClientHalfClosesFirst(t *testing.T) {
	srv := rawServer(t, func(c net.Conn) {
		io.ReadAll(c)
		c.Write([]byte("bye"))
	})
	_, addr, _ := obsFor(t, srv, nil)
	c := socksConn(t, addr, srv)
	defer c.Close()
	c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, _ := io.ReadAll(c)
	if string(b) != "bye" {
		t.Fatalf("got %q: connection dropped when client half-closed before sending", b)
	}
}

// ---------- 13. a blocking Events callback must not wedge Close ----------

func TestArea1_CloseWithBlockedEventsCallback(t *testing.T) {
	hello := captureHello(&tls.Config{ServerName: "ev.test", InsecureSkipVerify: true})
	srv := rawServer(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		c.Read(buf)
		c.Write(rec(0x16, []byte{2, 0, 0, 0}))
		io.Copy(io.Discard, c)
	})
	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	o, addr, _ := obsFor(t, srv, func(o *Options) {
		o.Events = func(Event) {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-block
		}
	})
	c := socksConn(t, addr, srv)
	defer c.Close()
	c.Write(hello)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("callback not reached")
	}
	done := make(chan struct{})
	go func() { o.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(block)
		<-done
		t.Fatal("Observer.Close hangs while an Events callback is blocked (Close waits for handlers, handlers wait for the callback)")
	}
	select {
	case <-block:
	default:
		close(block)
	}
}
