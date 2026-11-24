//go:build !windows

package observer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fakenet"
	"github.com/Shuushi0/AutoDPI/internal/socks"
)

// r4Hello is a minimal ClientHello record for serverName padded to ~size bytes.
func r4Hello(serverName string, size int) []byte {
	name := []byte(serverName)
	l := 5 + len(name)
	ext := []byte{0, 0, byte(l >> 8), byte(l), byte((l - 2) >> 8), byte(l - 2), 0, byte(len(name) >> 8), byte(len(name))}
	ext = append(ext, name...)
	body := []byte{3, 3}
	body = append(body, bytes.Repeat([]byte{7}, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	pad := size - 4 - len(body) - 2 - len(ext) - 4
	if pad < 0 {
		pad = 0
	}
	ext = append(ext, 0, 21, byte(pad>>8), byte(pad))
	ext = append(ext, make([]byte, pad)...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	var out []byte
	for len(hs) > 0 {
		n := min(16384, len(hs))
		out = append(out, 0x16, 3, 1, byte(n>>8), byte(n))
		out = append(out, hs[:n]...)
		hs = hs[n:]
	}
	return out
}

var r4ServerHello = []byte{0x16, 3, 3, 0, 4, 2, 0, 0, 0}

// readRecord reads one TLS record from c.
func readRecord(c net.Conn) ([]byte, error) {
	h := make([]byte, 5)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, err
	}
	b := make([]byte, int(h[3])<<8|int(h[4]))
	_, err := io.ReadFull(c, b)
	return append(h, b...), err
}

// echoTLS answers the first record with a fake ServerHello, then echoes.
func echoTLS(t *testing.T) string {
	return rawServer(t, func(c net.Conn) {
		if _, err := readRecord(c); err != nil {
			return
		}
		if _, err := c.Write(r4ServerHello); err != nil {
			return
		}
		_, _ = io.Copy(c, c)
	})
}

// Observer.Close (daemon shutdown, maint restart, update restart) with one
// live flow whose client already half-closed (FIN) and whose server keeps its
// side open: Close waits for the server.
func TestRegressCloseHangsOnHalfClosedFlow(t *testing.T) {
	release := make(chan struct{})
	srv := rawServer(t, func(c net.Conn) {
		if _, err := readRecord(c); err != nil {
			return
		}
		c.Write(r4ServerHello)
		io.Copy(io.Discard, c) // sees the FIN ...
		<-release              // ... but keeps its side open (idle timeout of its own)
	})
	defer close(release)
	_, ps, _ := net.SplitHostPort(srv)
	var port int
	fmt.Sscan(ps, &port)
	o := New(Options{Dial: (&net.Dialer{}).DialContext, AllowLoopback: true, Ports: []int{port},
		HelloWait: 500 * time.Millisecond, ConnectTimeout: time.Second, FirstByte: time.Second})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go o.Serve(ln)
	c, err := r4Dial(t, ln.Addr().String(), srv)
	if err != nil {
		t.Fatal(err)
	}
	c.Write(r4Hello("halfclose.test", 600))
	if _, err := readRecord(c); err != nil {
		t.Fatal(err)
	}
	c.(interface{ CloseWrite() error }).CloseWrite()
	time.Sleep(200 * time.Millisecond)
	done := make(chan struct{})
	t0 := time.Now()
	go func() { o.Close(); close(done) }()
	select {
	case <-done:
		t.Logf("Close returned after %v", time.Since(t0))
	case <-time.After(10 * time.Second):
		t.Errorf("Observer.Close still blocked after 10 s: one half-closed flow holds daemon shutdown until its server closes")
		c.Close()
		select {
		case <-done:
			t.Logf("even after the CLIENT fully closed, Close returned only now (%v)", time.Since(t0))
		case <-time.After(3 * time.Second):
			t.Logf("Close still blocked 3 s after the client fully closed too")
		}
	}
}

func r4Dial(t testing.TB, proxy, target string) (net.Conn, error) {
	host, ps, _ := net.SplitHostPort(target)
	var port int
	fmt.Sscan(ps, &port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return socks.Dial(ctx, nil, proxy, host, port)
}

type r4srv struct {
	name string
	h    func(c net.Conn)
}

// What each kind of server makes of a flow, with production timing scaled down
// (hedge 200 ms, first byte 1.5 s, connect 1 s): outcome, duration, event, dead.
func TestRegressServerBehaviours(t *testing.T) {
	eng, err := fakenet.NewSplitEngine()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	cases := []r4srv{
		{"never answers", func(c net.Conn) { _, _ = readRecord(c); time.Sleep(5 * time.Second) }},
		{"answers after 1.2s (< first byte)", func(c net.Conn) {
			_, _ = readRecord(c)
			time.Sleep(1200 * time.Millisecond)
			c.Write(r4ServerHello)
			io.Copy(io.Discard, c)
		}},
		{"answers after 1.8s (> first byte)", func(c net.Conn) {
			_, _ = readRecord(c)
			time.Sleep(1800 * time.Millisecond)
			c.Write(r4ServerHello)
			io.Copy(io.Discard, c)
		}},
		{"reset after hello", func(c net.Conn) {
			_, _ = readRecord(c)
			c.(*net.TCPConn).SetLinger(0)
		}},
		{"TLS alert", func(c net.Conn) {
			_, _ = readRecord(c)
			c.Write([]byte{0x15, 3, 3, 0, 2, 2, 40})
		}},
		{"half header then stall", func(c net.Conn) {
			_, _ = readRecord(c)
			c.Write([]byte{0x16, 3})
			time.Sleep(5 * time.Second)
		}},
		{"close write only", func(c net.Conn) {
			_, _ = readRecord(c)
			c.(*net.TCPConn).CloseWrite()
			time.Sleep(3 * time.Second)
		}},
		{"HTTP reply (not TLS)", func(c net.Conn) {
			_, _ = readRecord(c)
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		}},
	}
	for _, sc := range cases {
		t.Run(sc.name, func(t *testing.T) {
			srv := rawServer(t, sc.h)
			var un atomic.Value
			o, addr, evs := obsFor(t, srv, func(o *Options) {
				o.Engines = func() []Engine {
					return []Engine{{Name: "split", Addr: eng.Addr()}, {Name: "split2", Addr: eng.Addr()}}
				}
				o.Hedge = 200 * time.Millisecond
				o.FirstByte = 1500 * time.Millisecond
				o.ConnectTimeout = time.Second
				o.Unopened = func(e Event) { un.Store(e) }
			})
			c, err := r4Dial(t, addr, srv)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			t0 := time.Now()
			_ = c.SetDeadline(time.Now().Add(8 * time.Second))
			c.Write(r4Hello("site.test", 600))
			b := make([]byte, 64)
			n, rerr := c.Read(b)
			took := time.Since(t0)
			var ev string
			select {
			case e := <-evs:
				ev = fmt.Sprintf("%s engine=%s blocked=%v results=%v", e.Outcome, e.Engine, e.Blocked, e.Results)
			case <-time.After(300 * time.Millisecond):
				ev = "none"
			}
			u, _ := un.Load().(Event)
			t.Logf("client got %d bytes % x err=%v after %v | event: %s | unopened: %v | dead=%d",
				n, b[:min(n, 9)], rerr, took.Round(10*time.Millisecond), ev, u.Results, o.DeadLen())
		})
	}
}

// r4Engine is a SOCKS5 engine that ignores the target and connects to to.
func r4Engine(t *testing.T, ln net.Listener, to string) {
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				cc, _, err := socks.Accept(c)
				if err != nil {
					return
				}
				up, err := net.Dial("tcp", to)
				if err != nil {
					_ = socks.Reply(cc, socks.RepHostUnreachable)
					return
				}
				defer up.Close()
				_ = socks.Reply(cc, socks.RepOK)
				go func() { io.Copy(up, cc); up.(*net.TCPConn).CloseWrite() }()
				io.Copy(cc, up)
			}()
		}
	}()
}

// The DPI resets direct and the first engine; the engine that would work
// (ciadpi) is restarting for a moment. The destination is parked for DeadTTL:
// once ciadpi is back, the site still does not open.
func TestRegressEngineRestartParksSite(t *testing.T) {
	resetter := rawServer(t, func(c net.Conn) { _, _ = readRecord(c); c.(*net.TCPConn).SetLinger(0) })
	good := echoTLS(t)
	lnA, _ := net.Listen("tcp", "127.0.0.1:0")
	r4Engine(t, lnA, resetter) // "tlsrec": reaches the server, reset
	lnB, _ := net.Listen("tcp", "127.0.0.1:0")
	bAddr := lnB.Addr().String()
	lnB.Close() // "ciadpi" down
	o, addr, evs := obsFor(t, resetter, func(o *Options) {
		o.Engines = func() []Engine {
			return []Engine{{Name: "tlsrec", Addr: lnA.Addr().String()}, {Name: "ciadpi", Addr: bAddr}}
		}
		o.Hedge = 200 * time.Millisecond
		o.DeadTTL = 10 * time.Minute
	})
	try := func() (int, error) {
		c, err := r4Dial(t, addr, resetter)
		if err != nil {
			return 0, err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		c.Write(r4Hello("blocked.test", 600))
		b := make([]byte, 16)
		return c.Read(b)
	}
	n, err := try()
	t.Logf("flow 1 (ciadpi down): %d bytes, %v, dead=%d", n, err, o.DeadLen())
	// ciadpi comes back
	lnB2, err := net.Listen("tcp", bAddr)
	if err != nil {
		t.Skip("could not rebind", err)
	}
	r4Engine(t, lnB2, good)
	for i := 2; i <= 4; i++ {
		n, err = try()
		var ev string
		select {
		case e := <-evs:
			ev = string(e.Outcome) + " " + e.Engine
		case <-time.After(200 * time.Millisecond):
			ev = "none"
		}
		t.Logf("flow %d (ciadpi up): %d bytes, %v, event %s, dead=%d", i, n, err, ev, o.DeadLen())
	}
	if n == 0 {
		t.Errorf("site stays unopened for DeadTTL although an engine that opens it is up again")
	}
}

// A DPI that drops (no reset) the plain and the record-fragmented ClientHello,
// while the second engine gets through. Without escalate_on_silence the ladder
// stops at the first engine: the site never opens and is never listed.
func TestRegressDropDPIWhereOnlySecondEngineWorks(t *testing.T) {
	silent := rawServer(t, func(c net.Conn) { _, _ = readRecord(c); time.Sleep(4 * time.Second) })
	good := echoTLS(t)
	lnA, _ := net.Listen("tcp", "127.0.0.1:0")
	r4Engine(t, lnA, silent)
	lnB, _ := net.Listen("tcp", "127.0.0.1:0")
	r4Engine(t, lnB, good)
	for _, esc := range []bool{false, true} {
		o, addr, evs := obsFor(t, silent, func(o *Options) {
			o.Engines = func() []Engine {
				return []Engine{{Name: "tlsrec", Addr: lnA.Addr().String()}, {Name: "ciadpi", Addr: lnB.Addr().String()}}
			}
			o.Hedge = 200 * time.Millisecond
			o.FirstByte = 1500 * time.Millisecond // production: 15 s
			o.EscalateOnSilence = esc
		})
		c, err := r4Dial(t, addr, silent)
		if err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write(r4Hello("dropped.test", 600))
		b := make([]byte, 16)
		n, err := c.Read(b)
		c.Close()
		ev := "none"
		select {
		case e := <-evs:
			ev = fmt.Sprintf("%s %s", e.Outcome, e.Engine)
		case <-time.After(200 * time.Millisecond):
		}
		t.Logf("escalate_on_silence=%v: client got %d bytes (%v) after %v; event %s; stats %+v", esc, n, err, time.Since(t0).Round(10*time.Millisecond), ev, o.Stats())
	}
}
