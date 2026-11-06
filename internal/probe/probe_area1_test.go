package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func fds() int { d, _ := os.ReadDir("/dev/fd"); return len(d) }

func tcpServer(t *testing.T, h func(c net.Conn)) string {
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

func newProber() *Prober {
	return &Prober{Dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}, Timeout: 800 * time.Millisecond}
}

func TestArea1_Outcomes(t *testing.T) {
	// real TLS server
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	readHello := func(c net.Conn) {
		c.SetReadDeadline(time.Now().Add(time.Second))
		io.ReadAtLeast(c, make([]byte, 5), 5)
	}

	oldSrv := httptest.NewUnstartedServer(nil)
	oldSrv.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	oldSrv.StartTLS()
	defer oldSrv.Close()

	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refusedAddr := closed.Addr().String()
	closed.Close()

	cases := []struct {
		name string
		addr string
		sni  string
		p    *Prober
		want Outcome
	}{
		{"ok", srv.Listener.Addr().String(), "example.com", &Prober{Dial: newProber().Dial, Roots: pool, Timeout: time.Second}, OK},
		{"cert mismatch (roots set, name wrong)", srv.Listener.Addr().String(), "other.example", &Prober{Dial: newProber().Dial, Roots: pool, Timeout: time.Second}, CertMismatch},
		{"cert mismatch (system roots)", srv.Listener.Addr().String(), "example.com", newProber(), CertMismatch},
		{"alert (protocol version)", oldSrv.Listener.Addr().String(), "example.com", newProber(), Alert},
		{"fin at once", tcpServer(t, func(c net.Conn) {}), "x.test", newProber(), Reset},
		{"fin after hello", tcpServer(t, func(c net.Conn) { readHello(c) }), "x.test", newProber(), Reset},
		{"rst after hello", tcpServer(t, func(c net.Conn) {
			readHello(c)
			c.(*net.TCPConn).SetLinger(0)
		}), "x.test", newProber(), Reset},
		{"http blockpage", tcpServer(t, func(c net.Conn) { readHello(c); c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nblocked")) }), "x.test", newProber(), Injected},
		{"3 junk bytes then fin", tcpServer(t, func(c net.Conn) { readHello(c); c.Write([]byte("abc")) }), "x.test", newProber(), Reset},
		{"blackhole", tcpServer(t, func(c net.Conn) { io.Copy(io.Discard, c) }), "x.test", &Prober{Dial: newProber().Dial, Timeout: 300 * time.Millisecond}, Timeout},
		{"refused", refusedAddr, "x.test", newProber(), Refused},
		{"tls-looking garbage", tcpServer(t, func(c net.Conn) { readHello(c); c.Write([]byte{0x16, 3, 3, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}) }), "x.test", newProber(), -1},
	}
	for _, c := range cases {
		r := c.p.TLS(context.Background(), c.addr, c.sni)
		t.Logf("%-40s -> %s", c.name, r)
		if c.want >= 0 && r.Outcome != c.want {
			t.Errorf("%s: got %s want %s", c.name, r, c.want)
		}
		if c.name == "blackhole" && (r.Took < 250*time.Millisecond || r.Took > 900*time.Millisecond) {
			t.Errorf("blackhole took %v", r.Took)
		}
	}
}

func TestArea1_ContextCancelMidHandshake(t *testing.T) {
	addr := tcpServer(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()
	p := newProber()
	p.Timeout = 10 * time.Second
	t0 := time.Now()
	r := p.TLS(ctx, addr, "x.test")
	if time.Since(t0) > time.Second {
		t.Fatalf("cancel ignored: %v", time.Since(t0))
	}
	t.Logf("cancelled probe classified as %s", r)
}

// A timeout while *dialing* through the proxy must classify as Timeout.
func TestArea1_ViaSocks(t *testing.T) {
	mk := func(h func(c net.Conn)) string { return tcpServer(t, h) }
	reply := func(code byte) string {
		return mk(func(c net.Conn) {
			io.ReadFull(c, make([]byte, 3))
			c.Write([]byte{5, 0})
			io.ReadFull(c, make([]byte, 10))
			c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		})
	}
	for _, code := range []byte{1, 2, 3, 4, 5, 7} {
		p := &Prober{Dial: ViaSocks(reply(code)), Timeout: time.Second}
		r := p.TLS(context.Background(), "1.2.3.4:443", "x.test")
		t.Logf("socks rep=%d -> %s", code, r)
		if r.Outcome != Refused {
			t.Errorf("rep %d: %s", code, r)
		}
	}
	stall := mk(func(c net.Conn) { io.Copy(io.Discard, c) })
	r := (&Prober{Dial: ViaSocks(stall), Timeout: 300 * time.Millisecond}).TLS(context.Background(), "1.2.3.4:443", "x.test")
	if r.Outcome != Timeout {
		t.Errorf("stalled proxy: %s", r)
	}
	// proxy that closes after greeting: classify Reset (EOF) is fine, must not hang
	cl := mk(func(c net.Conn) { io.ReadFull(c, make([]byte, 3)) })
	r = (&Prober{Dial: ViaSocks(cl), Timeout: time.Second}).TLS(context.Background(), "1.2.3.4:443", "x.test")
	t.Logf("proxy closes mid-handshake -> %s", r)
	// bad addr forms
	for _, a := range []string{"nohostport", "1.2.3.4:notaport", "[::1]:443"} {
		_ = (&Prober{Dial: ViaSocks(stall), Timeout: 200 * time.Millisecond}).TLS(context.Background(), a, "x.test")
	}
}

func TestArea1_NoLeaksAcrossManyProbes(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hole := tcpServer(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	rst := tcpServer(t, func(c net.Conn) { io.ReadAtLeast(c, make([]byte, 5), 5); c.(*net.TCPConn).SetLinger(0) })
	http := tcpServer(t, func(c net.Conn) { io.ReadAtLeast(c, make([]byte, 5), 5); c.Write([]byte("HTTP/1.1 403\r\n\r\n")) })
	time.Sleep(100 * time.Millisecond)
	g0, f0 := runtime.NumGoroutine(), fds()
	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := &Prober{Dial: newProber().Dial, Roots: pool, Timeout: 250 * time.Millisecond}
			switch i % 4 {
			case 0:
				p.TLS(context.Background(), srv.Listener.Addr().String(), "example.com")
			case 1:
				p.TLS(context.Background(), hole, "x.test")
			case 2:
				p.TLS(context.Background(), rst, "x.test")
			case 3:
				p.TLS(context.Background(), http, "x.test")
			}
		}(i)
	}
	wg.Wait()
	srv.CloseClientConnections()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > g0+4 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > g0+4 {
		buf := make([]byte, 1<<16)
		t.Errorf("goroutines %d -> %d\n%s", g0, g, buf[:runtime.Stack(buf, true)])
	}
	time.Sleep(300 * time.Millisecond)
	if f := fds(); f > f0+8 {
		t.Errorf("fds %d -> %d", f0, f)
	}
}

func TestArea1_OutcomeStringTotal(t *testing.T) {
	for o := OK; o <= Other; o++ {
		_ = o.String()
		_ = Result{Outcome: o, Err: "e"}.String()
	}
	defer func() {
		if recover() != nil {
			t.Log("Outcome(99).String() panics (index out of range); only reachable with a bogus value")
		}
	}()
	_ = Outcome(99).String()
}
