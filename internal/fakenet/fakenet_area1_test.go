package fakenet

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/socks"
)

func fds() int { d, _ := os.ReadDir("/dev/fd"); return len(d) }

func echoBackend(t *testing.T) string {
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
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func helloFor(name string) []byte {
	// minimal ClientHello carrying an SNI
	ext := []byte{0, 0}
	n := []byte{0, byte(len(name) + 3), 0, 0, byte(len(name))}
	n = append(n, name...)
	ext = append(ext, 0, byte(len(n)))
	ext = append(ext, n...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, 0, byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// Censor.conns grows with every accepted connection and is never pruned.
func TestArea1_CensorConnsMapGrows(t *testing.T) {
	c, err := NewCensor(echoBackend(t), Reset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 100; i++ {
		k, err := net.Dial("tcp", c.Addr())
		if err != nil {
			t.Fatal(err)
		}
		k.Write(helloFor("ok.test"))
		k.Write([]byte("x"))
		k.(*net.TCPConn).CloseWrite()
		io.ReadAll(k)
		k.Close()
	}
	time.Sleep(200 * time.Millisecond)
	c.mu.Lock()
	n := len(c.conns)
	c.mu.Unlock()
	if n > 5 {
		t.Errorf("Censor retains %d finished connections in c.conns (never deleted)", n)
	}
}

func TestArea1_CensorModesAndSeen(t *testing.T) {
	be := echoBackend(t)
	for _, mode := range []Mode{Reset, Drop} {
		c, _ := NewCensor(be, mode, func(n string) bool { return n == "bad.test" })
		// pass
		k, _ := net.Dial("tcp", c.Addr())
		h := helloFor("good.test")
		k.Write(h)
		got := make([]byte, len(h))
		_ = k.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(k, got); err != nil || !bytes.Equal(got, h) {
			t.Errorf("mode %d pass: %v", mode, err)
		}
		k.Close()
		// blocked
		k, _ = net.Dial("tcp", c.Addr())
		k.Write(helloFor("bad.test"))
		_ = k.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		_, err := k.Read(make([]byte, 1))
		ne, isNet := err.(net.Error)
		switch mode {
		case Reset:
			if err == nil || (isNet && ne.Timeout()) || !strings.Contains(err.Error(), "reset") {
				t.Errorf("Reset mode: %v", err)
			}
		case Drop:
			if !isNet || !ne.Timeout() {
				t.Errorf("Drop mode: %v", err)
			}
		}
		k.Close()
		// split first segment evades
		k, _ = net.Dial("tcp", c.Addr())
		h = helloFor("bad.test")
		k.Write(h[:1])
		time.Sleep(30 * time.Millisecond)
		k.Write(h[1:])
		got = make([]byte, len(h))
		_ = k.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(k, got); err != nil {
			t.Errorf("mode %d split: %v", mode, err)
		}
		k.Close()
		c.Close()
	}
}

// Close must release held (black-holed) flows and not leak goroutines.
func TestArea1_CensorCloseReleasesDrops(t *testing.T) {
	be := echoBackend(t)
	runtime.GC()
	g0, f0 := runtime.NumGoroutine(), fds()
	c, _ := NewCensor(be, Drop, func(string) bool { return true })
	var ks []net.Conn
	for i := 0; i < 30; i++ {
		k, _ := net.Dial("tcp", c.Addr())
		k.Write(helloFor("x.test"))
		ks = append(ks, k)
	}
	time.Sleep(100 * time.Millisecond)
	c.Close()
	for _, k := range ks {
		_ = k.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := k.Read(make([]byte, 1)); err == nil {
			t.Error("data after close")
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Error("censor.Close left a dropped flow open")
		}
		k.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > g0+2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > g0+2 {
		t.Errorf("goroutines %d -> %d", g0, g)
	}
	if f := fds(); f > f0+3 {
		t.Errorf("fds %d -> %d", f0, f)
	}
}

// Closing the censor while a forwarded flow is live: does the flow die?
func TestArea1_CensorCloseKillsForwardedFlows(t *testing.T) {
	be := echoBackend(t)
	c, _ := NewCensor(be, Reset, nil)
	k, _ := net.Dial("tcp", c.Addr())
	defer k.Close()
	k.Write(helloFor("x.test"))
	io.ReadFull(k, make([]byte, 5))
	c.Close()
	_ = k.SetReadDeadline(time.Now().Add(time.Second))
	k.Write([]byte("more"))
	_, err := io.ReadAll(k)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("Close left forwarded flow alive")
	}
}

// SplitEngine: half-close by client truncates the reply; Close leaves live flows.
func TestArea1_SplitEngineHalfClose(t *testing.T) {
	srv, _ := net.Listen("tcp", "127.0.0.1:0")
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); b, _ := io.ReadAll(c); c.Write(append([]byte("echo:"), b...)) }()
		}
	}()
	e, _ := NewSplitEngine()
	defer e.Close()
	c, err := socks.Dial(context.Background(), nil, e.Addr(), "127.0.0.1", srv.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello-world"))
	c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, _ := io.ReadAll(c)
	if string(b) != "echo:hello-world" {
		t.Errorf("SplitEngine truncated half-closed flow: got %q", b)
	}
}

func TestArea1_SplitEngineSplitsFirstWriteAndRewrite(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	srv, _ := net.Listen("tcp", "127.0.0.1:0")
	defer srv.Close()
	go func() {
		c, err := srv.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 100)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				mu.Lock()
				sizes = append(sizes, n)
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	e, _ := NewSplitEngine()
	defer e.Close()
	e.Rewrite = map[string]string{"203.0.113.5:443": srv.Addr().String()}
	c, err := socks.Dial(context.Background(), nil, e.Addr(), "203.0.113.5", 443)
	if err != nil {
		t.Fatal(err)
	}
	c.Write(bytes.Repeat([]byte{1}, 50))
	time.Sleep(100 * time.Millisecond)
	c.Close()
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(sizes) != 2 || sizes[0] != 1 || sizes[1] != 49 {
		t.Errorf("segments: %v", sizes)
	}
	select {
	case h := <-e.Hits:
		if h != srv.Addr().String() {
			t.Errorf("hit %s", h)
		}
	default:
		t.Error("no hit recorded")
	}
}

// A connect to an unreachable target must yield a SOCKS failure, not a hang.
func TestArea1_SplitEngineRefusedTarget(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	e, _ := NewSplitEngine()
	defer e.Close()
	_, err := socks.Dial(context.Background(), nil, e.Addr(), "127.0.0.1", port)
	if re, ok := err.(*socks.ReplyError); !ok || re.Code != socks.RepRefused {
		t.Fatalf("%v", err)
	}
}

// Silent client: the engine holds goroutine+2 fds until the peer closes, forever.
func TestArea1_SplitEngineSilentClientHeldForever(t *testing.T) {
	be := echoBackend(t)
	e, _ := NewSplitEngine()
	defer e.Close()
	_, port, _ := net.SplitHostPort(be)
	p, _ := net.LookupPort("tcp", port)
	g0 := runtime.NumGoroutine()
	c, err := socks.Dial(context.Background(), nil, e.Addr(), "127.0.0.1", p)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if g := runtime.NumGoroutine(); g <= g0 {
		t.Skip("not held")
	}
	c.Close()
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > g0+1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > g0+2 {
		t.Errorf("goroutines leaked after peer closed: %d -> %d", g0, g)
	}
}
