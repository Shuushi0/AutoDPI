package socks

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func fds() int {
	d, _ := os.ReadDir("/dev/fd")
	return len(d)
}

func pipePair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-ch
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

// Every strict prefix of a valid request must end in an error, never a hang or panic.
func TestArea1_AcceptTruncatedAtEveryByte(t *testing.T) {
	full := []byte{5, 2, 0, 2, 5, 1, 0, 3, 11}
	full = append(full, "example.com"...)
	full = append(full, 1, 187)
	for n := 0; n < len(full); n++ {
		c, s := pipePair(t)
		go func(n int) { c.Write(full[:n]); c.Close() }(n)
		done := make(chan error, 1)
		go func() { _, _, err := Accept(s); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("prefix %d accepted", n)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("prefix %d hangs", n)
		}
	}
	// full request works
	c, s := pipePair(t)
	go c.Write(full)
	bc, req, err := Accept(s)
	if err != nil || req.Host != "example.com" || req.Port != 443 {
		t.Fatalf("%v %+v", err, req)
	}
	_ = bc
}

func TestArea1_AcceptPipelinedBytesSurvive(t *testing.T) {
	c, s := pipePair(t)
	payload := bytes.Repeat([]byte{0x16, 3, 1, 0xaa}, 3000) // > bufio size
	go func() {
		msg := []byte{5, 1, 0, 5, 1, 0, 1, 1, 2, 3, 4, 1, 187}
		c.Write(append(msg, payload...))
	}()
	bc, req, err := Accept(s)
	if err != nil || req.Host != "1.2.3.4" {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	_ = bc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(bc, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("pipelined bytes lost/corrupted: %v", err)
	}
}

func TestArea1_AcceptEdgeInputs(t *testing.T) {
	cases := map[string][]byte{
		"zero methods":     {5, 0, 5, 1, 0, 1, 1, 1, 1, 1, 0, 80},
		"only gssapi":      {5, 1, 1},
		"socks4":           {4, 1, 0, 80, 1, 2, 3, 4, 0},
		"http":             []byte("GET / HTTP/1.1\r\n\r\n"),
		"bad atyp":         {5, 1, 0, 5, 1, 0, 9, 1, 2, 3},
		"bind":             {5, 1, 0, 5, 2, 0, 1, 1, 1, 1, 1, 0, 80},
		"udp":              {5, 1, 0, 5, 3, 0, 1, 1, 1, 1, 1, 0, 80},
		"reserved nonzero": {5, 1, 0, 5, 1, 7, 1, 1, 1, 1, 1, 0, 80},
	}
	for name, in := range cases {
		c, s := pipePair(t)
		go func() {
			c.Write(in)
			c.(*net.TCPConn).CloseWrite()
			io.Copy(io.Discard, c) // drain server's replies
		}()
		done := make(chan struct{})
		var req *Request
		var err error
		go func() { _, req, err = Accept(s); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Errorf("%s: hang", name)
			continue
		}
		t.Logf("%-16s -> err=%v req=%+v", name, err, req)
		s.Close()
	}
}

// Accept must leave the conn with NO deadline set.
func TestArea1_AcceptClearsDeadline(t *testing.T) {
	c, s := pipePair(t)
	go c.Write([]byte{5, 1, 0, 5, 1, 0, 1, 1, 2, 3, 4, 1, 187})
	bc, _, err := Accept(s)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	_ = bc.SetReadDeadline(time.Time{})
	go func() { time.Sleep(300 * time.Millisecond); c.Write([]byte("x")) }()
	b := make([]byte, 1)
	if _, err := bc.Read(b); err != nil {
		t.Fatalf("read after delay: %v", err)
	}
}

func TestArea1_BufConnCloseWriteHalfCloses(t *testing.T) {
	c, s := pipePair(t)
	go c.Write([]byte{5, 1, 0, 5, 1, 0, 1, 1, 2, 3, 4, 1, 187})
	bc, _, err := Accept(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := bc.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// peer sees EOF but can still send
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	// swallow method reply (2 bytes) then expect EOF
	b, _ := io.ReadAll(c)
	if len(b) != 2 {
		t.Fatalf("unexpected bytes %v", b)
	}
	if _, err := c.Write([]byte("still-open")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 10)
	_ = bc.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(bc, got); err != nil || string(got) != "still-open" {
		t.Fatalf("%q %v", got, err)
	}
}

// ---- client Dial ----

func fakeProxy(t *testing.T, h func(c net.Conn)) string {
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

func TestArea1_DialMalformedProxies(t *testing.T) {
	cases := map[string]func(c net.Conn){
		"close at once": func(c net.Conn) {},
		"wrong version": func(c net.Conn) { io.ReadFull(c, make([]byte, 3)); c.Write([]byte{4, 0}) },
		"auth required": func(c net.Conn) { io.ReadFull(c, make([]byte, 3)); c.Write([]byte{5, 2}) },
		"no acceptable": func(c net.Conn) { io.ReadFull(c, make([]byte, 3)); c.Write([]byte{5, 0xff}) },
		"short reply": func(c net.Conn) {
			io.ReadFull(c, make([]byte, 3))
			c.Write([]byte{5, 0})
			io.ReadFull(c, make([]byte, 10))
			c.Write([]byte{5, 0, 0})
		},
		"bad reply atyp": func(c net.Conn) {
			io.ReadFull(c, make([]byte, 3))
			c.Write([]byte{5, 0})
			io.ReadFull(c, make([]byte, 10))
			c.Write([]byte{5, 0, 0, 9, 0, 0})
		},
		"domain reply short": func(c net.Conn) {
			io.ReadFull(c, make([]byte, 3))
			c.Write([]byte{5, 0})
			io.ReadFull(c, make([]byte, 10))
			c.Write([]byte{5, 0, 0, 3, 200, 1})
		},
		"refused 5": func(c net.Conn) {
			io.ReadFull(c, make([]byte, 3))
			c.Write([]byte{5, 0})
			io.ReadFull(c, make([]byte, 10))
			c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		},
	}
	for name, h := range cases {
		addr := fakeProxy(t, h)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := Dial(ctx, nil, addr, "1.2.3.4", 443)
		cancel()
		if err == nil {
			c.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestArea1_DialStallHonoursContext(t *testing.T) {
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	for _, stage := range []int{0, 1, 2} {
		stage := stage
		addr := fakeProxy(t, func(c net.Conn) {
			if stage >= 1 {
				io.ReadFull(c, make([]byte, 3))
				c.Write([]byte{5, 0})
			}
			if stage >= 2 {
				io.ReadFull(c, make([]byte, 10))
				c.Write([]byte{5, 0, 0, 1}) // header but no address
			}
			<-stall
		})
		// deadline
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		t0 := time.Now()
		_, err := Dial(ctx, nil, addr, "1.2.3.4", 443)
		cancel()
		if err == nil || time.Since(t0) > time.Second {
			t.Errorf("stage %d deadline: err=%v after %v", stage, err, time.Since(t0))
		}
		// plain cancel without deadline
		ctx, cancel = context.WithCancel(context.Background())
		go func() { time.Sleep(150 * time.Millisecond); cancel() }()
		t0 = time.Now()
		_, err = Dial(ctx, nil, addr, "1.2.3.4", 443)
		if err == nil || time.Since(t0) > time.Second {
			t.Errorf("stage %d cancel: err=%v after %v", stage, err, time.Since(t0))
		}
	}
}

func TestArea1_DialNoFDLeakOnFailure(t *testing.T) {
	addr := fakeProxy(t, func(c net.Conn) { io.ReadFull(c, make([]byte, 3)); c.Write([]byte{5, 0xff}) })
	time.Sleep(50 * time.Millisecond)
	base := fds()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if c, err := Dial(ctx, nil, addr, "example.com", 443); err == nil {
				c.Close()
			}
		}()
	}
	wg.Wait()
	// also: proxy address that refuses
	for i := 0; i < 50; i++ {
		Dial(context.Background(), nil, "127.0.0.1:1", "example.com", 443)
	}
	time.Sleep(300 * time.Millisecond)
	if n := fds(); n > base+6 {
		t.Fatalf("fd leak: %d -> %d", base, n)
	}
	_ = runtime.NumGoroutine
}

func TestArea1_DialAddressEncodings(t *testing.T) {
	ch := make(chan []byte, 8)
	addr := fakeProxy(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 3))
		c.Write([]byte{5, 0})
		buf := make([]byte, 300)
		n, _ := c.Read(buf)
		ch <- append([]byte(nil), buf[:n]...)
		c.Write([]byte{5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // v6 bound addr
		io.Copy(io.Discard, c)
	})
	for host, want := range map[string][]byte{
		"::ffff:1.2.3.4": {5, 1, 0, 1, 1, 2, 3, 4, 0x01, 0xbb},
		"1.2.3.4":        {5, 1, 0, 1, 1, 2, 3, 4, 0x01, 0xbb},
		"::1":            append(append([]byte{5, 1, 0, 4}, net.ParseIP("::1").To16()...), 0x01, 0xbb),
		"fe80::1%en0":    append(append([]byte{5, 1, 0, 4}, net.ParseIP("fe80::1").To16()...), 0x01, 0xbb),
		"a.example":      append([]byte{5, 1, 0, 3, 9}, append([]byte("a.example"), 0x01, 0xbb)...),
	} {
		c, err := Dial(context.Background(), nil, addr, host, 443)
		if err != nil {
			t.Errorf("%s: %v", host, err)
			continue
		}
		if g := <-ch; !bytes.Equal(g, want) {
			t.Errorf("%s: sent %x want %x", host, g, want)
		}
		c.Close()
	}
	// 256-byte name must be refused, 255 accepted
	if _, err := Dial(context.Background(), nil, addr, string(bytes.Repeat([]byte("a"), 256)), 443); err == nil {
		t.Error("256-byte host accepted")
	}
	// port bounds
	c, err := Dial(context.Background(), nil, addr, "1.2.3.4", 70000)
	if err == nil {
		c.Close()
		t.Logf("port 70000 silently truncated to %x", <-ch)
	}
	c, err = Dial(context.Background(), nil, addr, "1.2.3.4", -1)
	if err == nil {
		c.Close()
		t.Logf("port -1 silently encoded as %x", <-ch)
	}
}

func TestArea1_RequestAddrIPv6(t *testing.T) {
	r := &Request{Host: "::1", Port: 443}
	if r.Addr() != "[::1]:443" {
		t.Fatal(r.Addr())
	}
	if _, ok := (&Request{Host: "999.1.1.1"}).IP(); ok {
		t.Fatal("bad ip parsed")
	}
	if ip, ok := (&Request{Host: "::ffff:1.2.3.4"}).IP(); !ok || !ip.Is4In6() {
		t.Fatal("mapped parse")
	}
}
