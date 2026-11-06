package socks

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// proxy accepts one SOCKS connection and reports the request it saw.
func proxy(t *testing.T, code byte) (addr string, got chan *Request, payload chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got, payload = make(chan *Request, 1), make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		bc, req, err := Accept(c)
		if err != nil {
			return
		}
		got <- req
		_ = Reply(bc, code)
		if code != RepOK {
			return
		}
		buf := make([]byte, 64)
		n, _ := bc.Read(buf)
		payload <- buf[:n]
	}()
	return ln.Addr().String(), got, payload
}

func TestRoundTrip(t *testing.T) {
	for _, host := range []string{"203.0.113.9", "2001:db8::1", "discord.com"} {
		addr, got, payload := proxy(t, RepOK)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := Dial(ctx, nil, addr, host, 443)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		_, _ = c.Write([]byte("hello"))
		req := <-got
		if req.Host != host || req.Port != 443 {
			t.Fatalf("%s: server saw %+v", host, req)
		}
		if p := <-payload; string(p) != "hello" {
			t.Fatalf("%s: payload %q", host, p)
		}
		c.Close()
	}
}

func TestRefused(t *testing.T) {
	addr, _, _ := proxy(t, RepRefused)
	_, err := Dial(context.Background(), nil, addr, "203.0.113.9", 443)
	re, ok := err.(*ReplyError)
	if !ok || re.Code != RepRefused {
		t.Fatalf("want ReplyError(5), got %v", err)
	}
}

// A client may pipeline payload right behind the CONNECT request; Accept must
// not swallow it in its read buffer.
func TestPipelinedPayloadSurvives(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		msg := []byte{5, 1, 0, 5, 1, 0, 1, 1, 2, 3, 4, 0x01, 0xbb, 'T', 'L', 'S'}
		_, _ = c1.Write(msg)
		// drain the server's two replies so its writes do not block
		go io.Copy(io.Discard, c1)
	}()
	bc, req, err := Accept(c2)
	if err != nil {
		t.Fatal(err)
	}
	if req.Host != "1.2.3.4" || req.Port != 443 {
		t.Fatalf("bad request %+v", req)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(bc, buf); err != nil || string(buf) != "TLS" {
		t.Fatalf("payload = %q, %v", buf, err)
	}
}
