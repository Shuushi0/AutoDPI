package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func serveEcho(t *testing.T) string {
	path := sock(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Serve(ctx, path, func(_ context.Context, r Request) (any, error) { return map[string]string{"cmd": r.Cmd}, nil })
	for i := 0; i < 50 && func() bool { _, err := os.Stat(path); return err != nil }(); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	return path
}

func answer(t *testing.T, c net.Conn) Response {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var r Response
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&r); err != nil {
		t.Fatalf("no answer: %v", err)
	}
	return r
}

func TestOversizedRequestIsRefused(t *testing.T) {
	path := serveEcho(t)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		_, _ = c.Write([]byte(`{"cmd":"status","domain":"` + strings.Repeat("a", MaxRequest) + `"}`))
	}()
	if r := answer(t, c); r.OK || !strings.Contains(r.Error, "larger than") {
		t.Fatalf("answer %+v, want a size error", r)
	}
	// The server is still there for the next client.
	var out map[string]string
	if err := Call(path, Request{Cmd: "status"}, &out, 5*time.Second); err != nil || out["cmd"] != "status" {
		t.Fatalf("after an oversized request: %v %v", out, err)
	}
}

func TestTooManyConnectionsAreToldBusy(t *testing.T) {
	path := serveEcho(t)
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < MaxConns; i++ { // silent clients hold every slot
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	time.Sleep(100 * time.Millisecond)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if r := answer(t, c); r.OK || !strings.Contains(r.Error, "busy") {
		t.Fatalf("answer %+v, want busy", r)
	}
	// Once the silent ones are gone the service answers again.
	for _, c := range held {
		c.Close()
	}
	held = nil
	time.Sleep(100 * time.Millisecond)
	var out map[string]string
	if err := Call(path, Request{Cmd: "status"}, &out, 5*time.Second); err != nil {
		t.Fatalf("after the slots freed: %v", err)
	}
}
