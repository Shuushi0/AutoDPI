//go:build !windows

package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
)

func area4Sock(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ipc4")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "s")
}

func area4Serve(t *testing.T, path string, h Handler) (cancel func(), done chan error) {
	t.Helper()
	ctx, c := context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { done <- Serve(ctx, path, h) }()
	for i := 0; i < 200; i++ {
		if conn, err := net.Dial("unix", path); err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(c)
	return c, done
}

func echo(_ context.Context, r Request) (any, error) { return map[string]string{"cmd": r.Cmd}, nil }

// BUG (medium): ipc.Serve returns on the first Accept error. A transient
// EMFILE ("too many open files", plausible under load: the daemon proxies every
// TCP/443 flow and runs with a 16384 fd limit) ends the control server, and
// daemon.Run treats a Serve error as fatal (daemon.go: cancel()), so the
// whole daemon, TUN included, shuts down because one accept() failed.
// A server loop must retry temporary accept errors (like net/http does).
func TestArea4_ServeSurvivesTransientAcceptError(t *testing.T) {
	path := area4Sock(t)
	_, done := area4Serve(t, path, echo)

	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		t.Skip(err)
	}
	low := syscall.Rlimit{Cur: 128, Max: orig.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Skip(err)
	}
	var hogs []*os.File
	restore := func() {
		for _, f := range hogs {
			f.Close()
		}
		hogs = nil
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &orig)
	}
	defer restore()
	for {
		f, err := os.Open("/dev/null")
		if err != nil {
			break
		}
		hogs = append(hogs, f)
	}
	// free exactly one descriptor for the client side of the connection
	hogs[len(hogs)-1].Close()
	hogs = hogs[:len(hogs)-1]
	c, err := net.Dial("unix", path) // takes the last fd; the server's accept() has none left
	if err != nil {
		restore()
		t.Skipf("could not stage EMFILE: %v", err)
	}
	var serveErr error
	select {
	case serveErr = <-done:
	case <-time.After(1500 * time.Millisecond):
	}
	c.Close()
	restore()
	if serveErr != nil {
		t.Fatalf("Serve gave up on a transient accept error and returned: %v", serveErr)
	}
	// and it must still serve afterwards
	var out map[string]string
	if err := Call(path, Request{Cmd: "after"}, &out, 2*time.Second); err != nil || out["cmd"] != "after" {
		t.Fatalf("control server dead after the fd shortage: %v", err)
	}
}

// BUG (low): after a SIGKILLed daemon the socket file remains; Call then
// reports a raw "connect: connection refused" rather than "daemon is not
// running", unlike the "no such file" case and unlike the macOS app, which maps
// ECONNREFUSED to "not running". `autodpi status` is what a user types after
// a crash.
func TestArea4_CallOnStaleSocketSaysDaemonNotRunning(t *testing.T) {
	path := area4Sock(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close() // file stays, nobody listens
	err = Call(path, Request{Cmd: "status"}, nil, time.Second)
	if want := i18n.T("servis çalışmıyor", "the service is not running"); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("stale socket: got %v, want %q", err, want)
	}
}

// BUG (low): the server closes the connection without a response when the
// request is malformed, and Call surfaces a bare io.EOF ("hata: EOF").
func TestArea4_MalformedRequestGetsAReadableError(t *testing.T) {
	path := area4Sock(t)
	area4Serve(t, path, echo)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("this is not json\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, _ := io.ReadAll(c)
	if len(b) == 0 {
		t.Errorf("malformed request: connection closed with no error response (client would print just EOF)")
	}
}

// Serve must not delete a regular file that merely sits at the socket path.
func TestArea4_ServeDoesNotClobberRegularFile(t *testing.T) {
	path := area4Sock(t)
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, path, echo) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "precious" {
		t.Errorf("a regular file at the socket path was deleted/replaced (err=%v content=%q)", err, b)
	}
}

func TestArea4_CallTimeoutIsHonouredWhenServerStalls(t *testing.T) {
	path := area4Sock(t)
	area4Serve(t, path, func(ctx context.Context, r Request) (any, error) {
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
		}
		return nil, nil
	})
	start := time.Now()
	err := Call(path, Request{Cmd: "slow"}, nil, 300*time.Millisecond)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("stalled server: err=%v after %v", err, time.Since(start))
	}
}

func TestArea4_RefusesSecondDaemonAndCleansStaleSocket(t *testing.T) {
	path := area4Sock(t)
	cancel, done := area4Serve(t, path, echo)
	if err := Serve(context.Background(), path, echo); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("second Serve over a live daemon: %v", err)
	}
	// the live one still answers (the refused Serve must not have removed its socket)
	if err := Call(path, Request{Cmd: "x"}, nil, time.Second); err != nil {
		t.Errorf("first daemon broken by the refused start: %v", err)
	}
	cancel()
	<-done
	if _, err := os.Stat(path); err == nil {
		t.Error("socket file left after shutdown")
	}
	// stale socket file from a crash is replaced
	ln, _ := net.Listen("unix", path)
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	_, done2 := area4Serve(t, path, echo)
	if err := Call(path, Request{Cmd: "y"}, nil, time.Second); err != nil {
		t.Errorf("stale socket not replaced: %v", err)
	}
	select {
	case err := <-done2:
		t.Errorf("Serve returned early: %v", err)
	default:
	}
}

func TestArea4_SocketIsNotWorldAccessible(t *testing.T) {
	path := area4Sock(t)
	area4Serve(t, path, echo)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o007 != 0 {
		t.Errorf("socket mode %v lets 'other' connect", st.Mode().Perm())
	}
}

func TestArea4_PanicErrorAndBigPayloads(t *testing.T) {
	path := area4Sock(t)
	area4Serve(t, path, func(_ context.Context, r Request) (any, error) {
		switch r.Cmd {
		case "panic-nil":
			var m map[string]int
			//lint:ignore SA5000 a runtime error panic, on purpose
			m["x"] = 1
		case "panic-err":
			panic(errors.New("boom"))
		case "big":
			return strings.Repeat("x", 2<<20), nil
		case "unmarshalable":
			return make(chan int), nil
		case "typed-nil":
			var p *struct{ A int }
			return p, nil
		case "bigreq":
			return len(r.Domain), nil
		}
		return nil, nil
	})
	for _, c := range []string{"panic-nil", "panic-err", "unmarshalable"} {
		if err := Call(path, Request{Cmd: c}, nil, 2*time.Second); err == nil {
			t.Errorf("%s: no error", c)
		}
	}
	var s string
	if err := Call(path, Request{Cmd: "big"}, &s, 10*time.Second); err != nil || len(s) != 2<<20 {
		t.Errorf("2MB response: %v len=%d", err, len(s))
	}
	var st struct{ A int }
	if err := Call(path, Request{Cmd: "typed-nil"}, &st, 2*time.Second); err != nil {
		t.Errorf("typed nil: %v", err)
	}
	// A request just under MaxRequest goes through; an 8MB one is refused
	// (the server stops reading, so the client sees an error or a broken pipe).
	var n int
	if err := Call(path, Request{Cmd: "bigreq", Domain: strings.Repeat("d", MaxRequest-100)}, &n, 10*time.Second); err != nil || n != MaxRequest-100 {
		t.Errorf("request under the limit: %v %d", err, n)
	}
	if err := Call(path, Request{Cmd: "bigreq", Domain: strings.Repeat("d", 8<<20)}, &n, 10*time.Second); err == nil {
		t.Errorf("8MB request was served")
	}
	// daemon still answers after the panics
	if err := Call(path, Request{Cmd: "ok"}, nil, time.Second); err != nil {
		t.Errorf("server dead after panics: %v", err)
	}
}

// A client that connects and sends nothing (or half a request) must not pin
// resources for ever, and must not block other clients while slots are left
// (beyond MaxConns they are told the service is busy: limits_test.go).
func TestArea4_SilentAndSlowClientsDoNotBlockOthers(t *testing.T) {
	path := area4Sock(t)
	area4Serve(t, path, echo)
	var conns []net.Conn
	for i := 0; i < MaxConns-1; i++ {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			c.Write([]byte(`{"cmd":"sta`))
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	start := time.Now()
	if err := Call(path, Request{Cmd: "hello"}, nil, 2*time.Second); err != nil || time.Since(start) > time.Second {
		t.Errorf("blocked by idle clients: %v after %v", err, time.Since(start))
	}
	// the 5s read deadline eventually drops idle connections
	conns[0].SetReadDeadline(time.Now().Add(7 * time.Second))
	if _, err := conns[0].Read(make([]byte, 1)); err == nil {
		t.Error("expected the server to close the half-sent request")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Errorf("server kept a half-sent request open for >7s")
	}
}

func TestArea4_ConcurrentCallsAndTrailingBytes(t *testing.T) {
	path := area4Sock(t)
	var served atomic.Int64
	area4Serve(t, path, func(_ context.Context, r Request) (any, error) {
		served.Add(1)
		time.Sleep(5 * time.Millisecond)
		return map[string]string{"cmd": r.Cmd}, nil
	})
	var wg sync.WaitGroup
	var bad atomic.Int64
	for i := 0; i < 60; i++ { // stays below the listen backlog (somaxconn=128 on macOS)
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := fmt.Sprintf("c%d", i)
			var out map[string]string
			if err := Call(path, Request{Cmd: cmd}, &out, 5*time.Second); err != nil || out["cmd"] != cmd {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 || served.Load() != 60 {
		t.Errorf("bad=%d served=%d", bad.Load(), served.Load())
	}
	// two requests on one connection: only the first is answered, connection closes
	c, _ := net.Dial("unix", path)
	defer c.Close()
	c.Write([]byte(`{"cmd":"a"}` + "\n" + `{"cmd":"b"}` + "\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	dec := json.NewDecoder(bufio.NewReader(c))
	var r1, r2 Response
	if err := dec.Decode(&r1); err != nil || !r1.OK {
		t.Fatalf("first: %v %+v", err, r1)
	}
	if err := dec.Decode(&r2); err == nil {
		t.Errorf("a second response arrived on a one-shot connection")
	}
}

func TestArea4_RequestFieldsRoundTrip(t *testing.T) {
	path := area4Sock(t)
	area4Serve(t, path, func(_ context.Context, r Request) (any, error) { return r, nil })
	in := Request{Cmd: "c", Domain: "bücher.de", Engine: "e", Host: "h\"\n\\", All: true, N: -7, Lang: "tr"}
	var out Request
	if err := Call(path, in, &out, time.Second); err != nil || out != in {
		t.Errorf("round trip: %v %+v", err, out)
	}
	// a request that does not name a language asks in the caller's
	in.Lang = ""
	if err := Call(path, in, &out, time.Second); err != nil || out.Lang != i18n.Lang() {
		t.Errorf("language: %v %q, want %q", err, out.Lang, i18n.Lang())
	}
	// unknown fields from a newer client are tolerated
	c, _ := net.Dial("unix", path)
	defer c.Close()
	c.Write([]byte(`{"cmd":"x","future":1}` + "\n"))
	var resp Response
	c.SetReadDeadline(time.Now().Add(time.Second))
	if err := json.NewDecoder(c).Decode(&resp); err != nil || !resp.OK {
		t.Errorf("unknown field: %v %+v", err, resp)
	}
}
