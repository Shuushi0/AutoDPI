package singbox_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fakenet"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
	"github.com/Shuushi0/AutoDPI/internal/socks"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// Real sing-box, loopback only: no TUN, no root. It proves how sing-box hands
// flows to the observer, how domain_suffix matches, and that rewriting the
// rule-set file reroutes new connections without a restart.
func TestSingBoxRoutingAndHotReload(t *testing.T) {
	name := "sing-box"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(os.Getenv("AUTODPI_BINDIR"), name)
	if _, err := os.Stat(bin); err != nil {
		bin, _ = filepath.Abs(filepath.Join("..", "..", "bin", name))
		if _, err := os.Stat(bin); err != nil {
			t.Skip("sing-box binary not available")
		}
	}

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hi") }))
	defer origin.Close()
	censor, err := fakenet.NewCensor(origin.Listener.Addr().String(), fakenet.Reset, func(n string) bool {
		return n == "blocked.test" || n == "sub.blocked.test"
	})
	if err != nil {
		t.Fatal(err)
	}
	defer censor.Close()
	engine, err := fakenet.NewSplitEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	_, censorPortStr, _ := net.SplitHostPort(censor.Addr())
	censorPort, _ := net.LookupPort("tcp", censorPortStr)
	_, enginePortStr, _ := net.SplitHostPort(engine.Addr())
	enginePort, _ := net.LookupPort("tcp", enginePortStr)

	// Clients ask for a public-looking address (sing-box keeps private ones
	// direct); the observer's dialer and the engine map it to the censor.
	const fake = "203.0.113.7"
	fakeAddr := fmt.Sprintf("%s:%d", fake, censorPort)
	engine.Rewrite = map[string]string{fakeAddr: censor.Addr()}

	// Observer with the same engine as its retry path.
	events := make(chan observer.Event, 32)
	obs := observer.New(observer.Options{
		Engines: func() []observer.Engine { return []observer.Engine{{Name: "ciadpi", Addr: engine.Addr()}} },
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == fakeAddr {
				addr = censor.Addr()
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		Events:         func(e observer.Event) { events <- e },
		Ports:          []int{censorPort},
		ConnectTimeout: time.Second, FirstByte: time.Second, Hedge: 200 * time.Millisecond,
		AllowLoopback: true,
	})
	oln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go obs.Serve(oln)
	defer obs.Close()
	obsPort := oln.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	engines := []singbox.Engine{{Name: "ciadpi", Kind: singbox.Socks, Port: enginePort}}
	if err := singbox.WriteRuleSet(dir, "ciadpi", nil); err != nil {
		t.Fatal(err)
	}
	testPort := freePort(t)
	cfg, err := singbox.Build(singbox.Options{
		Engines: engines, ObserverPort: obsPort, ObservePorts: []int{censorPort},
		RuleDir: dir, TestPort: testPort, LogLevel: "debug",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Logf("sing-box log tail:\n%s", tail(logs.String(), 2500))
	}()
	waitListening(t, fmt.Sprintf("127.0.0.1:%d", testPort))

	get := func(sni string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		c, err := socks.Dial(ctx, nil, fmt.Sprintf("127.0.0.1:%d", testPort), fake, censorPort)
		if err != nil {
			return "", err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err := tc.Handshake(); err != nil {
			return "", err
		}
		io.WriteString(tc, "GET / HTTP/1.0\r\n\r\n")
		b, _ := io.ReadAll(tc)
		return string(b), nil
	}
	nextEvent := func() observer.Event {
		select {
		case e := <-events:
			return e
		case <-time.After(3 * time.Second):
			t.Fatal("observer saw nothing")
			return observer.Event{}
		}
	}

	// 1. Unlisted + blocked: reaches the observer, which repairs it.
	if _, err := get("blocked.test"); err != nil {
		t.Fatalf("unlisted blocked flow should be repaired by the observer: %v", err)
	}
	e := nextEvent()
	t.Logf("observer saw: asked=%q dest=%s sni=%q outcome=%s engine=%s", e.Asked, e.Dest, e.SNI, e.Outcome, e.Engine)
	if e.Outcome != observer.Fallback || e.SNI != "blocked.test" {
		t.Fatalf("event = %+v", e)
	}

	// 2. List the domain. The same flow must now bypass the observer entirely.
	before := drain(engine.Hits)
	if err := singbox.WriteRuleSet(dir, "ciadpi", []string{"blocked.test"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // let the file watcher fire
	for _, sni := range []string{"blocked.test", "sub.blocked.test"} {
		if _, err := get(sni); err != nil {
			t.Fatalf("listed %s should open: %v", sni, err)
		}
	}
	select {
	case e := <-events:
		t.Fatalf("listed domains must skip the observer, but it saw %+v (hot reload or suffix match failed)", e)
	case <-time.After(300 * time.Millisecond):
	}
	if got := drain(engine.Hits); got < 2 {
		t.Fatalf("engine should have carried both listed flows, hits=%d (before=%d)", got, before)
	}
	// domain_suffix must match on a label boundary: notblocked.test is not
	// listed and stays with the observer (which finds the real path fine).
	if _, err := get("notblocked.test"); err != nil {
		t.Fatalf("unlisted notblocked.test: %v", err)
	}
	if e := nextEvent(); e.SNI != "notblocked.test" || e.Outcome != observer.Direct {
		t.Fatalf("notblocked.test should reach the observer and go direct, got %+v", e)
	}
	if got := drain(engine.Hits); got != 0 {
		t.Fatalf("an unlisted look-alike name was sent to the engine (%d hits)", got)
	}

	// 3. Delist: back to the observer.
	if err := singbox.WriteRuleSet(dir, "ciadpi", nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := get("blocked.test"); err != nil {
		t.Fatal(err)
	}
	if e := nextEvent(); e.Outcome != observer.Fallback {
		t.Fatalf("after delisting the observer should see it again, got %+v", e)
	}
}

func drain(ch chan string) int {
	n := 0
	for {
		select {
		case <-ch:
			n++
		default:
			return n
		}
	}
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s never started listening", addr)
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
