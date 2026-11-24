package singbox_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer that sing-box's output can be written into
// while the test reads it; a plain one is a data race under -race.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// boxProc is one running sing-box.
type boxProc struct {
	cmd    *exec.Cmd
	logs   *syncBuffer
	exited chan struct{}
}

// startBox writes cfg into dir and runs sing-box on it until the test ends.
// ready reports when the process is up (a port answers, a log line appears).
// It returns an error, not a failure, when sing-box exits before that: the
// usual cause is a port that freePort handed out and another process took in
// between, which the caller retries with fresh ports. Four other test runs
// share this machine, so that does happen.
func startBox(t *testing.T, bin, dir, name string, cfg []byte, ready func(p *boxProc) bool) (*boxProc, error) {
	t.Helper()
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	p := &boxProc{logs: &syncBuffer{}, exited: make(chan struct{})}
	p.cmd = exec.Command(bin, "run", "-c", path)
	p.cmd.Stdout, p.cmd.Stderr = p.logs, p.logs
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.cmd.Wait(); close(p.exited) }()
	deadline := time.Now().Add(10 * time.Second)
	for !ready(p) {
		select {
		case <-p.exited:
			return nil, fmt.Errorf("%s exited before it was ready:\n%s", name, tail(p.logs.String(), 2000))
		default:
		}
		if time.Now().After(deadline) {
			p.stop()
			return nil, fmt.Errorf("%s not ready after 10 s:\n%s", name, tail(p.logs.String(), 2000))
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() {
		if !p.stop() {
			t.Errorf("%s did not stop on SIGTERM within 5 s and was killed", name)
		}
		if t.Failed() {
			t.Logf("%s log tail:\n%s", name, tail(p.logs.String(), 3000))
		}
	})
	return p, nil
}

// stop asks sing-box to shut down the way the daemon does and kills it if it
// does not; it reports whether the shutdown was clean.
func (p *boxProc) stop() bool {
	select {
	case <-p.exited:
		return true
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.exited:
		return true
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
		return false
	}
}

// answers is a ready check: the TCP port accepts a connection.
func answers(port int) func(*boxProc) bool {
	return func(*boxProc) bool {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
		}
		return err == nil
	}
}

// startRetrying runs startBox with a configuration made afresh (new free
// ports) up to three times.
func startRetrying(t *testing.T, bin, dir, name string, build func() ([]byte, func(*boxProc) bool)) *boxProc {
	t.Helper()
	var errs []error
	for i := 0; i < 3; i++ {
		cfg, ready := build()
		p, err := startBox(t, bin, dir, name, cfg, ready)
		if err == nil {
			return p
		}
		errs = append(errs, err)
	}
	t.Fatalf("sing-box (%s) would not start: %v", name, errors.Join(errs...))
	return nil
}

// dropRule removes from the generated route rules the one rule equal to want
// and fails when there is not exactly one: if Build stops emitting it, the
// test must be looked at again rather than quietly test something else.
func dropRule(t *testing.T, cfg map[string]any, want map[string]any) {
	t.Helper()
	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	// Compare as decoded JSON, the form the rules are in.
	var w any
	b, _ := json.Marshal(want)
	_ = json.Unmarshal(b, &w)
	var kept []any
	found := 0
	for _, r := range rules {
		if reflect.DeepEqual(r, w) {
			found++
			continue
		}
		kept = append(kept, r)
	}
	if found != 1 {
		t.Fatalf("Build's rules hold %d copies of %s, want 1; this test's adjustment needs another look", found, b)
	}
	route["rules"] = kept
}

// lanIPv4 is an IPv4 address of this machine that is not loopback and not on
// a point-to-point interface (a VPN's, or the installed AutoDPI's own TUN).
func lanIPv4() (net.IP, bool) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, false
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 ||
			strings.HasPrefix(ifc.Name, "utun") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				return n.IP.To4(), true
			}
		}
	}
	return nil, false
}
