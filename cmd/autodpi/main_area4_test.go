//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/daemon"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/store"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func area4Bin(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("/tmp", "mdpi4bin")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "autodpi")
		out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("%v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

type area4Env struct {
	home string
	mu   sync.Mutex
	reqs []ipc.Request
}

// newArea4Env starts a fake daemon on <home>/ctl.sock and returns a home for
// AUTODPI_HOME. home is short: AF_UNIX paths are limited to 104 bytes.
func newArea4Env(t *testing.T, h func(ipc.Request) (any, error)) *area4Env {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "mdpi4")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	e := &area4Env{home: home}
	if h != nil {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		sock := filepath.Join(home, "ctl.sock")
		go ipc.Serve(ctx, sock, func(_ context.Context, r ipc.Request) (any, error) {
			e.mu.Lock()
			e.reqs = append(e.reqs, r)
			e.mu.Unlock()
			return h(r)
		})
		for i := 0; i < 200; i++ {
			if _, err := os.Stat(sock); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return e
}

func (e *area4Env) last() ipc.Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.reqs) == 0 {
		return ipc.Request{}
	}
	return e.reqs[len(e.reqs)-1]
}

type res struct {
	out, err string
	code     int
}

func (e *area4Env) run(t *testing.T, args ...string) res {
	t.Helper()
	cmd := exec.Command(area4Bin(t), args...)
	cmd.Env = []string{"AUTODPI_HOME=" + e.home, "PATH=/usr/bin:/bin", "HOME=" + e.home, "TZ=UTC", "AUTODPI_LANG=tr"}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("%v hung", args)
	}
	return res{so.String(), se.String(), cmd.ProcessState.ExitCode()}
}

func okHandler(r ipc.Request) (any, error) { return map[string]any{}, nil }

func TestArea4_ExitCodesAndUsage(t *testing.T) {
	e := newArea4Env(t, nil)
	if r := e.run(t); r.code != 2 || !strings.Contains(r.err, "autodpi") || r.out != "" {
		t.Errorf("no args: %+v", r)
	}
	if r := e.run(t, "bogus"); r.code != 2 || !strings.Contains(r.err, `bilinmeyen komut "bogus"`) {
		t.Errorf("unknown: %+v", r)
	}
	for _, a := range []string{"help", "--help", "-h"} {
		if r := e.run(t, a); r.code != 0 || !strings.Contains(r.out, "install") {
			t.Errorf("%s: %+v", a, r)
		}
	}
	for _, a := range []string{"version", "--version", "-v"} {
		if r := e.run(t, a); r.code != 0 || !regexp.MustCompile(`^autodpi \S+ \(darwin/\w+, yardımcı programlar gömülü: (evet|hayır)\)\n$`).MatchString(r.out) {
			t.Errorf("%s: %+v", a, r)
		}
	}
	// every client command without a daemon: one clean line on stderr, exit 1, nothing on stdout
	for _, a := range [][]string{{"status"}, {"list"}, {"add", "a.com"}, {"remove", "a.com"}, {"test", "a.com"}, {"pause"}, {"resume"}, {"networks"}, {"log"}} {
		r := e.run(t, a...)
		if r.code != 1 || r.out != "" || !strings.HasPrefix(r.err, "hata: ") || strings.Count(r.err, "\n") != 1 {
			t.Errorf("%v with no daemon: %+v", a, r)
		}
		if !strings.Contains(r.err, "servis çalışmıyor") || strings.Contains(r.err, "not running") {
			t.Errorf("%v: message does not say, in Turkish only, that the service is not running: %q", a, r.err)
		}
	}
	// flag errors are exit 2 with the usage, in the language of the rest
	for _, a := range [][]string{{"list", "--bogus"}, {"log", "-n", "abc"}, {"daemon", "--for", "xyz"}, {"uninstall", "--nope"}} {
		if r := e.run(t, a...); r.code != 2 || !strings.HasPrefix(r.err, "hata: ") || !strings.Contains(r.err, "kullanım: autodpi "+a[0]) ||
			strings.Contains(r.err, "flag provided") || strings.Contains(r.err, "invalid value") {
			t.Errorf("%v: exit %d (%s)", a, r.code, r.err)
		}
	}
	if r := e.run(t, "log", "-h"); r.code != 0 || !strings.Contains(r.out, "kaç olay (varsayılan 50)") {
		t.Errorf("log -h: %+v", r)
	}
}

func TestArea4_UsageErrors(t *testing.T) {
	e := newArea4Env(t, okHandler)
	for _, a := range [][]string{{"add"}, {"add", "a", "b", "c"}, {"remove"}, {"remove", "a", "b"}, {"test"}, {"test", "--all"}} {
		r := e.run(t, a...)
		if r.code != 1 || !strings.Contains(r.err, "kullanım") {
			t.Errorf("%v: %+v", a, r)
		}
	}
	if n := len(e.reqs); n != 0 {
		t.Errorf("usage errors still reached the daemon (%d requests)", n)
	}
}

func TestArea4_StatusOutput(t *testing.T) {
	var st daemon.Status
	var stMu sync.Mutex
	set := func(v daemon.Status) { stMu.Lock(); st = v; stMu.Unlock() }
	e := newArea4Env(t, func(r ipc.Request) (any, error) { stMu.Lock(); defer stMu.Unlock(); return st, nil })
	set(daemon.Status{Version: "9.9", PID: 42, State: daemon.StateActive, Uptime: "1m0s", SingBoxPID: 77, Detail: "hi",
		Network: netid.Info{Key: "asn:1", Label: "AS1 Test"}, Entries: 5, Open: 2,
		Engines:  []string{"tlsrec", "ciadpi"},
		Observer: observer.Stats{Conns: 10, Direct: 6, Fallback: 2, Passthrough: 1}})
	r := e.run(t, "status")
	for _, want := range []string{"autodpi 9.9 · pid 42 · çalışma süresi 1m0s", "AKTİF — sing-box pid 77 — hi", "AS1 Test [asn:1]", "5 kayıt", "Açık:      2 alan adı", "tlsrec > ciadpi", "10 bağlantı: 6 direkt, 2 yedek motorla açıldı, 1 gözlenmeden geçti"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("status lacks %q:\n%s", want, r.out)
		}
	}
	// zero value / odd values must not crash or print garbage
	set(daemon.Status{State: "wat"})
	r = e.run(t, "status")
	if r.code != 0 || !strings.Contains(r.out, "(henüz belirlenmedi)") || !strings.Contains(r.out, "Durum:     wat") {
		t.Errorf("zero status: %+v", r)
	}
	for state, tr := range map[string]string{daemon.StateStandby: "BEKLEMEDE", daemon.StatePaused: "DURAKLATILDI", daemon.StateOffline: "ÇEVRİMDIŞI", daemon.StateError: "HATA", daemon.StateStarting: "BAŞLIYOR"} {
		set(daemon.Status{State: state})
		if r := e.run(t, "status"); !strings.Contains(r.out, tr) {
			t.Errorf("state %s not translated to %s: %s", state, tr, r.out)
		}
	}
}

// BUG (low): `test` prints engine results by ranging over a map, so the order of
// the "motor X:" lines changes from run to run (and does not follow the ladder).
func TestArea4_TestOutputIsDeterministic(t *testing.T) {
	e := newArea4Env(t, func(r ipc.Request) (any, error) {
		return daemon.TestResult{Host: "discord.com", Verdict: "blocked", Engine: "tlsrec",
			Direct:  []string{"rst 70ms", "rst 80ms"},
			Control: "ok 100ms",
			Order:   []string{"tlsrec", "ciadpi", "tlsspoof"},
			Engines: map[string]string{"tlsrec": "ok", "ciadpi": "ok", "tlsspoof": "skipped", "tlsfrag": "rst", "warp": "n/a"}}, nil
	})
	seen := map[string]bool{}
	var sample string
	for i := 0; i < 25; i++ {
		r := e.run(t, "test", "discord.com", "--all")
		if r.code != 0 {
			t.Fatalf("%+v", r)
		}
		seen[r.out] = true
		sample = r.out
	}
	if len(seen) > 1 {
		t.Errorf("%d different outputs for identical input (map iteration order); sample:\n%s", len(seen), sample)
	}
	if !strings.HasPrefix(sample, "discord.com → ENGELLİ (motor: tlsrec)\n  direkt #1:  rst 70ms\n  direkt #2:  rst 80ms\n  kontrol (nötr SNI): ok 100ms\n") {
		t.Errorf("test header wrong:\n%s", sample)
	}
	// ladder order first (as the daemon reports it), the rest by name
	var got []string
	for _, ln := range strings.Split(sample, "\n") {
		if f := strings.Fields(ln); len(f) > 1 && f[0] == "motor" {
			got = append(got, strings.TrimSuffix(f[1], ":"))
		}
	}
	if strings.Join(got, " ") != "tlsrec ciadpi tlsspoof tlsfrag warp" {
		t.Errorf("engine lines in order %v", got)
	}
}

func TestArea4_TestArgParsing(t *testing.T) {
	e := newArea4Env(t, func(r ipc.Request) (any, error) { return daemon.TestResult{Host: r.Host, Verdict: "clean"}, nil })
	for _, args := range [][]string{{"test", "a.com", "--all"}, {"test", "--all", "a.com"}, {"test", "-all", "a.com"}, {"test", "a.com", "-all=true"}} {
		if r := e.run(t, args...); r.code != 0 {
			t.Fatalf("%v: %+v", args, r)
		}
		if q := e.last(); q.Host != "a.com" || !q.All || q.Cmd != "test" {
			t.Errorf("%v: daemon got %+v", args, q)
		}
	}
	e.run(t, "test", "a.com")
	if q := e.last(); q.All {
		t.Errorf("All set without flag: %+v", q)
	}
	// a second host is refused, not silently dropped
	n := len(e.reqs)
	r := e.run(t, "test", "a.com", "b.com")
	if r.code == 0 || !strings.Contains(r.err, "b.com") || len(e.reqs) != n {
		t.Errorf("`test a.com b.com`: %+v (requests %d -> %d)", r, n, len(e.reqs))
	}
}

func TestArea4_ListAddRemoveOutput(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	e := newArea4Env(t, func(r ipc.Request) (any, error) {
		switch r.Cmd {
		case "list":
			return daemon.ListResult{Networks: []daemon.NetworkList{
				{Key: "asn:1", Label: "AS1", Current: true, Entries: []store.Entry{
					{Domain: "bücher.example", Engine: "ciadpi", Source: "auto", Added: now},
					{Domain: "a.com", Source: "manual", Added: now},
				}},
				{Key: "gw:x", Label: "", Entries: nil},
			}}, nil
		case "add":
			return map[string]any{"added": r.Domain != "dup.com", "domain": r.Domain}, nil
		}
		return map[string]any{}, nil
	})
	r := e.run(t, "list", "--all")
	if r.code != 0 || !e.last().All {
		t.Fatalf("%+v", r)
	}
	for _, want := range []string{"Ağ: AS1 [asn:1] (şu anki)", "ALAN ADI", "bücher.example  ciadpi       otomatik  2026-10-29 12:00", "a.com           (ilk motor)  elle      2026-10-29 12:00"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("list lacks %q:\n%s", want, r.out)
		}
	}
	// a network with no entries prints a header, not a crash or a blank
	if !strings.Contains(r.out, "Ağ:  [gw:x]") {
		t.Logf("empty-label network is printed as %q", regexp.MustCompile(`Ağ: .*\[gw:x\]`).FindString(r.out))
	}
	if r := e.run(t, "add", "dup.com"); !strings.Contains(r.out, "zaten kapsanıyor: dup.com") {
		t.Errorf("%+v", r)
	}
	if r := e.run(t, "add", "x.com", "tlsrec"); !strings.Contains(r.out, "eklendi: x.com") || e.last().Engine != "tlsrec" {
		t.Errorf("%+v %+v", r, e.last())
	}
	if r := e.run(t, "add", "x.com"); e.last().Engine != "" || r.code != 0 {
		t.Errorf("%+v", e.last())
	}
	if r := e.run(t, "remove", "x.com"); r.out != "çıkarıldı: x.com\n" {
		t.Errorf("%+v", r)
	}
	for cmd, want := range map[string]string{"pause": "duraklatıldı\n", "resume": "sürdürüldü\n"} {
		if r := e.run(t, cmd); r.out != want || e.last().Cmd != cmd {
			t.Errorf("%s: %+v", cmd, r)
		}
	}
}

func TestArea4_EmptyListsDoNotCrash(t *testing.T) {
	e := newArea4Env(t, func(r ipc.Request) (any, error) {
		switch r.Cmd {
		case "networks", "log":
			return nil, nil // handler returns nothing at all
		case "list":
			return nil, nil
		case "status":
			return nil, nil
		}
		return map[string]any{}, nil
	})
	for _, a := range [][]string{{"networks"}, {"log"}, {"log", "-n", "5"}, {"list"}, {"status"}} {
		r := e.run(t, a...)
		if r.code != 0 || strings.Contains(r.err, "panic") {
			t.Errorf("%v: %+v", a, r)
		}
	}
	if r := e.run(t, "list"); r.out != "(liste yok)\n" {
		t.Errorf("empty list: %q", r.out)
	}
	if r := e.run(t, "log", "-n", "7"); e.last().N != 7 {
		t.Errorf("log -n not forwarded: %+v %+v", r, e.last())
	}
}

// The persistent clean list and its CLI are gone: `clean` is an unknown command.
func TestCleanCommandIsGone(t *testing.T) {
	e := newArea4Env(t, okHandler)
	r := e.run(t, "clean", "list")
	if r.code != 2 || !strings.Contains(r.err, "bilinmeyen komut") {
		t.Errorf("%+v", r)
	}
	if r := e.run(t, "help"); strings.Contains(r.out, "clean") {
		t.Errorf("usage still mentions clean:\n%s", r.out)
	}
}

func TestArea4_DaemonErrorsSurfaceAsHata(t *testing.T) {
	e := newArea4Env(t, func(r ipc.Request) (any, error) { return nil, fmt.Errorf("invalid domain %q", r.Domain) })
	r := e.run(t, "add", "bad domain")
	if r.code != 1 || r.err != "hata: invalid domain \"bad domain\"\n" || r.out != "" {
		t.Errorf("%+v", r)
	}
}

// install/uninstall as a normal user must fail cleanly and touch nothing.
func TestArea4_InstallUninstallNeedRootAndTouchNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("must not run as root")
	}
	e := newArea4Env(t, nil)
	sentinel := filepath.Join(e.home, "state.json")
	os.WriteFile(sentinel, []byte("keep"), 0o600)
	os.MkdirAll(filepath.Join(e.home, "bin"), 0o755)
	os.WriteFile(filepath.Join(e.home, "bin", "sing-box"), []byte("x"), 0o755)
	for _, a := range [][]string{{"uninstall"}, {"uninstall", "--purge"}, {"install"}} {
		r := e.run(t, a...)
		if r.code != 1 || !strings.HasPrefix(r.err, "hata: ") {
			t.Errorf("%v: %+v", a, r)
		}
		if a[0] == "uninstall" && !strings.Contains(r.err, "root") {
			t.Errorf("%v: message should say root is needed: %q", a, r.err)
		}
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" {
		t.Errorf("--purge as non-root touched the support dir: %v %q", err, b)
	}
	if _, err := os.Stat(filepath.Join(e.home, "bin", "sing-box")); err != nil {
		t.Errorf("uninstall as non-root removed helper binaries: %v", err)
	}
}

// daemon without root and without --no-tun/--test-port must refuse before doing anything.
func TestArea4_DaemonRefusesWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("must not run as root")
	}
	e := newArea4Env(t, nil)
	r := e.run(t, "daemon")
	if r.code != 1 || !strings.Contains(r.err, "root") {
		t.Errorf("%+v", r)
	}
	if ents, _ := os.ReadDir(e.home); len(ents) != 0 {
		t.Errorf("refused daemon still created files: %v", ents)
	}
}

func TestArea4_DoctorRunsReadOnly(t *testing.T) {
	e := newArea4Env(t, nil)
	r := e.run(t, "doctor")
	if r.code != 0 && r.code != 1 {
		t.Fatalf("doctor exit %d: %s %s", r.code, r.out, r.err)
	}
	if strings.Contains(r.err, "panic") || !strings.Contains(r.out, "root yetkisi") || !strings.Contains(r.out, "kontrol soketi") {
		t.Errorf("doctor output:\n%s\n%s", r.out, r.err)
	}
	for _, ln := range strings.Split(strings.TrimRight(r.out, "\n"), "\n") {
		if !(strings.HasPrefix(ln, "✓ ") || strings.HasPrefix(ln, "✗ ") || strings.HasPrefix(ln, "· ")) {
			t.Errorf("unexpected doctor line %q", ln)
		}
	}
}

// `autodpi ui --no-open`: loopback only, token required, clean exit on SIGTERM/SIGINT.
func TestArea4_UICommandEndToEnd(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		e := newArea4Env(t, func(r ipc.Request) (any, error) { return map[string]any{"state": "active"}, nil })
		cmd := exec.Command(area4Bin(t), "ui", "--no-open")
		cmd.Env = []string{"AUTODPI_HOME=" + e.home, "PATH=/usr/bin:/bin", "HOME=" + e.home}
		stdout, _ := cmd.StdoutPipe()
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		defer cmd.Process.Kill()
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`http://127\.0\.0\.1:(\d+)/\?t=([0-9a-f]{32})`).FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("no URL in %q", line)
		}
		base, tok := "http://127.0.0.1:"+m[1], m[2]
		get := func(path, tk string) int {
			req, _ := http.NewRequest("GET", base+path, nil)
			if tk != "" {
				req.Header.Set("X-Token", tk)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			return resp.StatusCode
		}
		if c := get("/", ""); c != 403 {
			t.Errorf("no token: %d", c)
		}
		if c := get("/", tok); c != 200 {
			t.Errorf("token: %d", c)
		}
		if c := get("/api/status", tok); c != 200 {
			t.Errorf("api via real ipc socket: %d", c)
		}
		// listener is loopback only
		out, _ := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-p", fmt.Sprint(cmd.Process.Pid), "-iTCP", "-sTCP:LISTEN").Output()
		if !strings.Contains(string(out), "127.0.0.1:"+m[1]) || strings.Contains(string(out), "*:"+m[1]) {
			t.Errorf("listener not loopback-only:\n%s", out)
		}
		cmd.Process.Signal(sig)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%v: ui exited with %v after signal", sig, err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%v: ui did not exit", sig)
		}
		if _, err := http.Get(base + "/"); err == nil {
			t.Errorf("port still serving after exit")
		}
	}
}

// Two `ui` runs must never share a token or port by accident.
func TestArea4_UITokensDiffer(t *testing.T) {
	var toks []string
	for i := 0; i < 2; i++ {
		e := newArea4Env(t, nil)
		cmd := exec.Command(area4Bin(t), "ui", "--no-open")
		cmd.Env = []string{"AUTODPI_HOME=" + e.home, "PATH=/usr/bin:/bin"}
		stdout, _ := cmd.StdoutPipe()
		cmd.Start()
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		cmd.Process.Kill()
		cmd.Wait()
		toks = append(toks, line)
	}
	if toks[0] == toks[1] || toks[0] == "" {
		t.Errorf("urls repeat: %q", toks)
	}
}

var _ = json.Marshal

// `test` prints the engines in the ladder order the daemon reports.
func TestArea4_TestOutputFollowsTheLadder(t *testing.T) {
	e := newArea4Env(t, func(r ipc.Request) (any, error) {
		return daemon.TestResult{Host: "x.com", Verdict: "blocked", Engine: "tlsrec",
			Engines: map[string]string{"tlsrec": "ok", "ciadpi": "ok", "tlsspoof": "rst", "zzz": "?"},
			Order:   []string{"tlsrec", "ciadpi", "tlsspoof"}}, nil
	})
	r := e.run(t, "test", "x.com", "--all")
	i, j, k, l := strings.Index(r.out, "motor tlsrec:"), strings.Index(r.out, "motor ciadpi:"), strings.Index(r.out, "motor tlsspoof:"), strings.Index(r.out, "motor zzz:")
	if !(i >= 0 && i < j && j < k && k < l) {
		t.Errorf("engine lines not in ladder order:\n%s", r.out)
	}
}
