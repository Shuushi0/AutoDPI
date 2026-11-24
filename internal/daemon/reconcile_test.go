//go:build !windows

// The reconcile scenarios fake macOS networksetup through sysdns.Manager.Run,
// which the Windows Manager does not have.

package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
	"github.com/Shuushi0/AutoDPI/internal/store"
	"github.com/Shuushi0/AutoDPI/internal/supervise"
	"github.com/Shuushi0/AutoDPI/internal/sysdns"
	"github.com/Shuushi0/AutoDPI/internal/verdict"
)

const serviceOrder = `An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) USB LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)
`

// fakeSys stands in for the machine: routes, tunnels, health probes and
// networksetup. Every knob is guarded so the engage loop may run in its own
// goroutine.
type fakeSys struct {
	mu        sync.Mutex
	net       netid.Info
	iface     string // default route
	v6        bool
	foreign   string
	tool      string // a conflicting DPI tool that is running
	tun       bool
	healthErr error
	capErr    error
	starts    int
	running   int
	dns       map[string][]string // networksetup state per service
	dnsCalls  int
	setErr    error
	checks    []string // hosts handed to check
	checkFn   func(key, host string) verdict.Verdict
}

func (f *fakeSys) set(fn func(f *fakeSys)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeSys) get() fakeSys {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeSys{net: f.net, iface: f.iface, starts: f.starts, running: f.running, dnsCalls: f.dnsCalls,
		dns: map[string][]string{"Wi-Fi": f.dns["Wi-Fi"], "USB LAN": f.dns["USB LAN"]}, checks: slices.Clone(f.checks)}
}

func (f *fakeSys) networksetup(args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsCalls++
	switch args[0] {
	case "-listnetworkserviceorder":
		return serviceOrder, nil
	case "-getdnsservers":
		if l := f.dns[args[1]]; len(l) > 0 {
			return strings.Join(l, "\n") + "\n", nil
		}
		return "There aren't any DNS Servers set on " + args[1] + ".\n", nil
	case "-setdnsservers":
		if f.setErr != nil {
			return "", f.setErr
		}
		if args[2] == "Empty" {
			delete(f.dns, args[1])
		} else {
			f.dns[args[1]] = append([]string(nil), args[2:]...)
		}
		return "", nil
	}
	panic(args[0])
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// rig builds a daemon whose every contact with the system goes to f. Nothing
// real is started: sing-box is a goroutine that reports a pid and waits.
func rig(t *testing.T, opt Options) (*Daemon, *fakeSys) {
	t.Helper()
	dir := t.TempDir()
	p := paths.Set{Support: dir, Run: filepath.Join(dir, "run"), State: filepath.Join(dir, "state.json"), DNSSaved: filepath.Join(dir, "dns-saved.json")}
	if err := os.MkdirAll(p.Run, 0o755); err != nil {
		t.Fatal(err)
	}
	d := New(config.Default(), p, "", quietLog())
	d.opt = opt
	d.kick = make(chan struct{}, 1)
	var err error
	if d.st, err = store.Open(p.State); err != nil {
		t.Fatal(err)
	}
	d.engines = []singbox.Engine{{Name: "tlsrec", Kind: singbox.TLSRecord, Port: 1081}, {Name: "ciadpi", Kind: singbox.Socks, Port: 1082}}
	d.obsPort = 1080

	f := &fakeSys{
		net:   netid.Info{Key: "asn:15897", Label: "AS15897", Online: true},
		iface: "en0", tun: true,
		dns: map[string][]string{"Wi-Fi": {"192.168.1.1"}},
	}
	if opt.TestPort == 0 && !opt.NoTun {
		d.dns = &sysdns.Manager{File: p.DNSSaved, Log: quietLog(), Run: f.networksetup, Flush: func() {}}
	}
	d.sys = system{
		network: func() netid.Info { f.mu.Lock(); defer f.mu.Unlock(); return f.net },
		route: func() (string, string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.iface == "" {
				return "", "", errors.New("no default route")
			}
			return f.iface, "192.168.1.1", nil
		},
		hasIPv6:       func(string) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.v6 },
		foreignTunnel: func() (string, bool) { f.mu.Lock(); defer f.mu.Unlock(); return f.foreign, f.foreign != "" },
		conflict:      func() (string, bool) { f.mu.Lock(); defer f.mu.Unlock(); return f.tool, f.tool != "" },
		tunUp:         func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.tun },
		healthy:       func(context.Context) error { f.mu.Lock(); defer f.mu.Unlock(); return f.healthErr },
		captureHealthy: func(context.Context) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.capErr
		},
		keep: func(ctx context.Context, _ supervise.Spec, onUp func(int)) {
			f.set(func(f *fakeSys) { f.starts++; f.running++ })
			onUp(4242)
			<-ctx.Done()
			f.set(func(f *fakeSys) { f.running-- })
		},
		check: func(_ context.Context, key, host string, _ []netip.Addr, _ bool) verdict.Verdict {
			f.mu.Lock()
			f.checks = append(f.checks, host)
			fn := f.checkFn
			f.mu.Unlock()
			if fn == nil {
				return verdict.Verdict{Kind: verdict.Unknown}
			}
			return fn(key, host)
		},
	}
	d.useNetwork("asn:15897")
	t.Cleanup(d.stopSingBox)
	return d, f
}

// pass runs one reconcile pass as the engage loop would, with the health-check
// rate limit lifted so every pass probes.
func pass(t *testing.T, d *Daemon) {
	t.Helper()
	d.lastHealth = time.Time{}
	d.reconcile(context.Background())
	if d.running() { // the fake sing-box reports its pid from its own goroutine
		for i := 0; i < 200; i++ {
			d.mu.Lock()
			pid := d.sbPID
			d.mu.Unlock()
			if pid != 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("fake sing-box never reported a pid")
	}
}

func state(d *Daemon) (string, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state, d.detail
}

func wantState(t *testing.T, d *Daemon, want string, detail ...string) {
	t.Helper()
	s, det := state(d)
	if s != want {
		t.Fatalf("state %q (%s), want %q", s, det, want)
	}
	for _, sub := range detail {
		if !strings.Contains(det, sub) {
			t.Fatalf("state detail %q does not mention %q", det, sub)
		}
	}
}

// engage brings the rig to an active capture holding the resolver.
func engage(t *testing.T, d *Daemon, f *fakeSys) {
	t.Helper()
	pass(t, d) // health ok -> start
	wantState(t, d, StateStarting, "capture starting")
	pass(t, d) // capture up, verified -> DNS taken
	wantState(t, d, StateActive)
	if d.dns != nil && !slices.Equal(f.get().dns["Wi-Fi"], []string{sysdns.Capture}) {
		t.Fatalf("resolver not captured: %v", f.get().dns)
	}
}

func TestEngageVerifiesBeforeTakingDNS(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.capErr = errors.New("TLS through the capture: reset") })
	pass(t, d)
	wantState(t, d, StateStarting, "capture starting")
	if !d.running() || f.get().starts != 1 {
		t.Fatal("capture not started")
	}
	pass(t, d)
	wantState(t, d, StateStarting, "verifying")
	if d.dns.Holding() || !slices.Equal(f.get().dns["Wi-Fi"], []string{"192.168.1.1"}) {
		t.Fatal("resolver taken before the capture was verified")
	}
	f.set(func(f *fakeSys) { f.capErr = nil })
	pass(t, d)
	wantState(t, d, StateActive)
	if !d.dns.Holding() || !slices.Equal(f.get().dns["Wi-Fi"], []string{sysdns.Capture}) {
		t.Fatalf("resolver not taken after verification: %v", f.get().dns)
	}
}

func TestHealthFailureKeepsHandsOff(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.healthErr = errors.New("DoH: timeout") })
	for i := 0; i < 3; i++ {
		pass(t, d)
	}
	wantState(t, d, StateStandby, "health check failed", "DoH")
	if d.running() || f.get().starts != 0 || f.get().dnsCalls != 0 {
		t.Fatalf("touched the system with failing plumbing: %+v", f.get())
	}
}

func TestOfflineAndPaused(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.net.Online = false })
	pass(t, d)
	wantState(t, d, StateOffline)
	f.set(func(f *fakeSys) { f.net.Online = true })
	engage(t, d, f)

	if err := d.st.SetPaused(true); err != nil {
		t.Fatal(err)
	}
	pass(t, d)
	wantState(t, d, StatePaused)
	if d.running() || d.dns.Holding() || !slices.Equal(f.get().dns["Wi-Fi"], []string{"192.168.1.1"}) {
		t.Fatalf("pause left the capture or the resolver behind: running=%v dns=%v", d.running(), f.get().dns)
	}
	pass(t, d)
	if f.get().starts != 1 {
		t.Fatal("restarted while paused")
	}
	_ = d.st.SetPaused(false)
	pass(t, d)
	if !d.running() || f.get().starts != 2 {
		t.Fatal("resume did not re-engage")
	}
}

func TestCaptureNeverUpBacksOff(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.tun = false })
	pass(t, d)
	pass(t, d)
	wantState(t, d, StateStarting, "not up yet")

	for i, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute} {
		d.sbStarted = time.Now().Add(-31 * time.Second)
		t0 := time.Now()
		pass(t, d)
		wantState(t, d, StateError, "30s", "retry in")
		if d.running() {
			t.Fatal("capture kept after failing to come up")
		}
		if got := d.retryAt.Sub(t0).Round(time.Second); got != want {
			t.Fatalf("release %d: retry in %v, want %v", i+1, got, want)
		}
		pass(t, d)
		wantState(t, d, StateError, "30s", "next attempt in") // still an error while it waits
		if n := f.get().starts; n != i+1 {
			t.Fatalf("started %d times inside the backoff window, want %d", n, i+1)
		}
		d.retryAt = time.Now().Add(-time.Second)
		pass(t, d)
		if !d.running() || f.get().starts != i+2 {
			t.Fatal("no new attempt after the backoff expired")
		}
	}
}

// A resolver stalling briefly used to release the capture after three checks
// (~30s) and drop users' connections. Failures must persist before fail-open.
func TestBriefFailureDoesNotFailOpen(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.capErr = errors.New("DNS through the capture: timeout") })
	for i := 0; i < 6; i++ { // six failed checks, but all inside the persistence window
		pass(t, d)
	}
	wantState(t, d, StateActive)
	if !d.running() || !d.dns.Holding() || d.badChecks != 6 {
		t.Fatalf("capture released after a brief failure: running=%v holding=%v bad=%d", d.running(), d.dns.Holding(), d.badChecks)
	}
	// Recovery forgets the run of failures entirely.
	f.set(func(f *fakeSys) { f.capErr = nil })
	pass(t, d)
	if d.badChecks != 0 || !d.badSince.IsZero() {
		t.Fatalf("recovery kept failure state: bad=%d since=%v", d.badChecks, d.badSince)
	}
	// ...so a new failure run starts its window from zero.
	f.set(func(f *fakeSys) { f.capErr = errors.New("again") })
	for i := 0; i < 4; i++ {
		pass(t, d)
	}
	wantState(t, d, StateActive)
}

func TestPersistentFailureFailsOpen(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.capErr = errors.New("DNS through the capture: timeout") })
	pass(t, d)
	if d.badSince.IsZero() {
		t.Fatal("failure start not recorded")
	}
	d.badSince = time.Now().Add(-failOpenAfter - time.Second) // the outage has lasted long enough
	pass(t, d)
	wantState(t, d, StateActive) // but only two checks have failed: still tolerated
	if !d.dns.Holding() {
		t.Fatal("resolver released before the third failed check")
	}
	pass(t, d)
	wantState(t, d, StateStandby, "fail-open", "retry in 30s")
	if d.running() || d.dns.Holding() || !slices.Equal(f.get().dns["Wi-Fi"], []string{"192.168.1.1"}) {
		t.Fatalf("fail-open left state behind: running=%v dns=%v", d.running(), f.get().dns)
	}
	if d.badChecks != 0 || !d.badSince.IsZero() {
		t.Fatal("failure state survived the release")
	}
}

func TestFailuresBeforeVerificationAlsoNeedToPersist(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.capErr = errors.New("TLS through the capture: reset") })
	pass(t, d) // starts the capture
	for i := 0; i < 4; i++ {
		pass(t, d)
	}
	if !d.running() {
		t.Fatal("capture released during the first seconds of failing verification")
	}
	d.badSince = time.Now().Add(-failOpenAfter - time.Second)
	pass(t, d)
	if d.running() {
		t.Fatal("capture kept although verification kept failing for over a minute")
	}
}

func TestHealthRateLimit(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.capErr = errors.New("down") })
	for i := 0; i < 5; i++ { // the engine loop's 3s ticks, without lifting the 15s limit
		d.reconcile(context.Background())
	}
	if d.badChecks != 0 || !d.running() {
		t.Fatalf("health probed more often than every 15s (badChecks=%d)", d.badChecks)
	}
}

func TestStableRunForgetsFailures(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	d.failOpens = 4
	pass(t, d)
	if d.failOpens != 4 {
		t.Fatal("failures forgotten too early")
	}
	d.activeAt = time.Now().Add(-11 * time.Minute)
	pass(t, d)
	if d.failOpens != 0 {
		t.Fatalf("failOpens=%d after 10 stable minutes", d.failOpens)
	}
}

func TestForeignTunnelTakesPrecedence(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.foreign = "utun7" })
	pass(t, d)
	wantState(t, d, StateStandby, "utun7", "engages once it is gone")
	if f.get().starts != 0 {
		t.Fatal("engaged next to another tunnel")
	}
	f.set(func(f *fakeSys) { f.foreign = "" })
	engage(t, d, f)

	f.set(func(f *fakeSys) { f.foreign = "utun9" })
	pass(t, d)
	wantState(t, d, StateStandby, "utun9", "released")
	if d.running() || d.dns.Holding() || !slices.Equal(f.get().dns["Wi-Fi"], []string{"192.168.1.1"}) {
		t.Fatalf("capture or resolver kept next to a VPN: %v", f.get().dns)
	}
	if !d.retryAt.IsZero() {
		t.Fatal("a VPN is not a failure: no backoff expected")
	}
	f.set(func(f *fakeSys) { f.foreign = "" })
	pass(t, d)
	if !d.running() || f.get().starts != 2 {
		t.Fatal("did not re-engage once the VPN left")
	}
}

func TestIPv6ChangeRebuildsCapture(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	cfg, _ := os.ReadFile(filepath.Join(d.p.Run, "config.json"))
	if strings.Contains(string(cfg), "fdfe:") {
		t.Fatal("IPv6 TUN address on an IPv4-only network")
	}
	f.set(func(f *fakeSys) { f.v6 = true })
	pass(t, d)
	if !d.running() {
		t.Fatal("rebuilt on a single reading of the new IPv6 state")
	}
	pass(t, d) // a second reading agrees
	if d.running() || d.dns.Holding() {
		t.Fatal("capture not torn down on an IPv6 change")
	}
	pass(t, d)
	if !d.running() || !d.sbV6 {
		t.Fatal("capture not rebuilt with IPv6")
	}
	cfg, _ = os.ReadFile(filepath.Join(d.p.Run, "config.json"))
	if !strings.Contains(string(cfg), "fdfe:") {
		t.Fatal("rebuilt capture lacks the IPv6 address")
	}
}

func TestDNSFollowsDefaultRoute(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	calls := f.get().dnsCalls
	pass(t, d)
	if f.get().dnsCalls != calls {
		t.Fatal("resolver re-taken on every pass for the same interface")
	}
	f.set(func(f *fakeSys) { f.iface = "en5" })
	pass(t, d)
	got := f.get().dns
	if !slices.Equal(got["Wi-Fi"], []string{"192.168.1.1"}) || !slices.Equal(got["USB LAN"], []string{sysdns.Capture}) {
		t.Fatalf("resolver did not follow the default route: %v", got)
	}
	d.stopSingBox()
	got = f.get().dns
	if len(got["USB LAN"]) != 0 || !slices.Equal(got["Wi-Fi"], []string{"192.168.1.1"}) || d.dns.Holding() {
		t.Fatalf("stop did not restore every service: %v", got)
	}
}

func TestDNSTakeFailureRetriesLater(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.setErr = errors.New("networksetup: exit 4") })
	pass(t, d)
	pass(t, d)
	wantState(t, d, StateActive)
	calls := f.get().dnsCalls
	pass(t, d)
	if f.get().dnsCalls != calls {
		t.Fatal("failed takeover retried at once instead of after 30s")
	}
	f.set(func(f *fakeSys) { f.setErr = nil })
	d.dnsRetry = time.Now().Add(-time.Second)
	pass(t, d)
	if !slices.Equal(f.get().dns["Wi-Fi"], []string{sysdns.Capture}) {
		t.Fatalf("resolver not taken on retry: %v", f.get().dns)
	}
	d.stopSingBox()
	if !slices.Equal(f.get().dns["Wi-Fi"], []string{"192.168.1.1"}) {
		t.Fatalf("original resolver lost after a failed take: %v", f.get().dns)
	}
}

func TestTestPortModeIgnoresTunnelsAndDNS(t *testing.T) {
	d, f := rig(t, Options{TestPort: 21999})
	f.set(func(f *fakeSys) { f.foreign, f.tun, f.v6 = "utun7", false, true })
	pass(t, d)
	pass(t, d)
	wantState(t, d, StateActive)
	if d.sbV6 || f.get().dnsCalls != 0 {
		t.Fatal("test-port mode must not look at IPv6 or touch DNS")
	}
	cfg, _ := os.ReadFile(filepath.Join(d.p.Run, "config.json"))
	if !strings.Contains(string(cfg), `"listen_port": 21999`) || strings.Contains(string(cfg), `"tun"`) {
		t.Fatal("test-port config does not use the loopback inbound")
	}
}

// A new network starts with an empty list (no seeds): rule-sets exist, empty,
// so sing-box can start, and nothing is routed to an engine until a block has
// been learned or added.
func TestEngageStartsWithAnEmptyList(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	if n := len(d.st.List("asn:15897")); n != 0 {
		t.Fatalf("network has %d entries, want none", n)
	}
	for _, e := range d.engines {
		b, err := os.ReadFile(singbox.RuleSetPath(d.p.Run, e.Name))
		if err != nil || strings.Contains(string(b), "discord") || strings.Contains(string(b), "roblox") {
			t.Fatalf("rule-set of %s: %v %s", e.Name, err, b)
		}
	}
}

func TestConflictingToolKeepsStandby(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.tool = "GoodbyeDPI" })
	pass(t, d)
	wantState(t, d, StateStandby, "GoodbyeDPI", "engages once it is closed")
	if f.get().starts != 0 {
		t.Fatal("engaged next to another DPI tool")
	}
	f.set(func(f *fakeSys) { f.tool = "" })
	engage(t, d, f)

	f.set(func(f *fakeSys) { f.tool = "zapret (winws)" })
	pass(t, d)
	wantState(t, d, StateStandby, "zapret", "released")
	if d.running() || d.dns.Holding() || !slices.Equal(f.get().dns["Wi-Fi"], []string{"192.168.1.1"}) {
		t.Fatalf("capture or resolver kept next to another DPI tool: %v", f.get().dns)
	}
	if !d.retryAt.IsZero() {
		t.Fatal("another DPI tool is not a failure: no backoff expected")
	}

	// During a backoff wait (failures it most likely caused) the tool is what
	// the state names, and closing it forgets the wait.
	d.failOpens, d.retryAt = 3, time.Now().Add(time.Hour)
	pass(t, d)
	wantState(t, d, StateStandby, "zapret", "engages once it is closed")

	f.set(func(f *fakeSys) { f.tool = "" })
	pass(t, d)
	if !d.running() || f.get().starts != 2 || d.failOpens != 0 {
		t.Fatalf("did not re-engage at once when the tool closed (failOpens=%d)", d.failOpens)
	}
}

// A sing-box that keeps exiting as soon as it is started is this build, its
// configuration or this machine being broken. The state says so, with
// sing-box's own last words, and keeps saying so while the next attempt waits:
// "starting" or "standby" would read as if everything were in order.
func TestSingBoxThatKeepsExitingIsAnError(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.tun = false })
	pass(t, d)
	wantState(t, d, StateStarting)

	// Three exits within the first seconds: still the time in which an adapter
	// or a firewall that is not ready right after boot or wake sorts itself
	// out, as it did before any of this was reported.
	for range brokenExits {
		d.setPID(4242)
		d.sbPrinted("\x1b[31mFATAL\x1b[0m[0000] decode config at /x/config.json: inbounds[0]: unknown inbound type: tun")
		d.sbExited("exit status 1")
	}
	pass(t, d)
	wantState(t, d, StateStarting)
	if !d.running() {
		t.Fatal("released within the first seconds")
	}

	// Fewer exits, however long it has been, are not enough either.
	d.mu.Lock()
	d.sbExits = brokenExits - 1
	d.mu.Unlock()
	d.sbStarted = time.Now().Add(-brokenAfter - time.Second)
	pass(t, d)
	wantState(t, d, StateStarting)

	d.sbExited("exit status 1")
	pass(t, d)
	wantState(t, d, StateError, "sing-box does not start", "unknown inbound type: tun", "retry in")
	if _, det := state(d); strings.Contains(det, "\x1b") || strings.Contains(det, "FATAL[") {
		t.Fatalf("sing-box's colors and prefix reached the status line: %q", det)
	}
	if d.running() {
		t.Fatal("a sing-box that cannot start was kept")
	}
	pass(t, d)
	wantState(t, d, StateError, "sing-box does not start", "unknown inbound type: tun", "next attempt in")
	if n := f.get().starts; n != 1 {
		t.Fatalf("started %d times inside the backoff window, want 1", n)
	}

	// The next attempt starts from a clean slate, and with a sing-box that
	// stays up it engages as usual.
	d.retryAt = time.Now().Add(-time.Second)
	f.set(func(f *fakeSys) { f.tun = true })
	pass(t, d)
	pass(t, d)
	wantState(t, d, StateActive)
	if why := d.singBoxBroken(); why != "" {
		t.Fatalf("still called broken after engaging: %q", why)
	}
}

// broken makes the current capture's sing-box one that has kept exiting for
// long enough, with these last words.
func broken(d *Daemon, lines ...string) {
	for i := range brokenExits {
		d.setPID(4242 + i)
		for _, l := range lines {
			d.sbPrinted(l)
		}
		d.sbExited("exit status 2")
	}
	d.sbStarted = time.Now().Add(-brokenAfter - time.Second)
}

// Without a word from sing-box the exit error is the reason.
func TestSingBoxExitWithoutOutput(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.tun = false })
	pass(t, d)
	broken(d)
	d.mu.Lock()
	d.sbLastLine = ""
	d.mu.Unlock()
	d.sbExited("exit status 0xc0000135")
	pass(t, d)
	wantState(t, d, StateError, "sing-box does not start", "0xc0000135")
}

// After a crash the last line is the tail of a stack trace. What is shown is
// the line that says why.
func TestACrashIsReportedByItsPanicLine(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.tun = false })
	pass(t, d)
	broken(d, "panic: runtime error: invalid memory address or nil pointer dereference",
		"goroutine 1 [running]:", "github.com/sagernet/sing-tun.(*NativeTun).Start(0x0)",
		"\t/go/pkg/mod/github.com/sagernet/sing-tun@v0.9.7/tun_windows.go:123 +0x1c")
	pass(t, d)
	wantState(t, d, StateError, "sing-box does not start", "panic: runtime error")
	if _, det := state(d); strings.Contains(det, "tun_windows.go") {
		t.Fatalf("the stack trace's tail is what the status shows: %q", det)
	}
}

// The words of an earlier try do not stand for a later one that failed
// another way and said nothing.
func TestLastWordsBelongToTheLastProcess(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.tun = false })
	pass(t, d)
	broken(d, "FATAL[0000] start service: something that happened once")
	d.setPID(5000)
	d.sbExited("fork/exec: permission denied")
	pass(t, d)
	wantState(t, d, StateError, "sing-box does not start", "permission denied")
}

// The wait before the next round does not grow without end for this cause,
// and pausing and resuming is a way to try again at once.
func TestBrokenSingBoxWaitsAreBoundedAndPauseClearsThem(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.tun = false })
	for round := 0; round < 8; round++ {
		d.retryAt = time.Time{}
		pass(t, d)
		broken(d, "FATAL[0000] start service: configure tun interface: Access is denied.")
		pass(t, d)
		wantState(t, d, StateError, "sing-box does not start")
		if wait := time.Until(d.retryAt); wait > brokenRetryMax+time.Second {
			t.Fatalf("round %d: next attempt in %v, more than %v", round+1, wait.Round(time.Second), brokenRetryMax)
		}
	}
	if err := d.st.SetPaused(true); err != nil {
		t.Fatal(err)
	}
	pass(t, d)
	wantState(t, d, StatePaused)
	_ = d.st.SetPaused(false)
	f.set(func(f *fakeSys) { f.tun = true })
	pass(t, d)
	if !d.running() {
		s, det := state(d)
		t.Fatalf("resume did not try again at once: %s (%s)", s, det)
	}
}

// Once the capture has worked, exits are the watch's business: a crash after
// hours of running must not be reported as a sing-box that cannot start.
func TestExitsAfterVerificationAreNotABrokenBuild(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	broken(d, "signal: killed")
	pass(t, d)
	if s, det := state(d); s == StateError && strings.Contains(det, "does not start") {
		t.Fatalf("a verified capture was called a sing-box that does not start: %s", det)
	}
}

// The tap hears the supervisor's own records about sing-box.
func TestHelperTapCountsExitsAndKeepsLastWords(t *testing.T) {
	d, _ := rig(t, Options{})
	log := slog.New(helperTap{quietLog().Handler(), d})
	log.Info("FATAL[0000] start service: configure tun interface: Access is denied.", "proc", "sing-box")
	log.Warn(supervise.MsgExited, "proc", "sing-box", "err", errors.New("exit status 1"), "after", time.Second)
	log.Error(supervise.MsgStartFailed, "proc", "sing-box", "err", errors.New("fork/exec: operation not permitted"))
	d.mu.Lock()
	exits, last, fatal := d.sbExits, d.sbLastLine, d.sbFatal
	d.mu.Unlock()
	if exits != 2 || last != "start service: configure tun interface: Access is denied." || fatal != last {
		t.Fatalf("exits=%d last=%q fatal=%q", exits, last, fatal)
	}
}

// Three tries fail while the adapter is not ready right after boot, the fourth
// stays up and is still being verified when the ten seconds are over. That
// one works: it must not be killed for what the first three did, however
// short a time it has been up when the pass comes round.
func TestASingBoxThatHealedIsNotKilledForEarlierExits(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.capErr = errors.New("TLS through the capture: timeout") })
	pass(t, d)
	broken(d) // three quick exits, long enough ago
	d.setPID(7000)
	pass(t, d) // the fourth try has been up for a moment only
	if s, det := state(d); s == StateError {
		t.Fatalf("a sing-box that is running was released as broken: %s", det)
	}
	if !d.running() {
		t.Fatal("the running sing-box was stopped")
	}
	// Once it has stayed up, the earlier exits are forgotten: one more exit
	// later is one, not the fourth.
	d.mu.Lock()
	d.sbUpSince = time.Now().Add(-quickExit - time.Second)
	d.mu.Unlock()
	d.sbExited("exit status 1")
	pass(t, d)
	if s, det := state(d); s == StateError {
		t.Fatalf("one exit after a healthy run made it broken: %s", det)
	}
}

// What an earlier capture's sing-box said when it crashed is not the reason a
// later one cannot even be started.
func TestACrashLineDoesNotOutliveItsCapture(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.tun = false })
	pass(t, d)
	broken(d, "panic: runtime error: index out of range")
	pass(t, d)
	wantState(t, d, StateError, "panic: runtime error")
	d.retryAt = time.Time{}
	pass(t, d) // a new capture
	for range brokenExits {
		d.sbExited("fork/exec sing-box: no such file or directory") // could not be started: no process, no words
	}
	d.sbStarted = time.Now().Add(-brokenAfter - time.Second)
	pass(t, d)
	wantState(t, d, StateError, "no such file")
}

// While paused with a restore that keeps failing, networksetup is not run at
// every pass.
func TestAPausedFailingRestoreDoesNotHammer(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.setErr = errors.New("networksetup: Unable to commit changes to network database") })
	if err := d.st.SetPaused(true); err != nil {
		t.Fatal(err)
	}
	pass(t, d)
	wantState(t, d, StatePaused)
	pass(t, d) // one more try, which sets the wait
	calls := f.get().dnsCalls
	for range 5 {
		pass(t, d)
	}
	if got := f.get().dnsCalls - calls; got != 0 {
		t.Fatalf("%d networksetup calls in five paused passes inside the retry wait", got)
	}
	f.set(func(f *fakeSys) { f.setErr = nil })
	d.dnsRetry = time.Time{}
	pass(t, d)
	if d.dns.Holding() {
		t.Fatal("the resolver was not given back once networksetup worked again")
	}
}

// With DNS takeover turned off there is no manager to take with, but what an
// earlier run took and could not give back is still given back, and tried
// again when that fails at start.
func TestAHoldFromAnEarlierRunIsGivenBackWithTakeoverOff(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	old := d.dns
	d.stopSingBoxKeepingDNSForTest()
	d.dns, d.dnsOld = nil, old // as Run sets them when dns_takeover is off
	if !old.Holding() {
		t.Fatal("the rig did not leave a hold behind")
	}
	f.set(func(f *fakeSys) { f.net.Online = false }) // no new capture in this test
	pass(t, d)
	if old.Holding() || !slices.Equal(f.get().dns["Wi-Fi"], []string{"192.168.1.1"}) {
		t.Fatalf("the earlier run's hold is still there: %v", f.get().dns)
	}
}

// A long error keeps its end, which is where the cause is: the tray tooltip
// and the two-line detail in the apps cut the end off.
func TestBriefReasonKeepsTheCause(t *testing.T) {
	for in, want := range map[string]string{
		`decode config at C:\ProgramData\AutoDPI\run\config.json: inbounds[0]: unknown inbound type: tun and something long enough to pass ninety`: "inbounds[0]: unknown inbound type: tun and something long enough to pass ninety",
		"start service: configure tun interface: Access is denied.":                                                                                "start service: configure tun interface: Access is denied.",
		"short": "short",
	} {
		if got := briefReason(in); got != want {
			t.Errorf("briefReason(%q) = %q, want %q", in, got, want)
		}
	}
	if got := briefReason(strings.Repeat("x", 300)); len([]rune(got)) > 90 {
		t.Errorf("a long line without a colon is %d characters", len([]rune(got)))
	}
}

// The default route goes away and stays away while the capture is up (a
// network that only has IPv6 left, say). The capture held DNS at an address
// that can no longer be reached, and with every check skipped while offline it
// stayed "active" for good. A blip is waited out; a minute is not.
func TestACaptureThatStaysOfflineIsReleased(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.net.Online = false })
	pass(t, d)
	if !d.running() || !d.dns.Holding() {
		t.Fatal("released at the first pass without a route: a blip must be waited out")
	}
	d.offlineSince = time.Now().Add(-offlineRelease - time.Second)
	pass(t, d)
	wantState(t, d, StateOffline)
	if d.running() || d.dns.Holding() || !slices.Equal(f.get().dns["Wi-Fi"], []string{"192.168.1.1"}) {
		t.Fatalf("still held after a minute offline: running=%v holding=%v dns=%v", d.running(), d.dns.Holding(), f.get().dns)
	}
	f.set(func(f *fakeSys) { f.net.Online = true })
	pass(t, d)
	if !d.running() {
		t.Fatal("did not engage again once the route was back")
	}
}

// networksetup fails at times. When that happens as the capture is released,
// the system is left asking 1.1.1.1 in the clear with no capture behind it,
// and nothing tried again until the next successful engage and release.
func TestAFailedRestoreIsTriedAgainWhileWaiting(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.setErr = errors.New("networksetup: Unable to commit changes to network database") })
	d.release("fail-open: checks failing for 1m30s: DoH: timeout", StateStandby)
	if !slices.Equal(f.get().dns["Wi-Fi"], []string{sysdns.Capture}) || !d.dns.Holding() {
		t.Fatalf("the fake restore did not fail: %v", f.get().dns)
	}
	pass(t, d) // still failing: nothing changes, and it does not hammer
	calls := f.get().dnsCalls
	pass(t, d)
	if got := f.get().dnsCalls; got != calls {
		t.Fatalf("%d more networksetup calls within the retry wait", got-calls)
	}
	f.set(func(f *fakeSys) { f.setErr = nil })
	d.dnsRetry = time.Time{}
	pass(t, d)
	if d.dns.Holding() || !slices.Equal(f.get().dns["Wi-Fi"], []string{"192.168.1.1"}) {
		t.Fatalf("the resolver was not given back while waiting: %v", f.get().dns)
	}
	wantState(t, d, StateStandby)
}

// stopSingBoxKeepingDNSForTest stops the capture as a crash would: the
// resolver stays ours and the record stays on disk.
func (d *Daemon) stopSingBoxKeepingDNSForTest() {
	d.mu.Lock()
	stop := d.sbStop
	d.sbStop = nil
	d.mu.Unlock()
	if stop != nil {
		stop()
	}
}
