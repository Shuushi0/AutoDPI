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
		wantState(t, d, StateStandby, "next attempt in")
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
