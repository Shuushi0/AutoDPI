//go:build !windows

// Area 2 review tests: daemon control logic (reconcile, health, fail-open,
// backoff, DNS take/release, IPv6 rebuild, network change). They reuse the rig
// of reconcile_test.go: every contact with the machine goes to a fake, nothing
// real is started and networksetup is never run.
//
// Tests named TestArea2Bug_* assert the behaviour a user would expect and FAIL
// today: each is the reproduction of a confirmed finding. Run just them with
// -run Area2Bug.

package daemon

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/store"
	"github.com/Shuushi0/AutoDPI/internal/sysdns"
)

func wifiDNS(f *fakeSys) []string { return f.get().dns["Wi-Fi"] }

func dnsIsOriginal(f *fakeSys) bool {
	g := f.get().dns
	return slices.Equal(g["Wi-Fi"], []string{"192.168.1.1"}) && len(g["USB LAN"]) == 0
}

// ---------------------------------------------------------------------------
// Findings

// A failing start (here: config.json cannot be written) has no backoff. The
// engage loop retries every pass (3s) and every pass first runs the full
// health probe (DoH + TLS through the observer, up to 18s of network work).
// Compare release(), which backs off 30s..16m.
func TestArea2Bug_StartFailureHasNoBackoff(t *testing.T) {
	d, _ := rig(t, Options{})
	if err := os.MkdirAll(filepath.Join(d.p.Run, "config.json"), 0o755); err != nil { // WriteFile will fail
		t.Fatal(err)
	}
	var probes atomic.Int32
	orig := d.sys.healthy
	d.sys.healthy = func(ctx context.Context) error { probes.Add(1); return orig(ctx) }
	const passes = 10
	for i := 0; i < passes; i++ {
		pass(t, d)
	}
	wantState(t, d, StateError)
	if d.running() {
		t.Fatal("capture running although the start failed")
	}
	if int(probes.Load()) == passes && !d.retryAt.After(time.Now()) {
		t.Fatalf("start failed %d passes in a row and every pass re-ran the health probe: no backoff (retryAt=%v)", passes, d.retryAt)
	}
}

// A release (fail-open, capture never came up) schedules a retry up to 16
// minutes away. Moving to a different network does not clear it, so a Mac that
// failed open on a broken hotel network stays unprotected on the home network
// for the rest of the window.
func TestArea2Bug_NetworkChangeKeepsBackoff(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	for i := 0; i < 5; i++ { // a long-standing failure history -> 8 minute backoff
		d.release("simulated persistent failure", StateStandby)
	}
	if !d.retryAt.After(time.Now().Add(4 * time.Minute)) {
		t.Fatalf("setup: retryAt %v", d.retryAt)
	}
	old := f.net
	f.set(func(f *fakeSys) { f.net = netid.Info{Key: "asn:9121", Label: "AS9121 home", Online: true} })
	d.onNetChange(old, f.net)
	pass(t, d)
	if !d.running() {
		s, det := state(d)
		t.Fatalf("new network, but still waiting out the old network's backoff: state %s (%s)", s, det)
	}
}

// Failure counters survive an offline period: watch() does nothing while the
// network is offline, so a run of failures from before is still "persistent"
// when the Mac comes back, and the first failed check after reconnecting
// (DHCP still settling, captive portal) drops the capture.
func TestArea2Bug_FailureRunSurvivesOfflinePeriod(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.capErr = errors.New("DNS through the capture: timeout") })
	pass(t, d)
	pass(t, d)
	if d.badChecks != 2 {
		t.Fatalf("setup: badChecks=%d", d.badChecks)
	}
	f.set(func(f *fakeSys) { f.net.Online = false })
	d.badSince = time.Now().Add(-10 * time.Minute) // the offline period passes
	for i := 0; i < 3; i++ {
		pass(t, d)
	}
	f.set(func(f *fakeSys) { f.net.Online = true }) // back, and the first probe still fails
	pass(t, d)
	if !d.running() {
		t.Fatalf("capture released after ONE failed check since reconnecting (stale badChecks=2 / badSince=10min ago)")
	}
}

// reconcile asks route(8) which interface has the default route to decide
// whether the network has IPv6. One failed or timed-out route call (4s limit,
// or the route briefly gone while roaming) reads as "no IPv6" and tears down a
// perfectly good IPv6 capture, dropping every connection and the resolver.
func TestArea2Bug_TransientRouteErrorRebuildsIPv6Capture(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.v6 = true })
	engage(t, d, f)
	if !d.sbV6 {
		t.Fatal("setup: capture should include IPv6")
	}
	f.set(func(f *fakeSys) { f.iface = "" }) // route lookup fails once
	pass(t, d)
	f.set(func(f *fakeSys) { f.iface = "en0" })
	if !d.running() {
		t.Fatal("one failed route lookup tore the IPv6 capture down (route error is read as 'network lost IPv6')")
	}
}

// An established capture that loses its TUN is released at once (no grace) and
// the message claims a startup timeout.
func TestArea2_ActiveCaptureLosingTunIsReleasedAtOnce(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	d.sbStarted = time.Now().Add(-time.Hour) // it has been up for a long time
	f.set(func(f *fakeSys) { f.tun = false })
	pass(t, d)
	if d.running() || !dnsIsOriginal(f) {
		t.Fatalf("fail-open incomplete: running=%v dns=%v", d.running(), f.get().dns)
	}
	_, det := state(d)
	if strings.Contains(det, "did not bring the capture up in 30s") {
		t.Logf("NOTE cosmetic: a capture that ran for a while and lost its utun is reported as 'did not bring the capture up in 30s': %q", det)
	}
	if d.failOpens != 1 {
		t.Fatalf("failOpens=%d", d.failOpens)
	}
}

// ---------------------------------------------------------------------------
// Fail-open timing and backoff

func TestArea2_FailOpenBoundary(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.capErr = errors.New("down") })
	// Two failures already, the run began 89s ago: the third failed check is
	// before the 90s mark, so nothing is released.
	d.badChecks, d.badSince = failOpenChecks-1, time.Now().Add(-(failOpenAfter - 2*time.Second))
	pass(t, d)
	if !d.running() || d.badChecks != failOpenChecks {
		t.Fatalf("released at ~88s: running=%v bad=%d", d.running(), d.badChecks)
	}
	// Past the mark, on the next failing check.
	d.badSince = time.Now().Add(-failOpenAfter)
	pass(t, d)
	if d.running() {
		t.Fatal("not released although 3+ checks failed over 90s")
	}
	wantState(t, d, StateStandby, "fail-open")
	if d.badChecks != 0 || !d.badSince.IsZero() {
		t.Fatal("failure run not cleared by release")
	}
}

func TestArea2_ManyChecksButShortWindowDoesNotFailOpen(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.capErr = errors.New("down") })
	for i := 0; i < 50; i++ { // 50 failed checks in well under 90s of wall time
		pass(t, d)
	}
	if !d.running() || d.badChecks != 50 {
		t.Fatalf("running=%v badChecks=%d", d.running(), d.badChecks)
	}
}

// A failure on the DoH half (healthy) counts the same as one on the capture
// half, and either recovers the run.
func TestArea2_HealthHalvesBothCount(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.healthErr = errors.New("DoH (all resolvers): timeout") })
	pass(t, d)
	if d.badChecks != 1 || !d.unstable() {
		t.Fatalf("bad=%d unstable=%v", d.badChecks, d.unstable())
	}
	f.set(func(f *fakeSys) { f.healthErr = nil })
	pass(t, d)
	if d.badChecks != 0 || d.unstable() {
		t.Fatalf("recovery: bad=%d unstable=%v", d.badChecks, d.unstable())
	}
}

func TestArea2_UnstableWindowExpires(t *testing.T) {
	d, _ := rig(t, Options{})
	d.recordHealth(errors.New("x"))
	if !d.unstable() {
		t.Fatal("fresh failure must count")
	}
	d.mu.Lock()
	d.badAt = time.Now().Add(-healthStale - time.Second)
	d.mu.Unlock()
	if d.unstable() {
		t.Fatal("a failure older than healthStale must not block validation")
	}
	d.recordHealth(nil)
	if d.unstable() {
		t.Fatal("success must clear")
	}
}

func TestArea2_BackoffSequenceAndReset(t *testing.T) {
	d, f := rig(t, Options{})
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute}
	for i, w := range want {
		engage(t, d, f)
		f.set(func(f *fakeSys) { f.capErr = errors.New("down") })
		pass(t, d)
		d.badChecks, d.badSince = failOpenChecks-1, time.Now().Add(-failOpenAfter)
		t0 := time.Now()
		pass(t, d)
		if d.running() {
			t.Fatalf("round %d: not released", i)
		}
		if got := d.retryAt.Sub(t0).Round(time.Second); got != w {
			t.Fatalf("round %d: retry in %v, want %v", i, got, w)
		}
		f.set(func(f *fakeSys) { f.capErr = nil })
		d.retryAt = time.Time{}
	}
	// Re-engage, run stably 11 minutes: the history is forgotten.
	engage(t, d, f)
	d.activeAt = time.Now().Add(-11 * time.Minute)
	pass(t, d)
	if d.failOpens != 0 {
		t.Fatalf("failOpens=%d after a stable run", d.failOpens)
	}
	f.set(func(f *fakeSys) { f.capErr = errors.New("down") })
	pass(t, d)
	d.badChecks, d.badSince = failOpenChecks-1, time.Now().Add(-failOpenAfter)
	t0 := time.Now()
	pass(t, d)
	if got := d.retryAt.Sub(t0).Round(time.Second); got != 30*time.Second {
		t.Fatalf("after reset the next release must wait 30s, got %v", got)
	}
}

func TestArea2_BackoffCapNoOverflow(t *testing.T) {
	d, _ := rig(t, Options{})
	for i := 0; i < 70; i++ {
		t0 := time.Now()
		d.release("x", StateStandby)
		w := d.retryAt.Sub(t0)
		if w <= 0 || w > 16*time.Minute+time.Second {
			t.Fatalf("release %d: wait %v", i+1, w)
		}
	}
}

// After a fail-open the next capture must be re-verified before DNS is taken
// again (verified is reset), even though the previous run was verified.
func TestArea2_FailOpenThenReengageReverifiesBeforeDNS(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	d.release("simulated", StateStandby)
	if !dnsIsOriginal(f) {
		t.Fatal("DNS not restored by release")
	}
	d.retryAt = time.Time{}
	f.set(func(f *fakeSys) { f.capErr = errors.New("TLS through the capture: reset") })
	pass(t, d)
	pass(t, d)
	pass(t, d)
	if !dnsIsOriginal(f) {
		t.Fatalf("resolver captured by an unverified capture: %v", f.get().dns)
	}
	wantState(t, d, StateStarting, "verifying")
	f.set(func(f *fakeSys) { f.capErr = nil })
	pass(t, d)
	wantState(t, d, StateActive)
	if !slices.Equal(wifiDNS(f), []string{sysdns.Capture}) {
		t.Fatalf("resolver not taken once verified: %v", f.get().dns)
	}
}

// ---------------------------------------------------------------------------
// DNS take/release

func TestArea2_DNSFollowsRouteOnlyAfterVerification(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.capErr = errors.New("TLS through the capture: reset") })
	pass(t, d)
	pass(t, d)
	f.set(func(f *fakeSys) { f.iface = "en5" }) // default route moves while unverified
	pass(t, d)
	if !dnsIsOriginal(f) {
		t.Fatalf("DNS touched before verification: %v", f.get().dns)
	}
	f.set(func(f *fakeSys) { f.capErr = nil })
	pass(t, d)
	g := f.get().dns
	if !slices.Equal(g["USB LAN"], []string{sysdns.Capture}) || !slices.Equal(g["Wi-Fi"], []string{"192.168.1.1"}) {
		t.Fatalf("resolver must be taken on the interface that has the route now: %v", g)
	}
}

// The default route moves to an interface that is no network service (VPN-ish
// bridge): the previous service keeps the capture resolver, nothing is lost and
// stopping restores it.
func TestArea2_UnknownInterfaceKeepsPreviousDNSAndRestores(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.iface = "ppp0" })
	for i := 0; i < 3; i++ {
		pass(t, d)
	}
	wantState(t, d, StateActive)
	if !slices.Equal(wifiDNS(f), []string{sysdns.Capture}) {
		t.Fatalf("resolver dropped on a failed follow: %v", f.get().dns)
	}
	f.set(func(f *fakeSys) { f.iface = "en0" })
	d.dnsRetry = time.Time{}
	pass(t, d)
	d.stopSingBox()
	if !dnsIsOriginal(f) || d.dns.Holding() {
		t.Fatalf("not restored: %v", f.get().dns)
	}
}

// Route goes away entirely while active: DNS is left as is, no networksetup
// calls are made, and nothing panics.
func TestArea2_NoRouteWhileActiveTouchesNoDNS(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	calls := f.get().dnsCalls
	f.set(func(f *fakeSys) { f.iface = "" })
	for i := 0; i < 3; i++ {
		pass(t, d)
	}
	if f.get().dnsCalls != calls {
		t.Fatal("networksetup invoked without a default route")
	}
}

// Going offline while active: the capture stays, no probes run (they would
// all fail and count toward fail-open), state keeps saying active.
func TestArea2_OfflineWhileActiveRunsNoProbes(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	var probes atomic.Int32
	d.sys.healthy = func(context.Context) error { probes.Add(1); return errors.New("offline") }
	f.set(func(f *fakeSys) { f.net.Online = false })
	for i := 0; i < 5; i++ {
		pass(t, d)
	}
	if probes.Load() != 0 || d.badChecks != 0 {
		t.Fatalf("probes while offline: %d (bad=%d)", probes.Load(), d.badChecks)
	}
	if s, _ := state(d); s != StateActive {
		t.Logf("NOTE: state while offline with capture up is %q", s)
	}
}

// Pausing in every phase leaves nothing behind.
func TestArea2_PauseInEveryPhase(t *testing.T) {
	for phase := 0; phase < 3; phase++ {
		d, f := rig(t, Options{})
		switch phase {
		case 0: // sing-box just started
			pass(t, d)
		case 1: // started, not verified
			f.set(func(f *fakeSys) { f.capErr = errors.New("x") })
			pass(t, d)
			pass(t, d)
		case 2: // active
			engage(t, d, f)
		}
		_ = d.st.SetPaused(true)
		pass(t, d)
		wantState(t, d, StatePaused)
		if d.running() || d.dns.Holding() || !dnsIsOriginal(f) {
			t.Fatalf("phase %d: pause left things behind: running=%v dns=%v", phase, d.running(), f.get().dns)
		}
	}
}

// ---------------------------------------------------------------------------
// Network change handling

// The stable key replacing a provisional one carries the provisional list over
// (Rekey); an unrelated network does not.
func TestArea2_ProvisionalToStableRekey(t *testing.T) {
	d, f := rig(t, Options{})
	prov := netid.Info{Key: "gw:abc", GatewayKey: "gw:abc", Label: "en0 via 192.168.1.1", Provisional: true, Online: true}
	f.set(func(f *fakeSys) { f.net = prov })
	engage(t, d, f)
	if _, err := d.st.Add("gw:abc", store.Entry{Domain: "learned-host.com", Host: "learned-host.com", Engine: "tlsrec", Source: store.SourceAuto}); err != nil {
		t.Fatal(err)
	}
	stable := netid.Info{Key: "asn:15897", GatewayKey: "gw:abc", Label: "AS15897", Online: true}
	f.set(func(f *fakeSys) { f.net = stable })
	d.onNetChange(prov, stable)
	if _, ok := d.st.Match("asn:15897", "learned-host.com"); !ok {
		t.Fatal("learned entry did not move to the stable network")
	}
	for _, n := range d.st.Networks() {
		if n.Key == "gw:abc" {
			t.Fatal("provisional network left behind")
		}
	}
	b, _ := os.ReadFile(filepathRuleSet(d, "tlsrec"))
	if !strings.Contains(string(b), "learned-host.com") {
		t.Fatalf("rule-set not rewritten for the stable key: %s", b)
	}

	// A different attachment (GatewayKey differs) must not inherit it.
	d2, f2 := rig(t, Options{})
	prov2 := netid.Info{Key: "gw:one", GatewayKey: "gw:one", Provisional: true, Online: true}
	f2.set(func(f *fakeSys) { f.net = prov2 })
	engage(t, d2, f2)
	_, _ = d2.st.Add("gw:one", store.Entry{Domain: "other-host.com", Host: "other-host.com", Source: store.SourceAuto})
	other := netid.Info{Key: "asn:1", GatewayKey: "gw:other", Online: true}
	f2.set(func(f *fakeSys) { f.net = other })
	d2.onNetChange(prov2, other)
	if _, ok := d2.st.Match("asn:1", "other-host.com"); ok {
		t.Fatal("a different network inherited the provisional list")
	}
}

func filepathRuleSet(d *Daemon, engine string) string {
	return filepath.Join(d.p.Run, "blocked-"+engine+".json")
}

// onNetChange while not running must not create store networks (no TUN, no
// seeding) but must kick the loop.
func TestArea2_NetChangeWhileIdleOnlyKicks(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.net.Online = false })
	cur := netid.Info{Key: "asn:77", Label: "AS77", Online: true}
	d.onNetChange(netid.Info{}, cur)
	if n := len(d.st.Networks()); n != 0 {
		t.Fatalf("%d networks created while idle", n)
	}
	select {
	case <-d.kick:
	default:
		t.Fatal("no reconcile kick")
	}
}

// ---------------------------------------------------------------------------
// Races and shutdown

// Chaos: the engage loop runs for real while the world flips under it and
// other goroutines kick, pause, change network and (like Run's shutdown) stop
// the capture. Afterwards the machine must be back to its original resolver.
func TestArea2_EngageLoopChaosRace(t *testing.T) {
	d, f := rig(t, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	var loop sync.WaitGroup
	loop.Add(1)
	go func() { defer loop.Done(); d.engageLoop(ctx) }()

	var chaos sync.WaitGroup
	stop := make(chan struct{})
	chaos.Add(2)
	go func() { // the world
		defer chaos.Done()
		rng := rand.New(rand.NewSource(1))
		for {
			select {
			case <-stop:
				return
			default:
			}
			f.set(func(f *fakeSys) {
				switch rng.Intn(8) {
				case 0:
					f.foreign = map[bool]string{true: "utun9", false: ""}[rng.Intn(2) == 0]
				case 1:
					f.v6 = !f.v6
				case 2:
					f.iface = []string{"en0", "en5", "", "ppp0"}[rng.Intn(4)]
				case 3:
					f.tun = rng.Intn(4) != 0
				case 4:
					f.net.Online = rng.Intn(5) != 0
				case 5:
					f.capErr = []error{nil, errors.New("x")}[rng.Intn(2)]
				case 6:
					f.healthErr = []error{nil, errors.New("y")}[rng.Intn(2)]
				}
			})
			time.Sleep(time.Millisecond)
		}
	}()
	go func() { // API + monitor + shutdown-style callers
		defer chaos.Done()
		rng := rand.New(rand.NewSource(2))
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			switch rng.Intn(5) {
			case 0:
				_ = d.st.SetPaused(rng.Intn(2) == 0)
				d.kickReconcile()
			case 1:
				cur := netid.Info{Key: []string{"asn:1", "asn:2", "gw:z"}[rng.Intn(3)], Online: true}
				d.onNetChange(netid.Info{}, cur)
			case 2:
				d.stopSingBox()
			case 3:
				_ = d.running()
				d.unstable()
			default:
				d.kickReconcile()
			}
			time.Sleep(time.Millisecond)
		}
	}()
	time.Sleep(1500 * time.Millisecond)
	close(stop)
	chaos.Wait()
	// Run's shutdown order: cancel, stop, wait for the loop, release again.
	cancel()
	d.stopSingBox()
	loop.Wait()
	d.releaseDNS()
	if !dnsIsOriginal(f) {
		t.Fatalf("resolver not restored after shutdown: %v", f.get().dns)
	}
	if d.dns.Holding() {
		t.Fatal("manager still holds the resolver")
	}
	deadline := time.Now().Add(3 * time.Second)
	for f.get().running != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := f.get().running; n != 0 {
		t.Fatalf("%d fake sing-box instances still running after shutdown", n)
	}
}

// Shutdown while a take is in flight must not leave the resolver captured,
// whichever of stop/take wins.
func TestArea2_ShutdownDuringHoldDNS(t *testing.T) {
	for i := 0; i < 50; i++ {
		d, f := rig(t, Options{})
		engage(t, d, f)
		f.set(func(f *fakeSys) { f.iface = "en5" })
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); d.holdDNS() }()
		go func() { defer wg.Done(); d.stopSingBox() }()
		wg.Wait()
		d.releaseDNS() // Run's second release
		if !dnsIsOriginal(f) || d.dns.Holding() {
			t.Fatalf("iteration %d: %v", i, f.get().dns)
		}
	}
}

// ---------------------------------------------------------------------------
// Real Run, test-port mode, scratch home, short life. Uses the dev copy of
// sing-box and the built autodpi binary as guard; skipped without them.

func TestArea2_RunTestPortLifecycle(t *testing.T) {
	bin, _ := filepath.Abs("../../bin")
	self, _ := filepath.Abs("../../dist/autodpi")
	for _, p := range []string{filepath.Join(bin, "sing-box"), filepath.Join(bin, "ciadpi"), self} {
		if _, err := os.Stat(p); err != nil {
			t.Skip("helper binaries not available: ", p)
		}
	}
	t.Setenv("AUTODPI_BINDIR", bin)
	home, err := os.MkdirTemp("", "ma2-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	t.Setenv("AUTODPI_HOME", home)
	p := paths.Default()
	if p.System || !strings.HasPrefix(p.Support, home) {
		t.Fatalf("paths not under the scratch home: %+v", p)
	}
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Engines = []string{"tlsrec"}
	d := New(cfg, p, self, quietLog())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, Options{TestPort: port, MaxRuntime: 90 * time.Second}) }()

	reached := false
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		d.mu.Lock()
		s := d.state
		d.mu.Unlock()
		if s == StateActive {
			reached = true
			break
		}
	}
	d.mu.Lock()
	s, det := d.state, d.detail
	d.mu.Unlock()
	if !reached {
		t.Logf("did not reach active (no network?): %s %s", s, det)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	// Nothing of ours may survive.
	time.Sleep(500 * time.Millisecond)
	out, _ := exec.Command("pgrep", "-f", home).Output()
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("processes still running under the scratch home: %s", out)
	}
	if _, err := os.Stat(p.Sock); err == nil {
		t.Fatal("control socket left behind")
	}
	if !reached {
		t.Skip("capture did not verify (network unreachable); shutdown path still checked")
	}
}

// ---------------------------------------------------------------------------
// Process-level fail-open: the built binary as a real daemon in test-port mode
// (no TUN, no root), scratch AUTODPI_HOME, unused loopback port. SIGKILL
// must take sing-box and ciadpi down with it within the guard's 0.5s poll,
// SIGTERM must end it cleanly. Skipped without dist/autodpi.

func startTestDaemon(t *testing.T) (cmd *exec.Cmd, home string, port int) {
	t.Helper()
	self, _ := filepath.Abs("../../dist/autodpi")
	if _, err := os.Stat(self); err != nil {
		t.Skip("dist/autodpi not built")
	}
	home, err := os.MkdirTemp("", "ma2p-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("pkill", "-9", "-f", home).Run() // only processes of this scratch home
		os.RemoveAll(home)
	})
	port, err = freePort()
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(self, "daemon", "--test-port", strconv.Itoa(port), "--for", "2m", "--log-file", filepath.Join(home, "d.log"))
	cmd.Env = append(os.Environ(), "AUTODPI_HOME="+home)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond); err == nil {
			c.Close()
			return cmd, home, port
		}
		time.Sleep(200 * time.Millisecond)
	}
	b, _ := os.ReadFile(filepath.Join(home, "d.log"))
	t.Fatalf("test inbound never came up; log:\n%s", b)
	return
}

func leftovers(home string) string {
	out, _ := exec.Command("pgrep", "-fl", home).Output()
	return strings.TrimSpace(string(out))
}

func TestArea2_SIGKILLFailsOpenQuickly(t *testing.T) {
	cmd, home, port := startTestDaemon(t)
	if leftovers(home) == "" {
		t.Fatal("setup: no helper processes found")
	}
	killed := time.Now()
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	var took time.Duration
	for {
		_, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 100*time.Millisecond)
		if (err != nil && leftovers(home) == "") || time.Since(killed) > 6*time.Second {
			took = time.Since(killed)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if l := leftovers(home); l != "" {
		t.Fatalf("helpers alive %v after the daemon was SIGKILLed:\n%s", took, l)
	}
	if took > 3*time.Second {
		t.Fatalf("fail-open took %v", took)
	}
	t.Logf("capture gone %v after SIGKILL", took.Round(10*time.Millisecond))
}

func TestArea2_SIGTERMShutsDownCleanly(t *testing.T) {
	cmd, home, _ := startTestDaemon(t)
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon exited with %v after SIGTERM", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("daemon did not exit within 20s of SIGTERM")
	}
	time.Sleep(300 * time.Millisecond)
	if l := leftovers(home); l != "" {
		t.Fatalf("processes left after clean shutdown:\n%s", l)
	}
	if _, err := os.Stat(filepath.Join(home, "ctl.sock")); err == nil {
		t.Fatal("control socket left behind")
	}
}
