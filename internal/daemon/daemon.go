// Package daemon wires everything together: it keeps ciadpi and the observer
// up, drives sing-box (the TUN capture) when conditions allow, turns what the
// observer sees into validated per-network list entries, and answers the CLI.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/audit"
	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/domain"
	"github.com/Shuushi0/AutoDPI/internal/embedded"
	"github.com/Shuushi0/AutoDPI/internal/hoststate"
	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/netx"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/probe"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
	"github.com/Shuushi0/AutoDPI/internal/store"
	"github.com/Shuushi0/AutoDPI/internal/supervise"
	"github.com/Shuushi0/AutoDPI/internal/sysdns"
	"github.com/Shuushi0/AutoDPI/internal/sysx"
	"github.com/Shuushi0/AutoDPI/internal/verdict"
	"github.com/Shuushi0/AutoDPI/internal/version"
)

// Version is the release this daemon belongs to.
const Version = version.Version

// Daemon states reported by status.
const (
	StateStarting = "starting"
	StateActive   = "active"  // TUN capture running
	StateStandby  = "standby" // waiting: another tunnel owns the traffic
	StatePaused   = "paused"
	StateOffline  = "offline"
	StateError    = "error"
)

type Options struct {
	NoTun      bool          // run everything except the system capture
	MaxRuntime time.Duration // stop by itself after this long (safe trials)
	// TestPort replaces the TUN with a mixed proxy inbound on this loopback
	// port, running the very same rules. It needs no root and touches no
	// routes: the way to exercise the whole pipeline on a real network.
	TestPort int
	// LogFiles are the files `maint clear-logs` empties (the daemon log, its
	// previous generation, the launchd crash log).
	LogFiles []string
	// Supervised: a service manager starts the daemon again after a non-zero
	// exit (launchd's KeepAlive, the SCM's recovery actions). Only then can
	// `maint restart` work.
	Supervised bool
}

type candidate struct {
	host   string
	ip     netip.Addr
	engine string
}

type Daemon struct {
	cfg  config.Config
	p    paths.Set
	self string // path of the autodpi binary, for the guard
	log  *slog.Logger
	opt  Options

	st   *store.Store
	mon  *netid.Monitor
	doh  *netx.DoH
	dial *netx.Dialer
	obs  *observer.Observer
	val  *verdict.Validator
	bins embedded.Bins
	dns  *sysdns.Manager // nil unless the TUN captures the system

	engines []singbox.Engine
	wg      *singbox.WireGuardProfile
	obsPort int

	started   time.Time
	stop      context.CancelFunc // ends Run; set by Run before the control socket opens
	runCtx    context.Context    // Run's context, for work a control request starts
	restart   atomic.Bool        // Run returns ErrRestart instead of nil (maint restart)
	kick      chan struct{}
	cands     chan candidate
	retestGap time.Duration // pause between re-test probes

	// engage-loop only (no lock needed)
	lastHealth time.Time
	lastProbe  time.Time // last active (probing) health check that passed
	seenFlows  int64     // successful observer flows counted at the last check
	badChecks  int       // failed health checks in a row
	badSince   time.Time // when the current run of failed checks began
	dnsRetry   time.Time
	sbStarted  time.Time // when the current capture was started
	verified   bool      // a probe through the capture passed since then
	activeAt   time.Time // when it was first verified
	failOpens  int       // capture releases in a row, for the re-engage backoff
	retryAt    time.Time // no new capture before this
	sbV6       bool      // the running capture includes IPv6
	sbGateway  string    // the gateway the running capture sends local names to
	v6Diff     int       // passes in a row that read the opposite IPv6 state
	retryErr   string    // why the last start failed, shown while waiting to retry
	toolSeen   bool      // a conflicting DPI tool ran on an earlier pass

	netChanged atomic.Bool // the network changed: forget the re-engage backoff (set by the monitor, read by the engage loop)

	listMu sync.Mutex // serialises rule-set rewrites (three callers)

	sys system
	upd *updater // nil until Run

	mu       sync.Mutex
	state    string
	detail   string
	sbPID    int
	sbStop   func()
	dnsIf    string // interface whose service's resolver we hold
	flowSeen map[string]time.Time
	journal  []JournalEntry
	judged   map[string]*judgment        // network|site -> last look and Suspect strikes
	caches   map[string]*hoststate.Cache // network -> open names (see open.go)
	badAt    time.Time                   // when a health check last failed; zero once one passes
	findings []audit.Finding             // the system audit's latest result
	auditSig string                      // what the log last said about it

	auditKick chan struct{}

	openCur atomic.Pointer[netCache] // the current network's open names, for the observer's hot path
}

// system is the daemon's view of the machine and the network. New fills in
// the real thing; tests replace parts of it.
type system struct {
	network        func() netid.Info
	route          func() (iface, gateway string, err error)
	hasIPv6        func(iface string) bool
	foreignTunnel  func() (iface string, found bool)
	conflict       func() (name string, found bool) // another DPI tool rewriting the same packets
	tunUp          func() bool                      // our utun exists
	flows          func() int64                     // flows the capture carried successfully so far
	healthy        func(ctx context.Context) error  // what the capture depends on
	captureHealthy func(ctx context.Context) error  // probes through the capture
	keep           func(ctx context.Context, s supervise.Spec, onUp func(pid int))
	check          func(ctx context.Context, key, host string, ips []netip.Addr, all bool) verdict.Verdict
	audit          func(ctx context.Context, watched []string, compare bool) []audit.Finding // nil: no audit
}

func New(cfg config.Config, p paths.Set, self string, log *slog.Logger) *Daemon {
	routeCache, foreignCache := newRouteCache(), newForeignCache()
	d := &Daemon{cfg: cfg, p: p, self: self, log: log, state: StateStarting, retestGap: 2 * time.Second, auditKick: make(chan struct{}, 1)}
	d.sys = system{
		audit: func(ctx context.Context, watched []string, compare bool) []audit.Finding {
			facts := audit.Collect(ctx)
			fs := audit.Evaluate(facts, watched)
			if compare {
				fs = append(fs, audit.Probe(ctx, audit.ProbeNames(facts, watched), audit.SystemLookup, d.doh.LookupIPv4)...)
			}
			return fs
		},
		network: func() netid.Info {
			if d.mon == nil { // before Run creates it
				return netid.Info{}
			}
			return d.mon.Current()
		},
		route:         routeCache.get,
		hasIPv6:       netx.HasGlobalIPv6,
		foreignTunnel: foreignCache.get,
		conflict:      sysx.ConflictingTool,
		tunUp:         func() bool { return netx.InterfaceWithIP(singbox.TunIP) != "" },
		flows: func() int64 {
			if d.obs == nil {
				return 0
			}
			s := d.obs.Stats()
			return s.Direct + s.Fallback
		},
		healthy:        d.healthy,
		captureHealthy: d.captureHealthy,
		keep: func(ctx context.Context, s supervise.Spec, onUp func(int)) {
			supervise.Keep(ctx, s, func(p *supervise.Proc) { onUp(p.PID()) })
		},
		check: d.check,
	}
	return d
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func (d *Daemon) planEngines() error {
	kinds := map[string]singbox.Kind{
		"ciadpi": singbox.Socks, "tlsrec": singbox.TLSRecord, "tlsfrag": singbox.TLSSegment, "tlsspoof": singbox.TLSSpoof, "warp": singbox.WireGuard,
	}
	for _, name := range d.cfg.Engines {
		if name == "tlsspoof" && !sysx.IsRoot() {
			d.log.Info("engine tlsspoof skipped: injecting the decoy needs root")
			continue
		}
		port, err := freePort()
		if err != nil {
			return err
		}
		d.engines = append(d.engines, singbox.Engine{Name: name, Kind: kinds[name], Port: port})
		if name == "warp" {
			f, err := os.Open(d.cfg.WarpProfile)
			if err != nil {
				return fmt.Errorf("warp profile: %w", err)
			}
			d.wg, err = singbox.ParseWgcf(f)
			f.Close()
			if err != nil {
				return err
			}
		}
	}
	if len(d.engines) == 0 {
		return errors.New("no usable engine in the configured ladder")
	}
	return nil
}

func (d *Daemon) engineNames() []string {
	names := make([]string, len(d.engines))
	for i, e := range d.engines {
		names[i] = e.Name
	}
	return names
}

func (d *Daemon) observerEngines() []observer.Engine {
	out := make([]observer.Engine, len(d.engines))
	for i, e := range d.engines {
		out[i] = observer.Engine{Name: e.Name, Addr: e.Addr()}
	}
	return out
}

func (d *Daemon) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return d.doh.LookupIPv4(ctx, host)
}

// Run blocks until ctx ends (or MaxRuntime elapses), then restores the network.
func (d *Daemon) Run(ctx context.Context, opt Options) error {
	d.opt, d.started = opt, time.Now()
	d.kick, d.cands = make(chan struct{}, 1), make(chan candidate, 64)

	if c, err := net.DialTimeout("unix", d.p.Sock, time.Second); err == nil {
		c.Close()
		return fmt.Errorf(i18n.T("başka bir autodpi daemon'u zaten çalışıyor (%s)", "another autodpi daemon is already running (%s)"), d.p.Sock)
	}
	for _, dir := range []string{d.p.Support, d.p.Run} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// An update in flight is settled first: a version that keeps failing gives
	// way to the previous one before it can fail again.
	d.upd = newUpdater(d)
	if d.upd.resume() && opt.Supervised {
		return ErrRestart
	}
	if d.p.System && sysx.IsRoot() {
		// Windows: the service runs as SYSTEM and executes what is in here.
		if err := sysx.SecureDir(d.p.Support); err != nil {
			return fmt.Errorf("lock down install directory %s: %w", d.p.Support, err)
		}
		// Windows: signed-in users read config.json (the tray app's settings
		// page and language), only administrators change it. A save sets this
		// too; a file an administrator wrote another way, or one from before,
		// has the directory's administrators-only access.
		if err := sysx.ShareConfig(d.p.Config); err != nil && !errors.Is(err, os.ErrNotExist) {
			d.log.Warn("config.json stays unreadable for signed-in users", "err", err)
		}
	}
	if !opt.NoTun && opt.TestPort == 0 && d.cfg.DNSTakeover {
		d.dns = &sysdns.Manager{File: d.p.DNSSaved, Log: d.log}
		// A previous run that died holding the resolver left the original here.
		if err := d.dns.Release(); err != nil {
			d.log.Warn("restore system resolver", "err", err)
		}
	}
	var err error
	if embedded.Embedded() {
		// Before extracting: Windows keeps a running executable locked.
		killStale(embedded.Paths(d.p.Bin), d.log)
	}
	if d.bins, err = embedded.Prepare(d.p.Bin); err != nil {
		return err
	}
	if d.st, err = store.Open(d.p.State); err != nil {
		return err
	}
	if n, err := d.st.PruneEmpty(); err != nil {
		d.log.Warn("prune empty networks", "err", err)
	} else if n > 0 {
		d.log.Info("dropped empty provisional networks", "count", n)
	}
	if m := d.st.Migration(); m.From > 0 {
		d.log.Info("state file migrated", "from_version", m.From, "backup", m.Backup, "seeds_kept_as_auto", m.SeedsKept)
		if m.DroppedClean > 0 {
			d.log.Info("clean list is memory-only now", "names", m.DroppedClean, "note", "each name opens again after three direct connections")
		}
	}
	if err := d.planEngines(); err != nil {
		return err
	}

	d.dial = &netx.Dialer{Timeout: 6 * time.Second}
	d.doh = netx.NewDoHServers(d.dial, d.cfg.DoHServers)
	d.mon = &netid.Monitor{DoH: d.doh, Log: d.log, OnChange: d.onNetChange}
	d.val = &verdict.Validator{
		Direct:  &probe.Prober{Dial: d.dial.DialContext, Timeout: 5 * time.Second},
		Engines: d.observerEngines,
		Resolve: d.resolve,
	}
	d.applyList() // rule-set files must exist before sing-box ever starts

	ln, err := (&net.ListenConfig{KeepAlive: 30 * time.Second}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	d.obsPort = ln.Addr().(*net.TCPAddr).Port
	d.obs = observer.New(observer.Options{
		Engines:   d.observerEngines,
		Dial:      d.dial.DialContext,
		Resolve:   d.resolve,
		Events:    d.onEvent,
		Unopened:  d.onUnopened,
		Mode:      d.mode,
		Hedge:     time.Duration(d.cfg.HedgeMS) * time.Millisecond,
		FirstByte: time.Duration(d.cfg.FirstByteMS) * time.Millisecond,
		Log:       d.log,

		EscalateOnSilence: d.cfg.EscalateOnSilence,
	})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.stop, d.runCtx = cancel, ctx
	if opt.MaxRuntime > 0 {
		var c context.CancelFunc
		ctx, c = context.WithTimeout(ctx, opt.MaxRuntime)
		defer c()
	}

	// Route-table notifications replace most polling (see sysmemo.go): the
	// monitor and the capture loop run on the event and keep their timers as a
	// safety net only.
	if routes := netx.WatchRoutes(ctx); routes != nil {
		d.mon.Idle = monitorIdle
		go d.routeEvents(ctx, routes)
	}

	var wg sync.WaitGroup
	spawn := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	for _, e := range d.engines {
		if e.Name == "ciadpi" {
			spawn(func() { d.ciadpiLoop(ctx, e.Port) })
		}
	}
	spawn(func() { _ = d.obs.Serve(ln) })
	spawn(func() { d.mon.Run(ctx) })
	spawn(func() { d.candidateLoop(ctx) })
	spawn(func() { d.storeLoop(ctx) })
	spawn(func() { d.retestLoop(ctx) })
	spawn(func() { d.upd.confirmLoop(ctx) })
	spawn(func() { d.upd.loop(ctx) })
	if d.opt.TestPort == 0 {
		spawn(func() { d.auditLoop(ctx) })
	}
	var ctlErr error // read after wg.Wait
	spawn(func() {
		if err := ipc.Serve(ctx, d.p.Sock, d.reply); err != nil {
			d.log.Error("control socket", "err", err)
			ctlErr = fmt.Errorf("control socket: %w", err)
			cancel()
		}
	})
	if opt.NoTun && opt.TestPort == 0 {
		d.setState(StateStandby, "capture disabled (--no-tun)")
	} else {
		spawn(func() { d.engageLoop(ctx) })
	}
	d.log.Info("daemon up", "version", Version, "engines", d.engineNames(), "observer", d.obsPort)

	<-ctx.Done()
	d.log.Info("shutting down")
	d.stopSingBox() // first: give the network back before anything else goes away
	d.obs.Close()
	wg.Wait()
	d.releaseDNS() // again: the engage loop may have retaken it while stopping
	if ctlErr == nil && d.restart.Load() {
		return ErrRestart
	}
	return ctlErr
}

// ErrRestart is what Run returns after `maint restart`: the process must exit
// non-zero so launchd (KeepAlive SuccessfulExit=false) or the SCM (recovery
// actions) starts it again, while `maint shutdown` returns nil and stays down.
var ErrRestart = errors.New("restart requested")

// ciadpiLoop keeps ciadpi running while the service is not paused: a pause
// gives all traffic back, so the proxy goes too.
func (d *Daemon) ciadpiLoop(ctx context.Context, port int) {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		for d.st.Paused() {
			select {
			case <-tick.C:
			case <-ctx.Done():
				return
			}
		}
		cctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); supervise.Keep(cctx, d.ciadpiSpec(port), nil) }()
		for !d.st.Paused() && ctx.Err() == nil {
			select {
			case <-tick.C:
			case <-ctx.Done():
			}
		}
		cancel()
		<-done
		if ctx.Err() != nil {
			return
		}
	}
}

// monitorIdle is the network monitor's safety-net period while route
// notifications drive it.
const monitorIdle = 30 * time.Second

// routeEvents turns bursts of routing-table changes into one monitor poll and
// one capture-loop pass.
func (d *Daemon) routeEvents(ctx context.Context, routes <-chan struct{}) {
	for {
		select {
		case <-routes:
		case <-ctx.Done():
			return
		}
		select { // let the burst settle: a network switch is dozens of messages
		case <-time.After(400 * time.Millisecond):
		case <-ctx.Done():
			return
		}
		d.mon.Poke()
		d.kickReconcile()
	}
}

func (d *Daemon) ciadpiSpec(port int) supervise.Spec {
	var user *supervise.Credential
	if sysx.IsRoot() {
		user = supervise.Nobody // the bypass engine never needs root (macOS; ignored on Windows)
	}
	args := []string{"-i", "127.0.0.1", "-p", strconv.Itoa(port), "-c", strconv.Itoa(d.cfg.MaxConn)}
	args = append(args, d.cfg.CiadpiFields()...)
	return supervise.Spec{Name: "ciadpi", Path: d.bins.Ciadpi, Args: args, User: user, Self: d.self, Log: d.helperLog(), HardKill: true}
}

// verbose reports whether the daemon runs with -v.
func (d *Daemon) verbose() bool { return d.log.Enabled(context.Background(), slog.LevelDebug) }

// helperLog is where a helper's own output goes. ciadpi prints a line for every
// reset it sees and sing-box an ERROR for every connection that fails while the
// link is down (a minute after each wake from sleep: hundreds of lines), which
// was 80% of the log in normal use. Without -v only warnings pass: the
// supervisor's start/exit messages, not the helpers' per-connection chatter.
func (d *Daemon) helperLog() *slog.Logger {
	if d.verbose() {
		return d.log
	}
	return slog.New(minLevel{d.log.Handler(), slog.LevelWarn})
}

// minLevel drops records below a level.
type minLevel struct {
	slog.Handler
	min slog.Level
}

func (h minLevel) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= h.min && h.Handler.Enabled(ctx, l)
}
func (h minLevel) WithAttrs(a []slog.Attr) slog.Handler {
	return minLevel{h.Handler.WithAttrs(a), h.min}
}
func (h minLevel) WithGroup(n string) slog.Handler { return minLevel{h.Handler.WithGroup(n), h.min} }

// applyList writes the current network's list into the rule-set files that
// sing-box watches.
func (d *Daemon) applyList() {
	d.listMu.Lock()
	defer d.listMu.Unlock()
	key := d.sys.network().Key
	names := d.engineNames()
	by := d.st.ByEngine(key, names, names[0])
	for _, e := range d.engines {
		if err := singbox.WriteRuleSet(d.p.Run, e.Name, by[e.Name]); err != nil {
			d.log.Error("write rule-set", "engine", e.Name, "err", err)
		}
	}
}

func (d *Daemon) storeLoop(ctx context.Context) {
	for {
		select {
		case <-d.st.Changed():
			select { // debounce bursts
			case <-time.After(300 * time.Millisecond):
			case <-ctx.Done():
				return
			}
			d.applyList()
		case <-ctx.Done():
			return
		}
	}
}

func (d *Daemon) kickReconcile() {
	select {
	case d.kick <- struct{}{}:
	default:
	}
}

func (d *Daemon) onNetChange(old, cur netid.Info) {
	d.note("network", cur.Key, cur.Label)
	running := d.running()
	if running {
		if _, err := d.st.Touch(cur.Key, cur.Label); err != nil {
			d.log.Error("touch network", "err", err)
		}
	}
	// Only the same attachment, now identified, inherits the provisional
	// list; not a known network the Mac moved to before the lookup finished.
	if old.Provisional && !cur.Provisional && cur.GatewayKey == old.Key {
		if err := d.st.Rekey(old.Key, cur.Key); err != nil {
			d.log.Error("rekey network", "err", err)
		}
		d.dropCache(old.Key) // what the provisional network saw is not carried over
	}
	d.useNetwork(cur.Key)
	if d.obs != nil {
		d.obs.ForgetDead() // what no path could open there says nothing about here
	}
	if running {
		d.applyList()
	}
	// A failure history belongs to the network it happened on, except that the
	// same attachment finally being identified is not another network.
	if !(old.Provisional && !cur.Provisional && cur.GatewayKey == old.Key) {
		d.netChanged.Store(true)
	}
	d.kickReconcile()
	d.kickAudit()
}

func (d *Daemon) running() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sbStop != nil
}

func (d *Daemon) engageLoop(ctx context.Context) {
	// Before the network monitor's first look the network reads as offline:
	// the first pass waits for it, so a start is not journalled as "offline,
	// no default route" a moment before the network shows up.
	if d.mon != nil {
		select {
		case <-d.mon.Ready():
		case <-time.After(10 * time.Second): // the look is bounded by its commands' timeouts
		case <-ctx.Done():
			return
		}
	}
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for ctx.Err() == nil {
		d.reconcile(ctx)
		select {
		case <-t.C:
		case <-d.kick:
		case <-ctx.Done():
			return
		}
	}
}

func (d *Daemon) reconcile(ctx context.Context) {
	if d.netChanged.Swap(false) {
		d.failOpens, d.retryAt, d.retryErr = 0, time.Time{}, ""
	}
	tool := d.conflict()
	if tool == "" && d.toolSeen {
		// Failures while it ran were most likely its doing: start afresh.
		d.failOpens, d.retryAt, d.retryErr = 0, time.Time{}, ""
	}
	d.toolSeen = tool != ""
	switch {
	case d.st.Paused():
		d.stopSingBox()
		d.setState(StatePaused, "")
	case d.running():
		if tool != "" {
			d.stopSingBox()
			d.setState(StateStandby, tool+" is running and rewrites the same packets; capture released")
			return
		}
		if !d.captureUp() {
			if time.Since(d.sbStarted) > 30*time.Second {
				d.release("sing-box did not bring the capture up in 30s", StateError)
				return
			}
			d.setState(StateStarting, "sing-box is not up yet; traffic is untouched meanwhile")
			return
		}
		if d.opt.TestPort == 0 {
			if ifc, found := d.sys.foreignTunnel(); found {
				d.stopSingBox()
				d.setState(StateStandby, "another tunnel owns the traffic ("+ifc+"); capture released")
				return
			}
			// The TUN must offer IPv6 exactly when the network does (see
			// singbox tunIP6). A failed route lookup says nothing, and one
			// differing reading may be a blip: rebuild only when two passes in
			// a row agree that it changed.
			// Local names go to the gateway the capture was built with; on
			// another network that is someone else's router.
			if gw := d.sys.network().Gateway; gw != "" && d.sbGateway != "" && gw != d.sbGateway {
				d.note("capture", "sing-box", "gateway changed ("+gw+"), restarting capture")
				d.stopSingBox()
				return
			}
			if v6, ok := d.networkIPv6(); ok {
				if v6 == d.sbV6 {
					d.v6Diff = 0
				} else if d.v6Diff++; d.v6Diff >= 2 {
					d.note("capture", "sing-box", fmt.Sprintf("network IPv6 changed (%v), restarting capture", v6))
					d.stopSingBox()
					return
				}
			}
		}
		d.watch(ctx)
		if !d.running() {
			return // the watch released the capture
		}
		if !d.verified {
			d.setState(StateStarting, "verifying the capture before taking over DNS")
			return
		}
		d.holdDNS()
		d.setState(StateActive, "")
	case !d.sys.network().Online:
		d.badChecks, d.badSince = 0, time.Time{} // a failure run does not span an outage
		d.setState(StateOffline, "no default route")
	case tool != "":
		// Ahead of the backoff wait: the tool, not the network, is the reason.
		d.setState(StateStandby, tool+" is running and rewrites the same packets; engages once it is closed")
	case time.Now().Before(d.retryAt):
		left := time.Until(d.retryAt).Round(time.Second)
		if d.retryErr != "" {
			d.setState(StateError, fmt.Sprintf("%s; next attempt in %s", d.retryErr, left))
			return
		}
		d.setState(StateStandby, fmt.Sprintf("capture released earlier; next attempt in %s", left))
	default:
		if ifc, found := d.sys.foreignTunnel(); found && d.opt.TestPort == 0 {
			d.setState(StateStandby, "another tunnel owns the traffic ("+ifc+"); engages once it is gone")
			return
		}
		// Never take over DNS and TCP/443 unless the plumbing we depend on works.
		err := d.sys.healthy(ctx)
		if ctx.Err() != nil {
			return // shutting down: a check cut short says nothing about the network
		}
		d.recordHealth(err)
		if err != nil {
			d.setState(StateStandby, "not engaging, health check failed: "+err.Error())
			return
		}
		if err := d.startSingBox(ctx); err != nil {
			// Same backoff as a release: a start that cannot work (disk, config,
			// binaries) must not re-run the health probe every pass.
			d.retryErr = err.Error()
			wait := d.backoff()
			d.setState(StateError, fmt.Sprintf("%s; retry in %s", err, wait))
			return
		}
		d.retryErr = ""
		d.lastHealth, d.badChecks, d.badSince = time.Time{}, 0, time.Time{} // verify through the capture at once
		d.sbStarted, d.verified = time.Now(), false
		d.setState(StateStarting, "capture starting")
	}
}

// conflict reports another DPI-bypass program working on the same packets
// (sysx.ConflictingTool). Like another tunnel it is not a failure: the daemon
// waits in standby, without backoff, and engages once it is gone.
func (d *Daemon) conflict() string {
	if d.sys.conflict == nil {
		return ""
	}
	name, _ := d.sys.conflict()
	return name
}

// captureUp reports whether sing-box runs and, in TUN mode, its utun exists.
func (d *Daemon) captureUp() bool {
	d.mu.Lock()
	pid := d.sbPID
	d.mu.Unlock()
	if pid == 0 {
		return false
	}
	return d.opt.TestPort != 0 || d.sys.tunUp()
}

// release gives the network back after a failure and schedules the next
// attempt with exponential backoff, so a broken path does not flap.
func (d *Daemon) release(why, state string) {
	d.stopSingBox()
	d.retryErr = ""
	wait := d.backoff()
	d.setState(state, fmt.Sprintf("%s; capture released, retry in %s", why, wait))
}

// backoff schedules the next capture attempt, exponentially later for every
// failure in a row (30s .. 16m), and returns the wait.
func (d *Daemon) backoff() time.Duration {
	d.failOpens++
	wait := 30 * time.Second << min(d.failOpens-1, 5)
	d.retryAt = time.Now().Add(wait)
	return wait
}

// captureHealthy probes through the capture itself with sockets that are not
// pinned to the physical interface: a TLS handshake (TUN, sing-box stack and
// outbound) and, in TUN mode, a DNS query to the resolver the system will be
// pointed at (hijack-dns into DoH).
func (d *Daemon) captureHealthy(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	dial := (&net.Dialer{}).DialContext
	if d.opt.TestPort != 0 {
		dial = probe.ViaSocks(fmt.Sprintf("127.0.0.1:%d", d.opt.TestPort))
	}
	p := &probe.Prober{Dial: dial, Timeout: 4 * time.Second}
	if r := anyTLS(cctx, p, probeTargetsFor(d.cfg.DoHServers)); r.Outcome != probe.OK {
		return fmt.Errorf("TLS through the capture: %v", r)
	}
	if d.opt.TestPort != 0 {
		return nil
	}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", sysdns.Capture+":53")
	}}
	if _, err := r.LookupIPAddr(cctx, "example.com"); err != nil {
		return fmt.Errorf("DNS through the capture: %w", err)
	}
	return nil
}

// probeTarget is one endpoint the TLS health probes try, with the name its
// certificate is checked against.
type probeTarget struct{ addr, name string }

// dohNames are the certificate names of well-known DoH addresses; any other
// address is checked against its IP (the usual DoH certificate lists it).
var dohNames = map[string]string{
	"1.1.1.1": "one.one.one.one", "1.0.0.1": "one.one.one.one",
	"2606:4700:4700::1111": "one.one.one.one", "2606:4700:4700::1001": "one.one.one.one",
	"8.8.8.8": "dns.google", "8.8.4.4": "dns.google",
	"2001:4860:4860::8888": "dns.google", "2001:4860:4860::8844": "dns.google",
	"9.9.9.9": "dns.quad9.net", "149.112.112.112": "dns.quad9.net",
}

// probeTargetsFor turns the configured DoH servers into probe targets, so the
// health checks follow the resolvers the user chose (and do not fail on a
// network that blocks Cloudflare while other resolvers work).
func probeTargetsFor(servers []string) []probeTarget {
	var out []probeTarget
	for _, s := range servers {
		ip, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		name := dohNames[ip.String()]
		if name == "" {
			name = ip.String()
		}
		out = append(out, probeTarget{net.JoinHostPort(ip.String(), "443"), name})
	}
	if len(out) == 0 {
		out = []probeTarget{{"1.1.1.1:443", "one.one.one.one"}, {"1.0.0.1:443", "one.one.one.one"}}
	}
	return out
}

// anyTLS succeeds when a TLS handshake to any of targets does. When all fail
// it returns the first failure.
func anyTLS(ctx context.Context, p *probe.Prober, targets []probeTarget) probe.Result {
	var first probe.Result
	for i, t := range targets {
		r := p.TLS(ctx, t.addr, t.name)
		if r.Outcome == probe.OK {
			return r
		}
		if i == 0 {
			first = r
		}
		if ctx.Err() != nil {
			break
		}
	}
	return first
}

// healthy exercises what the capture depends on: DoH (all DNS goes there once
// we hijack it) and the observer's real-path relay. It fails only when every
// resolver fails; DoH tries them in turn.
func (d *Daemon) healthy(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	if _, err := d.doh.LookupIPv4(cctx, "example.com"); err != nil {
		return fmt.Errorf("DoH (all resolvers): %w", err)
	}
	p := &probe.Prober{Dial: probe.ViaSocks(fmt.Sprintf("127.0.0.1:%d", d.obsPort)), Timeout: 4 * time.Second}
	if r := anyTLS(cctx, p, probeTargetsFor(d.cfg.DoHServers)); r.Outcome != probe.OK {
		return fmt.Errorf("observer self-test: %v", r)
	}
	return nil
}

// Fail-open needs the failure to persist: this many failed checks in a row
// spread over at least failOpenAfter. Three timeouts in 30s (a resolver
// stalling briefly) dropped users' connections twice; a real outage lasts.
const (
	failOpenChecks = 3
	failOpenAfter  = 90 * time.Second
)

// watch is the fail-open brake: when every check keeps failing (all resolvers
// and the capture path, for at least failOpenAfter) the network is handed back
// (with backoff) until things work again. Its first pass after a start is what
// verifies the capture.
func (d *Daemon) watch(ctx context.Context) {
	if time.Since(d.lastHealth) < healthEvery {
		return
	}
	d.lastHealth = time.Now()
	if !d.sys.network().Online {
		d.badChecks, d.badSince = 0, time.Time{} // a failure run does not span an outage
		return
	}
	// Flows the capture carried to a server since the last check prove the
	// path works (TUN, sing-box, observer). Probing would add a DoH query and
	// three TLS handshakes every healthEvery, mobile data included, so while
	// real traffic keeps flowing the active probe runs only every probeEvery.
	if d.verified && d.sys.flows != nil {
		n := d.sys.flows()
		busy := n > d.seenFlows
		d.seenFlows = n
		if busy && time.Since(d.lastProbe) < probeEvery {
			d.recordHealth(nil)
			d.badChecks, d.badSince = 0, time.Time{}
			if time.Since(d.activeAt) > 10*time.Minute {
				d.failOpens = 0
			}
			return
		}
	}
	err := d.sys.healthy(ctx)
	if err == nil {
		err = d.sys.captureHealthy(ctx)
	}
	if ctx.Err() != nil {
		return // shutting down: a check cut short says nothing about the network
	}
	d.recordHealth(err)
	if err != nil {
		if d.badChecks == 0 {
			d.badSince = time.Now()
		}
		d.badChecks++
		d.log.Warn("health check failed", "n", d.badChecks, "for", time.Since(d.badSince).Round(time.Second), "err", err)
		if d.badChecks >= failOpenChecks && time.Since(d.badSince) >= failOpenAfter {
			d.badChecks, d.badSince = 0, time.Time{}
			d.release(fmt.Sprintf("fail-open: checks failing for %s: %v", failOpenAfter, err), StateStandby)
		}
		return
	}
	d.badChecks, d.badSince = 0, time.Time{}
	d.lastProbe = time.Now()
	if d.sys.flows != nil {
		d.seenFlows = d.sys.flows()
	}
	if !d.verified {
		d.verified, d.activeAt = true, time.Now()
	} else if time.Since(d.activeAt) > 10*time.Minute {
		d.failOpens = 0 // stable again: forget earlier failures
	}
}

// recordHealth remembers the outcome of the latest health check for the
// validation path, which runs on another goroutine.
func (d *Daemon) recordHealth(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.badAt = time.Now()
	} else {
		d.badAt = time.Time{}
	}
}

// unstable reports whether the health checks are failing right now. Checks
// run every healthEvery while the capture is up, so a failure older than
// healthStale is no longer current (nothing has re-checked since).
func (d *Daemon) unstable() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.badAt.IsZero() && time.Since(d.badAt) < healthStale
}

// networkIPv6 reports whether the default route's interface has global IPv6;
// ok is false when the route could not be read, which says nothing either way.
func (d *Daemon) networkIPv6() (v6, ok bool) {
	iface, _, err := d.sys.route()
	if err != nil {
		return false, false
	}
	return d.sys.hasIPv6(iface), true
}

func (d *Daemon) networkHasIPv6() bool {
	v6, ok := d.networkIPv6()
	return ok && v6
}

func (d *Daemon) startSingBox(ctx context.Context) error {
	d.sbV6, d.v6Diff = d.opt.TestPort == 0 && d.networkHasIPv6(), 0
	d.sbGateway = d.sys.network().Gateway
	net := d.sys.network()
	if _, err := d.st.Touch(net.Key, net.Label); err != nil {
		return err
	}
	d.applyList()
	cfg, err := singbox.Build(singbox.Options{
		Engines: d.engines, ObserverPort: d.obsPort, RuleDir: d.p.Run,
		Tun: d.opt.TestPort == 0, TestPort: d.opt.TestPort,
		BlockQUIC: d.cfg.BlockQUIC, IPv4Only: d.cfg.IPv4Only, WireGuard: d.wg, SpoofSNI: d.cfg.SpoofSNI,
		IPv6: d.sbV6, DoH: d.cfg.DoHServers,
		LocalDNS: d.sbGateway, LocalSuffixes: append(domain.LocalSuffixes(), d.cfg.LocalDomains...),
		LogLevel: map[bool]string{true: "warn", false: "fatal"}[d.verbose()], // see helperLog
		// Windows: sing-box's WFP filters stop the multi-homed DNS leak that
		// networksetup handles on macOS (see sysdns_windows.go).
		StrictRoute: runtime.GOOS == "windows",
	})
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(d.p.Run, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return err
	}
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	spec := supervise.Spec{
		Name: "sing-box", Path: d.bins.SingBox, Self: d.self, Log: d.log,
		Args: []string{"--disable-color", "run", "-c", cfgPath},
		Env:  helperGoEnv(),
	}
	go func() {
		defer close(done)
		d.sys.keep(sctx, spec, d.setPID)
		d.setPID(0)
	}()
	d.mu.Lock()
	d.sbStop = func() { cancel(); <-done }
	d.mu.Unlock()
	mode := "TUN on"
	if d.opt.TestPort != 0 {
		mode = fmt.Sprintf("test inbound 127.0.0.1:%d (no TUN)", d.opt.TestPort)
	}
	d.note("capture", "sing-box", mode+" · network "+net.Label)
	return nil
}

// holdDNS points the system resolver into the TUN (see sysdns) once sing-box
// is up, and follows the default route to another interface.
func (d *Daemon) holdDNS() {
	if d.dns == nil || time.Now().Before(d.dnsRetry) {
		return
	}
	iface, _, err := d.sys.route()
	d.mu.Lock()
	same := iface == d.dnsIf
	d.mu.Unlock()
	if err != nil || same {
		return
	}
	if err := d.dns.Take(iface); err != nil {
		d.dnsRetry = time.Now().Add(30 * time.Second)
		d.log.Warn("capture system resolver", "iface", iface, "err", err)
		return
	}
	d.mu.Lock()
	d.dnsIf = iface
	d.mu.Unlock()
	d.note("dns", iface, "system resolver -> "+sysdns.Capture+", answered by DoH")
}

func (d *Daemon) releaseDNS() {
	if d.dns == nil {
		return
	}
	if err := d.dns.Release(); err != nil {
		d.log.Error("restore system resolver", "err", err)
	}
	d.mu.Lock()
	d.dnsIf = ""
	d.mu.Unlock()
}

func (d *Daemon) stopSingBox() {
	d.releaseDNS() // first: queries to 1.1.1.1 must not outlive the hijack
	d.mu.Lock()
	stop := d.sbStop
	d.sbStop = nil
	d.mu.Unlock()
	if stop != nil {
		stop()
		d.note("capture", "sing-box", "TUN off")
		// Stopping sing-box closed the flows its engines carried, and that close
		// reads like a server's rejection. Nothing from before this counts.
		if d.obs != nil {
			d.obs.ForgetDead()
		}
	}
}

func (d *Daemon) setPID(pid int) {
	d.mu.Lock()
	d.sbPID = pid
	d.mu.Unlock()
}

func (d *Daemon) setState(s, detail string) {
	d.mu.Lock()
	changed := d.state != s || detailKind(d.detail) != detailKind(detail)
	activated := s == StateActive && d.state != StateActive
	d.state, d.detail = s, detail
	d.mu.Unlock()
	if changed {
		d.note("state", s, detail)
	}
	if activated {
		d.kickAudit()
	}
}

// detailKind is the reason a state's detail gives, without what differs from
// one pass to the next: the error after the first colon (behind a login page
// the same failure comes with another port or wording every time), the wait
// that counts down, and any number.
func detailKind(detail string) string {
	for _, sep := range []string{": ", "; next attempt in ", "; retry in "} {
		if i := strings.Index(detail, sep); i >= 0 {
			detail = detail[:i]
		}
	}
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return -1
		}
		return r
	}, detail)
}

// onEvent is the observer's hook: only a flow an engine delivered is worth a
// closer look. It is journalled as repaired only when the direct attempt was
// blocked (a reset or an injected reply): an engine that merely won the hedge
// against a slow direct attempt repaired nothing, but its name is judged all
// the same, which probes before anything is listed. A flow no path could open
// (a server that rejects the request, say) is not journalled or shown
// anywhere: nothing can be done about it, and it buried the real entries. The
// observer reports one only when it was an open name, so that trackOpen can
// close it.
func (d *Daemon) onEvent(ev observer.Event) {
	if ev.Outcome == observer.Fallback && ev.Blocked {
		d.noteFlow("repaired", ev, "via "+ev.Engine+", "+summarize(ev.Results))
	}
	d.trackOpen(ev)
	if ev.Outcome != observer.Fallback || ev.SNI == "" {
		return
	}
	ap, err := netip.ParseAddrPort(ev.Dest)
	if err != nil {
		return
	}
	select {
	case d.cands <- candidate{host: ev.SNI, ip: ap.Addr(), engine: ev.Engine}:
	default:
	}
}

// noteFlow puts a repaired connection in the journal (what a user asks about
// when a page shows ERR_CONNECTION_RESET), at most once a minute per host so
// a page full of retries does not flood it. Flows no path could open stay
// out of it.
func (d *Daemon) noteFlow(kind string, ev observer.Event, detail string) {
	host := ev.SNI
	if host == "" {
		host = ev.Dest
	}
	if d.firstThisMinute(kind + "|" + host) {
		d.note(kind, host, detail)
	}
}

// onUnopened logs a flow no path could open, at most once a minute per host. It
// stays out of the journal: a site that is simply down is no news, but a report
// has to be able to show why a site does not open.
func (d *Daemon) onUnopened(ev observer.Event) {
	host := ev.SNI
	if host == "" {
		host = ev.Dest
	}
	if !d.firstThisMinute("unopened|" + host) {
		return
	}
	detail := ev.Dest + ", " + summarize(ev.Results)
	if ev.Remembered {
		detail += ", engines skipped (no path opened it lately)"
	}
	d.logOnly("unopened", host, detail)
}

// firstThisMinute reports whether key was not seen in the last minute, and
// marks it seen if so.
func (d *Daemon) firstThisMinute(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.flowSeen == nil {
		d.flowSeen = map[string]time.Time{}
	}
	recent := time.Since(d.flowSeen[key]) < time.Minute
	if !recent {
		d.flowSeen[key] = time.Now()
		if len(d.flowSeen) > 2000 {
			// Only entries from the last minute still dedupe anything; drop the rest,
			// and everything only if a minute really saw that many flows.
			for k, t := range d.flowSeen {
				if time.Since(t) >= time.Minute {
					delete(d.flowSeen, k)
				}
			}
			if len(d.flowSeen) > 2000 {
				d.flowSeen = map[string]time.Time{key: time.Now()}
			}
		}
	}
	return !recent
}

// summarize shortens per-attempt results ("read tcp a->b: connection reset by
// peer (63ms)") to "direct reset 63ms, tlsrec ok 101ms".
func summarize(results map[string]string) string {
	names := make([]string, 0, len(results))
	for n := range results {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { // direct first, then the ladder order is unknown here: by name
		return names[i] == "direct" || (names[j] != "direct" && names[i] < names[j])
	})
	parts := make([]string, 0, len(names))
	for _, n := range names {
		r := results[n]
		kind := "error"
		switch {
		case strings.HasPrefix(r, "ok"):
			kind = "ok"
		case strings.Contains(r, "reset"), strings.Contains(r, "forcibly closed"), strings.Contains(r, "aborted"):
			kind = "reset"
		case strings.Contains(r, "timeout") || strings.Contains(r, "deadline"):
			kind = "timeout"
		case strings.Contains(r, "refused"):
			kind = "refused"
		case strings.Contains(r, "EOF"):
			kind = "closed"
		case strings.Contains(r, "non-TLS"):
			kind = "injected"
		}
		took := ""
		if i := strings.LastIndex(r, "("); i >= 0 && strings.HasSuffix(r, ")") {
			took = " " + r[i+1:len(r)-1]
		} else if kind == "ok" {
			took = strings.TrimPrefix(r, "ok")
		}
		parts = append(parts, n+" "+kind+took)
	}
	return strings.Join(parts, ", ")
}

func (d *Daemon) candidateLoop(ctx context.Context) {
	for {
		select {
		case c := <-d.cands:
			d.judge(ctx, c)
		case <-ctx.Done():
			return
		}
	}
}

const (
	// judgeEvery is how long the same site is left alone after it was judged.
	judgeEvery = 5 * time.Minute
	// strikeTTL is how long one Suspect verdict waits for its second.
	strikeTTL = time.Hour
	// healthEvery is the time between health checks while the capture is up:
	// each one is a DoH query plus three TLS handshakes, two of them through
	// sing-box.
	healthEvery = 30 * time.Second
	// probeEvery is how often the active probe still runs while real traffic
	// through the capture shows it works (see watch).
	probeEvery = 5 * time.Minute
	// healthStale is how long a failed health check keeps validation off: a
	// little over one check period, since nothing re-checks sooner.
	healthStale = 90 * time.Second
	// maxJudged bounds the per-site memory.
	maxJudged = 2048
)

// judgment is what is remembered of one site (registrable domain) on one
// network between looks.
type judgment struct {
	at      time.Time // last look
	strikes int       // Suspect verdicts in a row
}

// judgeSlot arms the per-site wait and says whether site may be judged now.
func (d *Daemon) judgeSlot(id string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if j := d.judged[id]; j != nil && now.Sub(j.at) < judgeEvery {
		return false
	}
	if d.judged == nil {
		d.judged = map[string]*judgment{}
	}
	if len(d.judged) >= maxJudged && d.judged[id] == nil {
		pruneJudged(d.judged, now)
	}
	j := d.judged[id]
	if j == nil {
		j = &judgment{}
		d.judged[id] = j
	}
	if now.Sub(j.at) > strikeTTL {
		j.strikes = 0
	}
	j.at = now
	return true
}

// pruneJudged makes room in a full judged map without losing a pending second
// look: first the entries whose strikes have expired anyway, then those with
// no strike, and only if every site still waits on a strike, the oldest half.
func pruneJudged(m map[string]*judgment, now time.Time) {
	for k, j := range m {
		if now.Sub(j.at) > strikeTTL {
			delete(m, k)
		}
	}
	if len(m) < maxJudged {
		return
	}
	for k, j := range m {
		if j.strikes == 0 && now.Sub(j.at) >= judgeEvery {
			delete(m, k)
		}
	}
	if len(m) < maxJudged {
		return
	}
	ats := make([]time.Time, 0, len(m))
	for _, j := range m {
		ats = append(ats, j.at)
	}
	slices.SortFunc(ats, func(a, b time.Time) int { return a.Compare(b) })
	cut := ats[len(ats)/2]
	for k, j := range m {
		if j.at.Before(cut) {
			delete(m, k)
		}
	}
}

// strike records one more verdict for site and returns how many Suspect
// verdicts in a row it now has; any other verdict clears them.
func (d *Daemon) strike(id string, suspect bool) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	j := d.judged[id]
	if j == nil {
		return 0
	}
	if !suspect {
		j.strikes = 0
		return 0
	}
	j.strikes++
	return j.strikes
}

// judge is the one gate through which a connection that an engine had to repair
// can get its name onto the list: the network must be up and stable, the site
// not judged in the last judgeEvery, and the verdict comes from verdict.Check.
func (d *Daemon) judge(ctx context.Context, c candidate) {
	net := d.sys.network()
	if net.Key == "" || !net.Online {
		return
	}
	if _, listed := d.st.Match(net.Key, c.host); listed {
		return
	}
	site, ok := domain.Registrable(c.host)
	if !ok {
		return
	}
	// On an unstable network every failure looks like a block. Checked before
	// the wait is armed, so the host is judged once the network is back.
	if d.unstable() {
		d.logOnly("skipped", c.host, "health checks failing, not validating")
		return
	}
	id := net.Key + "|" + site
	if !d.judgeSlot(id, time.Now()) {
		return
	}
	v := d.sys.check(ctx, net.Key, c.host, []netip.Addr{c.ip}, false)
	if ctx.Err() != nil {
		return
	}
	d.logOnly("verdict", c.host, v.String())
	d.apply(net.Key, c.host, id, v, nil)
}

// apply is where a verdict changes the list. For a host that is not listed
// (judge) it decides whether to list it; for a listed entry being re-tested
// (retest != nil) whether it stays, moves to another engine or goes.
//
//	not listed  Blocked                 -> listed
//	            Suspect (first)         -> wait for a second look, 5 minutes on
//	            Suspect (second)        -> listed
//	            anything else           -> nothing (and the Suspect count resets)
//	listed      Clean                   -> removed on the second in a row
//	            Blocked, Suspect        -> kept; moves to an engine that works
//	            anything else           -> kept, the Clean count resets
func (d *Daemon) apply(key, host, id string, v verdict.Verdict, retest *store.Entry) {
	if retest != nil {
		d.applyRetest(key, *retest, v)
		return
	}
	switch v.Kind {
	case verdict.Blocked:
		d.strike(id, false)
		d.list(key, host, v.Engine)
	case verdict.Suspect:
		if n := d.strike(id, true); n >= 2 {
			d.logOnly("verdict", host, "blocked via "+v.Engine+" (silent twice, confirmed)")
			d.list(key, host, v.Engine)
		} else {
			d.logOnly("suspect", host, "direct attempts only timed out; listed if it happens again in "+judgeEvery.String()+" or more")
		}
	default:
		d.strike(id, false)
	}
}

// list adds a validated block to the network's list.
func (d *Daemon) list(key, host, engine string) {
	e := store.Entry{Domain: host, Host: host, Engine: engine, Source: store.SourceAuto}
	added, err := d.st.Add(key, e)
	if err != nil {
		// The network is unknown to the store: either the provisional key was
		// folded into the stable one meanwhile, or the capture has not touched
		// it yet. Either way the entry belongs to the network we are on.
		if cur := d.sys.network(); cur.Key != "" {
			if _, terr := d.st.Touch(cur.Key, cur.Label); terr == nil {
				added, err = d.st.Add(cur.Key, e)
			}
		}
	}
	switch {
	case err != nil:
		d.log.Error("list add", "host", host, "err", err)
	case added:
		d.note("listed", host, "engine "+engine)
	}
}

// check validates host on network key (the current one when it starts); a
// network change meanwhile turns the verdict into Unknown.
func (d *Daemon) check(ctx context.Context, key, host string, ips []netip.Addr, all bool) verdict.Verdict {
	v := *d.val
	v.Same = func() bool { return d.sys.network().Key == key }
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return v.Check(cctx, host, ips, all)
}

func (d *Daemon) retestLoop(ctx context.Context) {
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			d.retestAll(ctx)
			timer.Reset(time.Duration(d.cfg.RetestHours) * time.Hour)
		case <-ctx.Done():
			return
		}
	}
}

func (d *Daemon) retestAll(ctx context.Context) {
	if !d.running() {
		return
	}
	key := d.sys.network().Key
	for _, e := range d.st.List(key) {
		if e.Source == store.SourceManual {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d.retestGap):
		}
		if d.sys.network().Key != key {
			return // another network now: its probes say nothing about this list
		}
		if !d.running() {
			return // paused or released meanwhile: the engines may be down
		}
		d.retest(ctx, key, e)
	}
}

func (d *Daemon) retest(ctx context.Context, key string, e store.Entry) {
	// Probe the host that was seen blocked: a DPI that matches only that name
	// would let the bare domain through and the entry would flap.
	host := e.Host
	if host == "" {
		host = e.Domain
	}
	// Stop at the first engine that opens it: when the entry's own engine is the
	// first that works nothing changes, otherwise the entry moves to that one.
	// Trying every engine each round cost two extra handshakes per entry.
	v := d.sys.check(ctx, key, host, nil, false)
	if ctx.Err() != nil {
		return
	}
	d.apply(key, host, "", v, &e)
}

// applyRetest acts on a re-test verdict. The entry is read again under the
// store's lock, so a manual entry added or pinned while the probes ran is never
// touched, and a clean count never outlives a round that was not clean.
func (d *Daemon) applyRetest(key string, probed store.Entry, v verdict.Verdict) {
	now := time.Now()
	var note func()
	_, _, err := d.st.Edit(key, probed.Domain, func(cur *store.Entry) bool {
		if cur.Source == store.SourceManual {
			return false
		}
		switch v.Kind {
		case verdict.Clean:
			if cur.OK+1 >= 2 {
				note = func() { d.note("removed", probed.Domain, "real path works again") }
				return true
			}
			cur.OK, cur.Checked = cur.OK+1, now
		case verdict.Blocked, verdict.Suspect: // already listed: timeout-only still keeps the entry alive
			engine := cur.Engine
			if engine == "" {
				engine = d.engines[0].Name
			}
			switched := !strings.HasPrefix(v.Engines[engine], "ok") // its engine stopped working: move to one that does
			cur.OK, cur.Checked = 0, now
			if cur.Engine == "" || switched {
				cur.Engine = v.Engine
			}
			if switched {
				note = func() { d.note("engine", probed.Domain, engine+" no longer opens it, now "+v.Engine) }
			} else {
				note = func() { d.logOnly("confirmed", probed.Domain, "engine "+engine) }
			}
		default:
			cur.OK, cur.Checked = 0, now
		}
		return false
	})
	if err != nil {
		d.log.Error("retest update", "domain", probed.Domain, "err", err)
	}
	if note != nil {
		note()
	}
}

var errNoNetwork = errors.New("no network identified yet")

// killStale ends helpers a previous daemon left behind (an orphaned sing-box
// would hold the TUN and our ports). Only this install's binaries are
// matched, and no other daemon is alive: the control socket was checked.
func killStale(b embedded.Bins, log *slog.Logger) {
	for _, path := range sysx.KillByPath(b.SingBox, b.Ciadpi) {
		log.Warn("killed leftover helper processes", "bin", path)
	}
}
