// Package observer is the local SOCKS5 endpoint sing-box hands unlisted
// TCP/443 flows to. It reads the client's TLS ClientHello, tries the real path
// first and, when the server never answers (reset, drop, injected junk),
// replays the very same ClientHello through the bypass engines so even the
// first connection opens. What it saw is reported as Events.
package observer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/hoststate"
	"github.com/Shuushi0/AutoDPI/internal/netx"
	"github.com/Shuushi0/AutoDPI/internal/probe"
	"github.com/Shuushi0/AutoDPI/internal/sni"
	"github.com/Shuushi0/AutoDPI/internal/socks"
)

// Engine is a local SOCKS5 endpoint that applies a DPI-evasion technique.
type Engine struct {
	Name string
	Addr string
}

type Outcome string

const (
	Direct   Outcome = "direct"   // the real path delivered
	Fallback Outcome = "fallback" // real path failed, an engine delivered
	// Failed means nothing delivered. It is reported only for a name that was in
	// Light mode (so its owner can take it out of that mode); any other flow no
	// path could open is neither reported nor counted, see Options.DeadTTL.
	Failed      Outcome = "failed"
	Passthrough Outcome = "passthrough" // not observed (not TLS, or no first flight)
)

// Mode is how a flow is handled; see Options.Mode.
type Mode int

const (
	Full  Mode = iota // direct first, hedge to the engines, report an Event
	Light             // direct only, until it fails
)

type Event struct {
	Time    time.Time
	SNI     string
	Dest    string // ip:port the client asked for
	Asked   string // destination host exactly as the SOCKS client sent it
	Outcome Outcome
	Engine  string // winning engine when Outcome is Fallback
	// Blocked says the direct attempt was reset or answered with something
	// that is not TLS, which is what a DPI does. A Fallback without it is an
	// engine that won while the direct attempt was merely slow (the hedge) or
	// failed in another way: an engine delivered, but nothing was repaired.
	Blocked bool
	// Results is each attempt's outcome by name. It is nil for a flow the direct
	// attempt alone served.
	Results map[string]string
	// Remembered marks an Unopened flow that got no engines because no path
	// opened its destination lately (Options.DeadTTL).
	Remembered bool
	Took       time.Duration
}

type Options struct {
	Engines func() []Engine
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	Events  func(Event)
	// Unopened is told about each flow nothing delivered, with its Results. Such
	// flows are no Event and no count; this is for the log, the one place that
	// can show why a site does not open. It runs on the flow's goroutine.
	Unopened       func(Event)
	Ports          []int
	HelloWait      time.Duration // how long to wait for the client's first flight
	ConnectTimeout time.Duration
	FirstByte      time.Duration // per attempt, time to the first server byte
	Hedge          time.Duration // start the next engine alongside a slow attempt
	// EscalateOnSilence opens the whole ladder without DPI evidence: each hedge
	// tick starts the next engine (config escalate_on_silence).
	EscalateOnSilence bool
	// Mode says how a flow to this server name (lower-case SNI) is handled.
	// Light dials the server directly and relays: no hedge timer, no engine
	// attempts, no Event. It is for names the daemon has seen open directly
	// again and again. If that one attempt fails before the first server byte
	// the very same ClientHello continues on the full path (engines at once)
	// and the flow's Event reports it, which is how the daemon learns the name
	// is no longer open. A nil Mode means Full for everything.
	Mode func(sni string) Mode
	// DeadTTL is how long a destination (SNI plus ip:port) that no path could
	// open is remembered: the direct attempt and an engine that did reach the
	// server all failed, and not just by running out of time. Such a destination
	// is then only tried directly, with no engine attempts and no Event, until
	// the entry expires or the direct attempt works again. Zero means 10 minutes,
	// a negative value turns the cache off. Failures that prove nothing about the
	// server (no engine configured, engine down, racing cap, timeouts) are never
	// remembered, so a bypass that is only temporarily unavailable costs nothing.
	DeadTTL time.Duration
	// MaxRacing caps concurrent flows per destination that have escalated to the
	// engines. A flow that loops back into the observer (an engine's own traffic
	// recaptured by the TUN) would otherwise multiply without bound. Flows the
	// direct attempt serves never count.
	MaxRacing int
	Log       *slog.Logger

	// AllowLoopback lets flows target 127.0.0.0/8. Loopback is never a valid
	// destination in production (sing-box keeps it direct); loopback test rigs
	// need it.
	AllowLoopback bool
}

// Stats counts flows. Flows no path could open are not counted: like their
// events, they carry nothing worth showing.
type Stats struct {
	Conns, Direct, Fallback, Passthrough int64
}

type Observer struct {
	opt    Options
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	ln     net.Listener
	racing map[string]int
	capped atomic.Int64
	dead   *hoststate.Dead // nil when DeadTTL < 0
	// deadGen counts ForgetDead calls: a flow that began under an earlier one
	// failed on another network and must not be remembered. Changed under mu.
	deadGen atomic.Uint64

	evOnce    sync.Once
	evq       chan Event
	evDropped atomic.Int64

	total, direct, fallback, pass atomic.Int64
}

func New(o Options) *Observer {
	if o.HelloWait == 0 {
		o.HelloWait = 2 * time.Second
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = 5 * time.Second
	}
	if o.FirstByte == 0 {
		o.FirstByte = 6 * time.Second
	}
	if o.Hedge == 0 {
		o.Hedge = 1200 * time.Millisecond
	}
	if o.MaxRacing == 0 {
		o.MaxRacing = 48
	}
	if o.DeadTTL == 0 {
		o.DeadTTL = 10 * time.Minute
	}
	if len(o.Ports) == 0 {
		o.Ports = []int{443}
	}
	if o.Engines == nil {
		o.Engines = func() []Engine { return nil }
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	ctx, cancel := context.WithCancel(context.Background())
	ob := &Observer{opt: o, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}, racing: map[string]int{}}
	if o.DeadTTL > 0 {
		ob.dead = hoststate.NewDead(o.DeadTTL, 1024)
	}
	return ob
}

// ForgetDead empties the negative cache (the network changed, so what failed
// there says nothing about here) and returns how many destinations it held.
func (o *Observer) ForgetDead() int {
	if o.dead == nil {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.deadGen.Add(1)
	return o.dead.Reset()
}

// rememberDead adds key unless the cache was emptied since the flow began (gen).
func (o *Observer) rememberDead(key hoststate.DeadKey, gen uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.deadGen.Load() == gen {
		o.dead.Add(key)
	}
}

func (o *Observer) unopened(e Event) {
	if o.opt.Unopened != nil && o.ctx.Err() == nil {
		o.opt.Unopened(e)
	}
}

// DeadLen is the number of destinations currently in the negative cache.
func (o *Observer) DeadLen() int {
	if o.dead == nil {
		return 0
	}
	return o.dead.Len()
}

func (o *Observer) Stats() Stats {
	return Stats{
		Conns: o.total.Load(), Direct: o.direct.Load(), Fallback: o.fallback.Load(),
		Passthrough: o.pass.Load(),
	}
}

// Serve accepts connections until the listener closes.
func (o *Observer) Serve(ln net.Listener) error {
	o.mu.Lock()
	if o.ctx.Err() != nil { // Close came first and could not close ln
		o.mu.Unlock()
		ln.Close()
		return nil
	}
	o.ln = ln
	o.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			if o.ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		o.mu.Lock()
		if o.ctx.Err() != nil { // Close is (or will be) waiting: add nothing
			o.mu.Unlock()
			c.Close()
			return nil
		}
		o.wg.Add(1)
		o.mu.Unlock()
		go func() {
			defer o.wg.Done()
			o.handle(c)
		}()
	}
}

// Close stops accepting, tears down live flows and waits for them.
func (o *Observer) Close() {
	o.mu.Lock()
	o.cancel()
	if o.ln != nil {
		o.ln.Close()
	}
	for c := range o.conns {
		c.Close()
	}
	o.mu.Unlock()
	o.wg.Wait()
}

func (o *Observer) track(c net.Conn) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ctx.Err() != nil {
		return false
	}
	o.conns[c] = struct{}{}
	return true
}

func (o *Observer) untrack(c net.Conn) {
	o.mu.Lock()
	delete(o.conns, c)
	o.mu.Unlock()
}

func (o *Observer) allowed(port int) bool {
	for _, p := range o.opt.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// emit hands e to the Events callback on a goroutine of its own, so a slow or
// stuck callback never holds up a flow (or Close). Events are dropped, with a
// warning, when the callback falls 256 behind; pending ones are dropped on Close.
func (o *Observer) emit(e Event) {
	if o.opt.Events == nil {
		return
	}
	o.evOnce.Do(func() {
		o.evq = make(chan Event, 256)
		go func() {
			for {
				select {
				case e := <-o.evq:
					o.opt.Events(e)
				case <-o.ctx.Done():
					return
				}
			}
		}()
	})
	select {
	case o.evq <- e:
	default:
		if n := o.evDropped.Add(1); n == 1 || n%1000 == 0 {
			o.opt.Log.Warn("event consumer is falling behind; dropping events", "dropped", n)
		}
	}
}

func (o *Observer) handle(raw net.Conn) {
	if !o.track(raw) {
		raw.Close()
		return
	}
	defer o.untrack(raw)
	defer raw.Close()
	o.total.Add(1)

	c, req, err := socks.Accept(raw)
	if err != nil {
		return
	}
	if !o.allowed(req.Port) {
		_ = socks.Reply(c, socks.RepNotAllowed)
		return
	}
	ip, isIP := req.IP()
	if !isIP {
		// Resolve ourselves: handing a name to an engine would send it through
		// the (possibly poisoned) system resolver.
		if o.opt.Resolve == nil {
			_ = socks.Reply(c, socks.RepHostUnreachable)
			return
		}
		ctx, cancel := context.WithTimeout(o.ctx, 5*time.Second)
		ips, err := o.opt.Resolve(ctx, req.Host)
		cancel()
		if err != nil || len(ips) == 0 {
			_ = socks.Reply(c, socks.RepHostUnreachable)
			return
		}
		ip = ips[0]
	}
	ip = ip.Unmap()
	if netx.Unroutable(ip) && !(o.opt.AllowLoopback && ip.IsLoopback()) {
		_ = socks.Reply(c, socks.RepNotAllowed)
		return
	}
	dest := netip.AddrPortFrom(ip, uint16(req.Port)).String()

	// Answer now: the client will not send its ClientHello before it believes
	// the tunnel is up, and we need that ClientHello to decide anything.
	if err := socks.Reply(c, socks.RepOK); err != nil {
		return
	}

	first, isTLS, err := sni.ReadFirstFlight(c, o.opt.HelloWait)
	if len(first) == 0 && err != nil {
		// A silent client may be waiting for a server-first protocol, and one
		// that half-closed without sending still wants the server's answer:
		// just relay. Any other error means the client is already gone.
		var ne net.Error
		if errors.Is(err, io.EOF) || (errors.As(err, &ne) && ne.Timeout()) {
			o.passthrough(c, dest, nil)
		}
		return
	}
	if err != nil && isTLS {
		return // client died mid-ClientHello
	}
	if !isTLS {
		o.passthrough(c, dest, first)
		return
	}
	name, _ := sni.Parse(first)
	o.observe(c, dest, req.Host, ip, req.Port, name, first)
}

func (o *Observer) passthrough(c net.Conn, dest string, first []byte) {
	o.pass.Add(1)
	ctx, cancel := context.WithTimeout(o.ctx, o.opt.ConnectTimeout)
	up, err := o.opt.Dial(ctx, "tcp", dest)
	cancel()
	if err != nil {
		return
	}
	defer up.Close()
	if len(first) > 0 {
		if _, err := up.Write(first); err != nil {
			return
		}
	}
	relay(c, up)
}

type attempt struct {
	name  string
	conn  net.Conn
	first []byte // the server's first bytes; aliases buf
	buf   *[]byte
	err   error
	took  time.Duration
	// connected: the dial succeeded, so what failed afterwards was the server (or
	// the path through it), not our ability to reach it. For an engine that means
	// the engine itself opened the connection upstream.
	connected bool
}

// release returns the read buffer to the pool; first is invalid afterwards.
func (a *attempt) release() {
	if a.buf != nil {
		helloBufPool.Put(a.buf)
		a.buf, a.first = nil, nil
	}
}

var helloBufPool = sync.Pool{New: func() any { b := make([]byte, 16<<10); return &b }}

// enter claims a racing slot for dest; false means the cap is reached.
func (o *Observer) enter(dest string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.racing[dest] >= o.opt.MaxRacing {
		return false
	}
	o.racing[dest]++
	return true
}

func (o *Observer) leave(dest string) {
	o.mu.Lock()
	if o.racing[dest]--; o.racing[dest] <= 0 {
		delete(o.racing, dest)
	}
	o.mu.Unlock()
}

// light is the open-name path: dial direct, send the ClientHello, relay. It
// reports whether the flow is finished; otherwise the direct attempt failed
// and its result is returned for the full path to build on.
func (o *Observer) light(c net.Conn, dest string, hello []byte, opened func()) (done bool, failed *outcome) {
	a := o.try(o.ctx, "direct", func(ctx context.Context) (net.Conn, error) { return o.opt.Dial(ctx, "tcp", dest) }, hello)
	if a.err != nil {
		if o.ctx.Err() != nil {
			return true, nil
		}
		return false, &outcome{name: "direct", err: a.err, took: a.took, connected: a.connected}
	}
	o.direct.Add(1)
	if opened != nil {
		opened()
	}
	defer a.conn.Close()
	_, werr := c.Write(a.first)
	a.release()
	if werr != nil {
		return true, nil
	}
	relay(c, a.conn)
	return true, nil
}

// outcome is one failed attempt, kept as is until a report is needed.
type outcome struct {
	name      string
	err       error
	took      time.Duration
	connected bool
}

// String is the attempt's error and duration for the journal. A reset is
// named as one even where Windows words it in another language, so the
// daemon's summary still reads it as a reset.
func (f outcome) String() string {
	msg := fmt.Sprint(f.err)
	if probe.IsReset(f.err) && !strings.Contains(msg, "reset") {
		msg = "connection reset: " + msg
	}
	return fmt.Sprintf("%s (%dms)", msg, f.took.Milliseconds())
}

// directEvidence is blockEvidence for the direct attempt, which also counts a
// clean close (EOF) before the server's first byte: some DPI boxes end a flow
// with a FIN instead of a reset, and probe.classify reads it the same way. An
// engine's EOF is left out: it may be the engine's own upstream giving up.
func directEvidence(err error) bool {
	return blockEvidence(err) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// blockEvidence reports whether a failed attempt looks like what a DPI does:
// the connection was reset, or answered with something that is not TLS.
// Silence and timeouts are also what a stalled link produces.
func blockEvidence(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errInjected) || probe.IsReset(err) {
		return true
	}
	// The code can be lost on the way (an error rebuilt from text); the
	// English messages of macOS and Go are the fallback.
	msg := err.Error()
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "forcibly closed")
}

func (o *Observer) observe(c net.Conn, dest, asked string, ip netip.Addr, port int, name string, hello []byte) {
	t0 := time.Now()
	gen := o.deadGen.Load()
	key := hoststate.DeadKey{Host: name, Dest: dest}
	if o.dead != nil && o.dead.Has(key) {
		// No path opened this destination lately: one direct attempt, nothing
		// else. If it works the server recovered and the entry goes.
		if _, failed := o.light(c, dest, hello, func() { o.dead.Forget(key) }); failed != nil {
			o.unopened(Event{Time: t0, SNI: name, Dest: dest, Asked: asked, Remembered: true,
				Blocked: directEvidence(failed.err), Results: map[string]string{"direct": failed.String()}, Took: time.Since(t0)})
		}
		return
	}
	var directFailed *outcome
	if name != "" && o.opt.Mode != nil && o.opt.Mode(name) == Light {
		var done bool
		if done, directFailed = o.light(c, dest, hello, nil); done {
			return
		}
	}
	win, results, rejected, blocked := o.race(dest, ip, port, hello, directFailed)
	if win == nil {
		if rejected && o.dead != nil && o.ctx.Err() == nil {
			o.rememberDead(key, gen)
		}
		o.unopened(Event{Time: t0, SNI: name, Dest: dest, Asked: asked, Blocked: blocked, Results: results, Took: time.Since(t0)})
		// Nothing delivered: no event, no count. The one exception is a name that
		// was in light mode, whose owner has to learn it is not open any more.
		if directFailed != nil {
			o.emit(Event{Time: t0, SNI: name, Dest: dest, Asked: asked, Outcome: Failed, Took: time.Since(t0)})
		}
		return
	}

	ev := Event{Time: t0, SNI: name, Dest: dest, Asked: asked, Results: results, Took: time.Since(t0), Blocked: blocked}
	if win.name == "direct" {
		ev.Outcome = Direct
		o.direct.Add(1)
	} else {
		ev.Outcome, ev.Engine = Fallback, win.name
		o.fallback.Add(1)
	}
	if o.opt.Log.Enabled(o.ctx, slog.LevelDebug) {
		o.opt.Log.Debug("observed", "sni", name, "dest", dest, "outcome", ev.Outcome, "engine", ev.Engine, "results", results)
	}
	o.emit(ev)
	defer win.conn.Close()
	_, werr := c.Write(win.first)
	win.release()
	if werr != nil {
		return
	}
	relay(c, win.conn)
}

// race starts the direct attempt, then escalates through the engines: at once
// when an attempt fails, or after Hedge when one is merely slow. The first
// attempt that yields server bytes wins and the rest are torn down. A non-nil
// directFailed means the direct attempt was already made (an open name that
// stopped working): it counts as is and the engines start at once.
//
// Only DPI evidence (a reset or an injected reply, on any attempt) opens the
// whole ladder. Without it the flow gets one engine: a stalled link or server
// times out on every path, and trying every engine against it only multiplies
// the wait and the traffic.
//
// When nothing delivered, the report holds only the failures. rejected says the
// server itself turned the flow away: some engine opened the connection upstream, sent
// the ClientHello and was answered by a reset, a close or junk, not by silence.
// That, unlike "no engine configured", "engine down", a full racing cap or a
// plain timeout, is proof that no path will open this destination for now.
// blocked says the direct attempt failed with DPI evidence (Event.Blocked).
//
// The first escalation takes one of the destination's racing slots (held until
// the race ends); with none free the flow goes on without engines.
func (o *Observer) race(dest string, ip netip.Addr, port int, hello []byte, directFailed *outcome) (win *attempt, report map[string]string, rejected, blocked bool) {
	ctx, cancel := context.WithCancel(o.ctx)
	defer cancel()

	var failures []outcome // attempts that failed
	evidence := false
	// Room for the direct attempt and every engine of any ladder (five at most).
	results := make(chan *attempt, 8)
	launched, received, next := 0, 0, 0
	var engines []Engine
	fetched, slot, capped := false, false, false
	defer func() {
		if slot {
			o.leave(dest)
		}
	}()

	start := func(name string, dial func(context.Context) (net.Conn, error)) {
		launched++
		go func() { results <- o.try(ctx, name, dial, hello) }()
	}
	escalate := func() {
		if !fetched {
			engines, fetched = o.opt.Engines(), true
		}
		if next >= len(engines) || launched >= cap(results) || capped || (next >= 1 && !evidence && !o.opt.EscalateOnSilence) {
			return
		}
		if !slot {
			if slot = o.enter(dest); !slot {
				capped = true
				if n := o.capped.Add(1); n == 1 || n%100 == 0 {
					o.opt.Log.Warn("racing cap reached for one destination: possible routing loop; not using engines", "dest", dest, "times", n)
				}
				return
			}
		}
		e := engines[next]
		next++
		start(e.Name, func(ctx context.Context) (net.Conn, error) {
			return socks.Dial(ctx, nil, e.Addr, ip.String(), port)
		})
	}
	fail := func(f outcome) {
		failures = append(failures, f)
		ev := blockEvidence(f.err)
		if f.name == "direct" {
			ev = directEvidence(f.err)
			blocked = blocked || ev
		}
		evidence = evidence || ev
		if f.name != "direct" && f.connected && !isTimeout(f.err) {
			rejected = true
		}
	}
	if directFailed != nil {
		fail(*directFailed)
		escalate()
	} else {
		start("direct", func(ctx context.Context) (net.Conn, error) { return o.opt.Dial(ctx, "tcp", dest) })
	}

	hedge := time.NewTimer(o.opt.Hedge)
	defer hedge.Stop()

loop:
	for received < launched {
		select {
		case a := <-results:
			received++
			if a.err == nil {
				win = a
				break loop
			}
			fail(outcome{name: a.name, err: a.err, took: a.took, connected: a.connected})
			escalate()
		case <-hedge.C:
			escalate()
			hedge.Reset(o.opt.Hedge)
		case <-o.ctx.Done():
			break loop
		}
	}
	cancel()
	if pending := launched - received; pending > 0 {
		go func() {
			for i := 0; i < pending; i++ {
				if a := <-results; a.conn != nil {
					a.conn.Close()
					a.release()
				}
			}
		}()
	}
	if win != nil && len(failures) == 0 && win.name == "direct" {
		return win, nil, false, false // served by the direct attempt alone: nothing to report
	}
	report = make(map[string]string, len(failures)+1)
	for _, f := range failures {
		report[f.name] = f.String()
	}
	if win == nil {
		return nil, report, rejected, blocked
	}
	report[win.name] = fmt.Sprintf("ok %dms", win.took.Milliseconds())
	return win, report, false, blocked
}

var errInjected = errors.New("non-TLS reply to ClientHello")

// isTimeout reports whether err is silence (a deadline) rather than an answer.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.ErrNoProgress) || (errors.As(err, &ne) && ne.Timeout())
}

// tlsPrefix reports whether b (at least one byte) can still be the start of a
// TLS handshake or alert record.
func tlsPrefix(b []byte) bool {
	return (b[0] == 0x16 || b[0] == 0x15) && (len(b) < 2 || b[1] == 0x03)
}

// try dials, sends the ClientHello and waits for the first server bytes. On
// success the returned attempt owns an open conn with deadlines cleared and a
// pooled buffer holding the bytes (release it when they are written).
func (o *Observer) try(ctx context.Context, name string, dial func(context.Context) (net.Conn, error), hello []byte) *attempt {
	t0 := time.Now()
	a := &attempt{name: name}
	fail := func(err error) *attempt {
		a.err, a.took = err, time.Since(t0)
		if a.conn != nil {
			a.conn.Close()
			a.conn = nil
		}
		a.release()
		return a
	}

	dctx, cancel := context.WithTimeout(ctx, o.opt.ConnectTimeout)
	conn, err := dial(dctx)
	cancel()
	if err != nil {
		return fail(err)
	}
	a.conn, a.connected = conn, true
	// Cancelling the race must unblock the I/O below.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(hello); err != nil {
		return fail(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(o.opt.FirstByte))
	a.buf = helloBufPool.Get().(*[]byte)
	buf := *a.buf
	// A real server answers a ClientHello with a handshake record or an alert.
	// Judge only once a whole record header (5 bytes) is in: the first segment
	// may be shorter, and a valid prefix is not a reason to give up.
	n := 0
	for idle := 0; n < 5; {
		m, err := conn.Read(buf[n:])
		n += m
		if n > 0 && !tlsPrefix(buf[:n]) {
			return fail(errInjected)
		}
		if n >= 5 {
			break
		}
		if err != nil {
			return fail(err)
		}
		if m == 0 {
			if idle++; idle >= 100 {
				return fail(io.ErrNoProgress)
			}
		}
	}
	if !stop() {
		// The race was cancelled under us: the deadline poison may have landed.
		return fail(context.Canceled)
	}
	_ = conn.SetDeadline(time.Time{})
	a.first, a.took = buf[:n], time.Since(t0)
	return a
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	c.Close()
}

// bufPool holds relay buffers, two per live flow for its whole life (idle
// HTTP/2 and WebSocket flows included), so their size multiplies by the flow
// count. 16 KiB matches the largest TLS record: a bigger buffer only adds
// memory, since a read rarely returns more than one record's worth anyway.
var bufPool = sync.Pool{New: func() any { b := make([]byte, 16<<10); return &b }}

// relay shuttles bytes both ways. A clean EOF half-closes the other side; an
// error tears both down.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		bp := bufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(dst, src, *bp)
		bufPool.Put(bp)
		if err != nil {
			a.Close()
			b.Close()
			return
		}
		closeWrite(dst)
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
