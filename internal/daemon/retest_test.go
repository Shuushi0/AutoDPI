//go:build !windows

package daemon

import (
	"context"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
	"github.com/Shuushi0/AutoDPI/internal/store"
	"github.com/Shuushi0/AutoDPI/internal/verdict"
)

func ruleSet(t *testing.T, d *Daemon, engine string) string {
	t.Helper()
	b, err := os.ReadFile(singbox.RuleSetPath(d.p.Run, engine))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func entry(t *testing.T, d *Daemon, key, dom string) (store.Entry, bool) {
	t.Helper()
	for _, e := range d.st.List(key) {
		if e.Domain == dom {
			return e, true
		}
	}
	return store.Entry{}, false
}

// The re-test notices that an entry's engine stopped opening it and moves it
// to one that does; sing-box only learns that through the rule-set files.
func TestRetestEngineSwitchReachesRuleSets(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	_, _ = d.st.Add("asn:15897", store.Entry{Domain: "discord.com", Engine: "tlsrec", Source: store.SourceAuto})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.storeLoop(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(ruleSet(t, d, "tlsrec"), `"discord.com"`) {
		if time.Now().After(deadline) {
			t.Fatal("entry not routed through its engine")
		}
		time.Sleep(50 * time.Millisecond)
	}
	f.set(func(f *fakeSys) {
		f.checkFn = func(string, string) verdict.Verdict {
			return verdict.Verdict{Kind: verdict.Blocked, Engine: "ciadpi", Engines: map[string]string{"tlsrec": "reset", "ciadpi": "ok"}}
		}
	})
	e, _ := entry(t, d, "asn:15897", "discord.com")
	d.retest(ctx, "asn:15897", e)
	if e, _ := entry(t, d, "asn:15897", "discord.com"); e.Engine != "ciadpi" || e.Source != store.SourceAuto {
		t.Fatalf("entry after re-test: %+v", e)
	}
	deadline = time.Now().Add(3 * time.Second)
	for !strings.Contains(ruleSet(t, d, "ciadpi"), `"discord.com"`) {
		if time.Now().After(deadline) {
			t.Fatalf("rule-sets still route discord.com through the broken engine:\ntlsrec: %s\nciadpi: %s", ruleSet(t, d, "tlsrec"), ruleSet(t, d, "ciadpi"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if strings.Contains(ruleSet(t, d, "tlsrec"), `"discord.com"`) {
		t.Fatal("discord.com left in the broken engine's rule-set")
	}
}

func TestRetestCleanRules(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	key := "asn:15897"
	_, _ = d.st.Add(key, store.Entry{Domain: "learned.example.net", Source: store.SourceAuto})
	_, _ = d.st.Add(key, store.Entry{Domain: "mine.example.org", Source: store.SourceManual})
	f.set(func(f *fakeSys) {
		f.checkFn = func(string, string) verdict.Verdict { return verdict.Verdict{Kind: verdict.Clean} }
	})
	ctx := context.Background()

	learned, _ := entry(t, d, key, "example.net")
	d.retest(ctx, key, learned)
	if e, ok := entry(t, d, key, "example.net"); !ok || e.OK != 1 {
		t.Fatalf("an entry needs two clean rounds: %+v %v", e, ok)
	}
	learned, _ = entry(t, d, key, "example.net")
	d.retest(ctx, key, learned)
	if _, ok := entry(t, d, key, "example.net"); ok {
		t.Fatal("entry kept after two clean rounds")
	}

	// A blocked round in between resets the count.
	_, _ = d.st.Add(key, store.Entry{Domain: "flappy.example.com", Source: store.SourceAuto})
	e, _ := entry(t, d, key, "example.com")
	d.retest(ctx, key, e)
	f.set(func(f *fakeSys) {
		f.checkFn = func(string, string) verdict.Verdict {
			return verdict.Verdict{Kind: verdict.Blocked, Engine: "tlsrec", Engines: map[string]string{"tlsrec": "ok"}}
		}
	})
	e, _ = entry(t, d, key, "example.com")
	d.retest(ctx, key, e)
	if e, _ := entry(t, d, key, "example.com"); e.OK != 0 {
		t.Fatalf("blocked round did not reset the clean count: %+v", e)
	}

	// Manual entries are never re-tested.
	f.set(func(f *fakeSys) { f.checks = nil })
	d.retestGap = time.Millisecond
	d.retestAll(ctx)
	if slices.Contains(f.get().checks, "mine.example.org") {
		t.Fatal("manual entry re-tested")
	}
}

// The re-test walks the list of the network it started on. If the Mac moves
// to another network meanwhile, what it measures belongs to the new one: the
// old list must not be judged by it (and probing on is wasted traffic).
func TestRetestStopsWhenNetworkChanges(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	d.retestGap = time.Millisecond
	old := "asn:15897"
	f.set(func(f *fakeSys) {
		f.checkFn = func(key, host string) verdict.Verdict {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.net.Key == old {
				// The first probe runs while the Mac switches to a network
				// where nothing is blocked.
				f.net = netid.Info{Key: "asn:9121", Label: "AS9121", Online: true}
				return verdict.Verdict{Kind: verdict.Unknown}
			}
			if key != f.net.Key { // what the real check (Same) reports
				return verdict.Verdict{Kind: verdict.Unknown}
			}
			return verdict.Verdict{Kind: verdict.Clean}
		}
	})
	_, _ = d.st.Add(old, store.Entry{Domain: "learned.example.net", Source: store.SourceAuto})
	_, _ = d.st.Add(old, store.Entry{Domain: "also.example.org", Source: store.SourceAuto})
	before := len(d.st.List(old))
	d.retestAll(context.Background())
	if n := len(d.st.List(old)); n != before {
		t.Fatalf("old network's list shrank from %d to %d entries after a network change", before, n)
	}
	if n := len(f.get().checks); n != 1 {
		t.Fatalf("kept probing the old network's list on the new network: %d checks %v", n, f.get().checks)
	}
}

func hasNetwork(d *Daemon, key string) bool {
	for _, n := range d.st.Networks() {
		if n.Key == key {
			return true
		}
	}
	return false
}

// A provisional (gateway) key is folded into the stable one only when the
// stable key identifies that same attachment. Leaving network A while its AS
// lookup is still pending (or failed for good) for an already known network B
// must not merge A's list into B's.
func TestNetChangeFoldsOnlyTheSameNetwork(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	_, _ = d.st.Touch("gw:aaaa", "en0 via 172.20.10.1")
	_, _ = d.st.Add("gw:aaaa", store.Entry{Domain: "learned.example.net", Source: store.SourceAuto})
	_, _ = d.st.Touch("asn:9121", "AS9121")

	a := netid.Info{Key: "gw:aaaa", Provisional: true, Online: true, GatewayKey: "gw:aaaa"}
	b := netid.Info{Key: "asn:9121", Online: true, GatewayKey: "gw:bbbb"} // known network, from the cache
	d.onNetChange(a, b)
	if _, ok := d.st.Match("asn:9121", "learned.example.net"); ok {
		t.Fatal("network A's entry was merged into unrelated network B")
	}
	if _, ok := d.st.Match("gw:aaaa", "learned.example.net"); !ok {
		t.Fatal("network A's provisional list was lost")
	}

	// A identified at last: its own stable key takes the list over.
	aID := netid.Info{Key: "asn:15897", Online: true, GatewayKey: "gw:aaaa"}
	d.onNetChange(a, aID)
	if _, ok := d.st.Match("asn:15897", "learned.example.net"); !ok || hasNetwork(d, "gw:aaaa") {
		t.Fatal("provisional list not folded into its own stable key")
	}
}

// What was added while the capture stood by (paused, another VPN) under a
// provisional key must follow the network to its stable key too.
func TestNetChangeFoldsWhileStandingBy(t *testing.T) {
	d, _ := rig(t, Options{})
	_, _ = d.st.Touch("gw:aaaa", "")
	_, _ = d.st.Add("gw:aaaa", store.Entry{Domain: "mine.example.org", Source: store.SourceManual})
	if d.running() {
		t.Fatal("rig should start idle")
	}
	d.onNetChange(netid.Info{Key: "gw:aaaa", Provisional: true, GatewayKey: "gw:aaaa"},
		netid.Info{Key: "asn:9121", GatewayKey: "gw:aaaa"})
	if e, ok := d.st.Match("asn:9121", "mine.example.org"); !ok || e.Source != store.SourceManual {
		t.Fatal("manual entry stranded under the provisional key")
	}
}

// Every named flow an engine delivered is judged; only one whose direct
// attempt was blocked (a reset, an injected reply) is journalled as repaired.
// An engine that won the hedge against a slow direct attempt repaired nothing.
func TestOnEventQueuesEngineFlowsAndJournalsOnlyRepairs(t *testing.T) {
	d, _ := rig(t, Options{})
	d.cands = make(chan candidate, 4)
	d.onEvent(observer.Event{SNI: "a.example.net", Dest: "203.0.113.1:443", Outcome: observer.Direct})
	d.onEvent(observer.Event{SNI: "b.example.net", Dest: "203.0.113.1:443", Outcome: observer.Failed, Results: map[string]string{"direct": "reset (5ms)"}})
	d.onEvent(observer.Event{SNI: "", Dest: "203.0.113.1:443", Outcome: observer.Fallback, Engine: "tlsrec", Blocked: true})
	d.onEvent(observer.Event{SNI: "c.example.net", Dest: "203.0.113.1:443", Outcome: observer.Fallback, Engine: "tlsrec", Blocked: true})
	d.onEvent(observer.Event{SNI: "h.example.net", Dest: "203.0.113.2:443", Outcome: observer.Fallback, Engine: "tlsrec"})
	if len(d.cands) != 2 {
		t.Fatalf("%d candidates queued, want the two engine flows with an SNI", len(d.cands))
	}
	if c := <-d.cands; c.host != "c.example.net" || c.engine != "tlsrec" || c.ip.String() != "203.0.113.1" {
		t.Fatalf("candidate %+v", c)
	}
	if c := <-d.cands; c.host != "h.example.net" {
		t.Fatalf("hedge win not judged: %+v", c)
	}
	// Journal: one line per host and kind per minute, and none for a failed
	// flow or a hedge win.
	for i := 0; i < 5; i++ {
		d.onEvent(observer.Event{SNI: "b.example.net", Dest: "203.0.113.1:443", Outcome: observer.Failed})
		d.onEvent(observer.Event{SNI: "c.example.net", Dest: "203.0.113.1:443", Outcome: observer.Fallback, Engine: "tlsrec", Blocked: true})
		d.onEvent(observer.Event{SNI: "h.example.net", Dest: "203.0.113.2:443", Outcome: observer.Fallback, Engine: "tlsrec"})
	}
	var failed, repaired, hedged int
	for _, j := range d.journal {
		switch {
		case j.Kind == "failed":
			failed++
		case j.Kind == "repaired" && j.Subject == "c.example.net":
			repaired++
		case j.Subject == "h.example.net":
			hedged++
		}
	}
	if failed != 0 || repaired != 1 || hedged != 0 {
		t.Fatalf("journal: %d failed, %d repaired lines for c.example.net, %d for the hedge win; want 0, 1 and 0", failed, repaired, hedged)
	}
}

// scriptedChecks makes the rig's validator answer from a list, one verdict per
// call, then repeat the last one.
func scriptedChecks(f *fakeSys, kinds ...verdict.Kind) {
	n := 0
	f.set(func(f *fakeSys) {
		f.checkFn = func(string, string) verdict.Verdict {
			k := kinds[min(n, len(kinds)-1)]
			n++
			v := verdict.Verdict{Kind: k}
			if k == verdict.Blocked || k == verdict.Suspect {
				v.Engine = "tlsrec"
			}
			return v
		}
	})
}

// ageJudgment pretends the last look at site on network key was d ago.
func ageJudgment(d *Daemon, key, site string, by time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if j := d.judged[key+"|"+site]; j != nil {
		j.at = j.at.Add(-by)
	}
}

// What gets onto the list, and when.
func TestJudgeTransitions(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.9")
	type step struct {
		kind    verdict.Kind
		wait    time.Duration // time since the previous look
		checked bool          // check() must have been called for this step
		listed  bool          // on the list afterwards
	}
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"blocked lists at once", []step{{verdict.Blocked, 0, true, true}}},
		{"clean", []step{{verdict.Clean, 0, true, false}}},
		{"unfixed", []step{{verdict.Unfixed, 0, true, false}}},
		{"unreachable", []step{{verdict.Unreachable, 0, true, false}}},
		{"unknown", []step{{verdict.Unknown, 0, true, false}}},
		{"one suspect does not list", []step{{verdict.Suspect, 0, true, false}}},
		{"second suspect after the wait lists", []step{{verdict.Suspect, 0, true, false}, {verdict.Suspect, 6 * time.Minute, true, true}}},
		{"second look within the wait is not made", []step{{verdict.Suspect, 0, true, false}, {verdict.Suspect, time.Minute, false, false}}},
		{"suspect then blocked lists", []step{{verdict.Suspect, 0, true, false}, {verdict.Blocked, 6 * time.Minute, true, true}}},
		{"clean between two suspects resets", []step{{verdict.Suspect, 0, true, false}, {verdict.Clean, 6 * time.Minute, true, false}, {verdict.Suspect, 6 * time.Minute, true, false}}},
		{"unknown between two suspects resets", []step{{verdict.Suspect, 0, true, false}, {verdict.Unknown, 6 * time.Minute, true, false}, {verdict.Suspect, 6 * time.Minute, true, false}}},
		{"a stale suspect does not count", []step{{verdict.Suspect, 0, true, false}, {verdict.Suspect, 2 * time.Hour, true, false}}},
		{"three suspects", []step{{verdict.Suspect, 0, true, false}, {verdict.Suspect, 6 * time.Minute, true, true}, {verdict.Suspect, 6 * time.Minute, false, true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, f := rig(t, Options{})
			engage(t, d, f)
			key := "asn:15897"
			var kind verdict.Kind
			f.set(func(f *fakeSys) {
				f.checkFn = func(string, string) verdict.Verdict {
					v := verdict.Verdict{Kind: kind}
					if kind == verdict.Blocked || kind == verdict.Suspect {
						v.Engine = "ciadpi"
					}
					return v
				}
			})
			for i, st := range tc.steps {
				if st.wait > 0 {
					ageJudgment(d, key, "example.net", st.wait)
				}
				kind = st.kind
				before := len(f.get().checks)
				d.judge(context.Background(), candidate{host: "www.slow.example.net", ip: ip, engine: "tlsrec"})
				if called := len(f.get().checks) > before; called != st.checked {
					t.Fatalf("step %d: check called=%v, want %v", i, called, st.checked)
				}
				e, ok := d.st.Match(key, "www.slow.example.net")
				if ok != st.listed {
					t.Fatalf("step %d: listed=%v, want %v", i, ok, st.listed)
				}
				if ok && (e.Engine != "ciadpi" || e.Source != store.SourceAuto || e.Domain != "example.net" || e.Host != "www.slow.example.net") {
					t.Fatalf("step %d: entry %+v", i, e)
				}
			}
		})
	}
}

func TestJudgeGuards(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	key := "asn:15897"
	scriptedChecks(f, verdict.Blocked)
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.9")

	_, _ = d.st.Add(key, store.Entry{Domain: "listed.example.com", Source: store.SourceAuto})
	for _, h := range []string{"gateway.listed.example.com", "localhost", "10.0.0.1", ""} {
		d.judge(ctx, candidate{host: h, ip: ip})
	}
	if n := len(f.get().checks); n != 0 {
		t.Fatalf("listed or unlistable hosts were probed: %v", f.get().checks)
	}
	f.set(func(f *fakeSys) { f.net.Online = false })
	d.judge(ctx, candidate{host: "x.offline.example.org", ip: ip})
	f.set(func(f *fakeSys) { f.net = netid.Info{} })
	d.judge(ctx, candidate{host: "x.offline.example.org", ip: ip})
	f.set(func(f *fakeSys) { f.net = netid.Info{Key: key, Label: "AS15897", Online: true} })
	if n := len(f.get().checks); n != 0 {
		t.Fatal("probed while offline or without a network")
	}

	// Unstable network: not judged, and the wait is not spent.
	d.mu.Lock()
	d.badAt = time.Now()
	d.mu.Unlock()
	d.judge(ctx, candidate{host: "a.unstable.example.org", ip: ip})
	if n := len(f.get().checks); n != 0 {
		t.Fatalf("validated %d times while health checks fail", n)
	}
	d.mu.Lock()
	d.badAt = time.Time{}
	d.mu.Unlock()
	d.judge(ctx, candidate{host: "a.unstable.example.org", ip: ip})
	if n := len(f.get().checks); n != 1 {
		t.Fatalf("%d checks after recovery, want 1", n)
	}
	if _, ok := d.st.Match(key, "a.unstable.example.org"); !ok {
		t.Fatal("not listed once the network was stable")
	}
}

// The wait is per site and per network: a sibling host is not probed during it,
// another network has its own.
func TestJudgeWaitIsPerSiteAndNetwork(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	scriptedChecks(f, verdict.Unknown)
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.9")
	d.judge(ctx, candidate{host: "a.shared.example.net", ip: ip})
	d.judge(ctx, candidate{host: "b.shared.example.net", ip: ip})
	if n := len(f.get().checks); n != 1 {
		t.Fatalf("%d checks, want 1 (same site within the wait)", n)
	}
	d.judge(ctx, candidate{host: "other.example.org", ip: ip})
	if n := len(f.get().checks); n != 2 {
		t.Fatalf("%d checks, want 2 (another site)", n)
	}
	f.set(func(f *fakeSys) { f.net = netid.Info{Key: "asn:2", Label: "AS2", Online: true} })
	d.judge(ctx, candidate{host: "a.shared.example.net", ip: ip})
	if n := len(f.get().checks); n != 3 {
		t.Fatalf("%d checks, want 3 (another network has its own wait)", n)
	}
}

func TestJudgeStopsWithItsContext(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	ctx, cancel := context.WithCancel(context.Background())
	f.set(func(f *fakeSys) {
		f.checkFn = func(string, string) verdict.Verdict {
			cancel() // shutdown while the probes run
			return verdict.Verdict{Kind: verdict.Blocked, Engine: "tlsrec"}
		}
	})
	d.judge(ctx, candidate{host: "a.example.net", ip: netip.MustParseAddr("203.0.113.9")})
	if _, ok := d.st.Match("asn:15897", "a.example.net"); ok {
		t.Fatal("listed during shutdown")
	}
}

// No goroutine, no timer: a Suspect leaves nothing running behind it.
func TestJudgeLeavesNoBackgroundWork(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	scriptedChecks(f, verdict.Suspect)
	d.judge(context.Background(), candidate{host: "a.example.net", ip: netip.MustParseAddr("203.0.113.9")})
	if _, ok := d.st.Match("asn:15897", "a.example.net"); ok {
		t.Fatal("listed on one Suspect")
	}
	for _, j := range d.journal {
		if j.Kind == "recheck" {
			t.Fatalf("a deferred re-check was scheduled: %+v", j)
		}
	}
}

// The journal holds failed and repaired connections, list changes and service
// state only: verdicts, suspects and confirmations go to the log file.
func TestJournalHoldsOnlyListChangesFromJudgeAndRetest(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	d.mu.Lock()
	d.journal = nil
	d.mu.Unlock()
	ip := netip.MustParseAddr("203.0.113.9")
	scriptedChecks(f, verdict.Suspect, verdict.Unknown, verdict.Blocked)
	d.judge(context.Background(), candidate{host: "a.example.net", ip: ip})
	d.judge(context.Background(), candidate{host: "b.example.org", ip: ip})
	d.judge(context.Background(), candidate{host: "c.example.com", ip: ip})
	f.set(func(f *fakeSys) {
		f.checkFn = func(string, string) verdict.Verdict {
			return verdict.Verdict{Kind: verdict.Blocked, Engine: "tlsrec", Engines: map[string]string{"tlsrec": "ok"}}
		}
	})
	e, _ := entry(t, d, "asn:15897", "example.com")
	d.retest(context.Background(), "asn:15897", e)
	var kinds []string
	for _, j := range d.journal {
		kinds = append(kinds, j.Kind)
	}
	if !slices.Equal(kinds, []string{"listed"}) {
		t.Fatalf("journal kinds %v, want just [listed]", kinds)
	}
}
