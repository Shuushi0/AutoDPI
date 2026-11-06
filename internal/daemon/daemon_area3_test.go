//go:build !windows

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/netid"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/probe"
	"github.com/Shuushi0/AutoDPI/internal/store"
	"github.com/Shuushi0/AutoDPI/internal/verdict"
)

const a3net = "asn:15897"

func a3rig(t *testing.T) (*Daemon, *fakeSys) {
	t.Helper()
	d, f := rig(t, Options{})
	d.obs = observer.New(observer.Options{})
	d.cands = make(chan candidate, 8)
	if _, err := d.st.Touch(a3net, "AS15897"); err != nil {
		t.Fatal(err)
	}
	return d, f
}

func a3entry(d *Daemon, dom string) (store.Entry, bool) {
	for _, e := range d.st.List(a3net) {
		if e.Domain == dom {
			return e, true
		}
	}
	return store.Entry{}, false
}

func a3setCheck(f *fakeSys, fn func(key, host string) verdict.Verdict) {
	f.set(func(f *fakeSys) { f.checkFn = fn })
}

func a3cand(host string) candidate {
	return candidate{host: host, ip: netip.MustParseAddr("203.0.113.5"), engine: "tlsrec"}
}

func a3checks(f *fakeSys) []string { return f.get().checks }

// ---------------------------------------------------------------------------
// judge / list: what gets onto the blocked list
// ---------------------------------------------------------------------------

func TestA3JudgeOnlyBlockedIsListed(t *testing.T) {
	for _, tc := range []struct {
		kind   verdict.Kind
		listed bool
	}{
		{verdict.Blocked, true},
		{verdict.Clean, false},
		{verdict.Unfixed, false},
		{verdict.Unreachable, false},
		{verdict.Unknown, false},
		{verdict.Suspect, false}, // one Suspect is a first strike, not a listing
	} {
		d, f := a3rig(t)
		a3setCheck(f, func(string, string) verdict.Verdict { return verdict.Verdict{Kind: tc.kind, Engine: "tlsrec"} })
		d.judge(context.Background(), a3cand("api.newsite.com"))
		if _, ok := a3entry(d, "newsite.com"); ok != tc.listed {
			t.Errorf("verdict %v: listed=%v want %v", tc.kind, ok, tc.listed)
		}
	}
}

func TestA3ListedEntryShape(t *testing.T) {
	d, f := a3rig(t)
	_, _ = d.st.Add(a3net, store.Entry{Domain: "covered.example.org", Source: store.SourceAuto})
	a3setCheck(f, func(string, string) verdict.Verdict {
		return verdict.Verdict{Kind: verdict.Blocked, Engine: "ciadpi"}
	})
	d.judge(context.Background(), a3cand("API.NewSite.com"))
	e, ok := a3entry(d, "newsite.com")
	if !ok || e.Engine != "ciadpi" || e.Source != store.SourceAuto || e.Host != "api.newsite.com" {
		t.Fatalf("%+v %v", e, ok)
	}
	// A second host of the same domain, and any covered host, is not probed again.
	n := len(a3checks(f))
	d.judge(context.Background(), a3cand("cdn.newsite.com"))
	d.judge(context.Background(), a3cand("www.covered.example.org"))
	d.judge(context.Background(), a3cand("WWW.Covered.Example.ORG")) // any spelling
	if len(a3checks(f)) != n {
		t.Errorf("covered hosts were probed: %v", a3checks(f)[n:])
	}
}

// list() after the provisional key was folded into the stable one.
func TestA3ListAfterRekeyGoesToTheStableNetwork(t *testing.T) {
	d, f := a3rig(t)
	_, _ = d.st.Touch("gw:old", "wifi")
	_ = d.st.Rekey("gw:old", a3net) // "gw:old" no longer exists
	f.set(func(f *fakeSys) { f.net.Key = a3net })
	d.list("gw:old", "x.late.com", "tlsrec")
	if _, ok := a3entry(d, "late.com"); !ok {
		t.Fatal("entry for the folded provisional key was lost")
	}
	if len(d.st.Networks()) != 1 {
		t.Fatalf("a stray network was created: %+v", d.st.Networks())
	}
}

// ---------------------------------------------------------------------------
// retest
// ---------------------------------------------------------------------------

func TestA3RetestPerVerdict(t *testing.T) {
	type want struct {
		present bool
		ok      int
		source  string
		engine  string
	}
	for _, tc := range []struct {
		name  string
		entry store.Entry
		v     verdict.Verdict
		want  want
	}{
		{"auto clean once -> ok=1", store.Entry{Domain: "s.com", Source: store.SourceAuto, Engine: "tlsrec"}, verdict.Verdict{Kind: verdict.Clean}, want{true, 1, "auto", "tlsrec"}},
		{"auto clean twice -> gone", store.Entry{Domain: "s.com", Source: store.SourceAuto, OK: 1}, verdict.Verdict{Kind: verdict.Clean}, want{}},
		{"suspect keeps and resets", store.Entry{Domain: "s.com", Source: store.SourceAuto, OK: 1, Engine: "tlsrec"}, verdict.Verdict{Kind: verdict.Suspect, Engine: "tlsrec", Engines: map[string]string{"tlsrec": "ok"}}, want{true, 0, "auto", "tlsrec"}},
		{"engine switch", store.Entry{Domain: "s.com", Source: store.SourceAuto, Engine: "tlsrec"}, verdict.Verdict{Kind: verdict.Blocked, Engine: "ciadpi", Engines: map[string]string{"tlsrec": "reset", "ciadpi": "ok"}}, want{true, 0, "auto", "ciadpi"}},
		{"engine keeps when it still works", store.Entry{Domain: "s.com", Source: store.SourceAuto, Engine: "ciadpi"}, verdict.Verdict{Kind: verdict.Blocked, Engine: "tlsrec", Engines: map[string]string{"tlsrec": "ok", "ciadpi": "ok"}}, want{true, 0, "auto", "ciadpi"}},
		{"empty engine pinned", store.Entry{Domain: "s.com", Source: store.SourceAuto}, verdict.Verdict{Kind: verdict.Blocked, Engine: "ciadpi", Engines: map[string]string{"tlsrec": "ok", "ciadpi": "ok"}}, want{true, 0, "auto", "ciadpi"}},
		// Any round that is not clean resets the count: two *consecutive* clean rounds.
		{"unfixed resets", store.Entry{Domain: "s.com", Source: store.SourceAuto, Engine: "tlsrec", OK: 1}, verdict.Verdict{Kind: verdict.Unfixed}, want{true, 0, "auto", "tlsrec"}},
		{"unreachable resets", store.Entry{Domain: "s.com", Source: store.SourceAuto, OK: 1}, verdict.Verdict{Kind: verdict.Unreachable}, want{true, 0, "auto", ""}},
		{"unknown resets", store.Entry{Domain: "s.com", Source: store.SourceAuto, OK: 1}, verdict.Verdict{Kind: verdict.Unknown}, want{true, 0, "auto", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, f := a3rig(t)
			_, _ = d.st.Add(a3net, tc.entry)
			a3setCheck(f, func(string, string) verdict.Verdict { return tc.v })
			e, _ := a3entry(d, "s.com")
			d.retest(context.Background(), a3net, e)
			got, ok := a3entry(d, "s.com")
			if ok != tc.want.present {
				t.Fatalf("present=%v want %v (%+v)", ok, tc.want.present, got)
			}
			if !ok {
				return
			}
			if got.OK != tc.want.ok || got.Source != tc.want.source || got.Engine != tc.want.engine || got.Checked.IsZero() {
				t.Fatalf("%+v want %+v", got, tc.want)
			}
		})
	}
}

// retest probes e.Host when it is set and the bare domain otherwise.
func TestA3RetestProbesTheBlockedHost(t *testing.T) {
	d, f := a3rig(t)
	_, _ = d.st.Add(a3net, store.Entry{Domain: "exnet.com", Host: "gateway.exnet.com", Source: store.SourceAuto})
	_, _ = d.st.Add(a3net, store.Entry{Domain: "bareexample.org", Source: store.SourceAuto})
	a3setCheck(f, func(string, string) verdict.Verdict { return verdict.Verdict{Kind: verdict.Unknown} })
	e, _ := a3entry(d, "exnet.com")
	d.retest(context.Background(), a3net, e)
	e2, _ := a3entry(d, "bareexample.org")
	d.retest(context.Background(), a3net, e2)
	got := a3checks(f)
	if !slices.Equal(got, []string{"gateway.exnet.com", "bareexample.org"}) {
		t.Fatalf("%v", got)
	}
}

// An entry the user adds manually while a pass is running, still looking like
// an automatic one in the pass's snapshot, is neither removed nor changed: the
// re-test reads the entry again when it acts.
func TestA3RetestDoesNotRemoveManualEntryAddedDuringPass(t *testing.T) {
	d, f := a3rig(t)
	engage(t, d, f)
	d.retestGap = time.Millisecond
	_, _ = d.st.Add(a3net, store.Entry{Domain: "roblox.la", Source: store.SourceAuto})
	var once sync.Once
	a3setCheck(f, func(_, host string) verdict.Verdict {
		// The first probe of the pass is slow; meanwhile the user runs
		// `autodpi add roblox.la`, which upgrades the entry to a manual one.
		once.Do(func() {
			if _, err := d.st.Add(a3net, store.Entry{Domain: "roblox.la", Source: store.SourceManual}); err != nil {
				t.Error(err)
			}
		})
		return verdict.Verdict{Kind: verdict.Clean}
	})
	d.retestAll(context.Background())
	e, ok := a3entry(d, "roblox.la")
	if !ok {
		t.Errorf("manual entry roblox.la was removed by the periodic re-test that started before it was added")
	} else if e.Source != store.SourceManual || e.OK != 0 {
		t.Errorf("manual entry changed: %+v", e)
	}
}

// The re-test must not rewrite a manually pinned engine either.
func TestA3RetestDoesNotOverwriteManualEnginePinnedDuringPass(t *testing.T) {
	d, f := a3rig(t)
	engage(t, d, f)
	d.retestGap = time.Millisecond
	_, _ = d.st.Add(a3net, store.Entry{Domain: "roblox.la", Source: store.SourceAuto, Engine: "ciadpi"})
	var once sync.Once
	a3setCheck(f, func(_, host string) verdict.Verdict {
		once.Do(func() {
			_, _ = d.st.Add(a3net, store.Entry{Domain: "roblox.la", Source: store.SourceManual, Engine: "tlsrec"})
		})
		return verdict.Verdict{Kind: verdict.Blocked, Engine: "ciadpi", Engines: map[string]string{"tlsrec": "reset", "ciadpi": "ok"}}
	})
	d.retestAll(context.Background())
	if e, _ := a3entry(d, "roblox.la"); e.Engine != "tlsrec" || e.Source != store.SourceManual {
		t.Errorf("user's pinned engine overwritten by the re-test: %+v", e)
	}
}

// Two consecutive clean rounds are required: Clean, Unreachable, Clean keeps it.
func TestA3RetestUnknownBetweenCleanRoundsKeepsEntry(t *testing.T) {
	d, f := a3rig(t)
	_, _ = d.st.Add(a3net, store.Entry{Domain: "s.com", Source: store.SourceAuto, Engine: "tlsrec"})
	for _, k := range []verdict.Kind{verdict.Clean, verdict.Unreachable, verdict.Clean} {
		k := k
		a3setCheck(f, func(string, string) verdict.Verdict { return verdict.Verdict{Kind: k} })
		if e, ok := a3entry(d, "s.com"); ok {
			d.retest(context.Background(), a3net, e)
		}
	}
	if e, ok := a3entry(d, "s.com"); !ok || e.OK != 1 {
		t.Errorf("after Clean, Unreachable, Clean: %+v %v (want kept with one clean round)", e, ok)
	}
}

// A retest result for an entry that left the list meanwhile (removed by the
// user) must not bring it back or panic.
func TestA3RetestOfARemovedEntryIsHarmless(t *testing.T) {
	d, f := a3rig(t)
	_, _ = d.st.Add(a3net, store.Entry{Domain: "gone.example.com", Source: store.SourceAuto})
	e, _ := a3entry(d, "gone.example.com")
	a3setCheck(f, func(string, string) verdict.Verdict {
		_, _ = d.st.Remove(a3net, "gone.example.com")
		return verdict.Verdict{Kind: verdict.Blocked, Engine: "tlsrec", Engines: map[string]string{"tlsrec": "ok"}}
	})
	d.retest(context.Background(), a3net, e)
	if _, ok := a3entry(d, "gone.example.com"); ok {
		t.Fatal("a removed entry came back")
	}
}

func TestA3RetestAllSkipsManualAndHonoursNetworkAndRunState(t *testing.T) {
	d, f := a3rig(t)
	d.retestGap = time.Millisecond
	_, _ = d.st.Add(a3net, store.Entry{Domain: "mine.example.org", Source: store.SourceManual})
	_, _ = d.st.Add(a3net, store.Entry{Domain: "learned-example.net", Source: store.SourceAuto})
	a3setCheck(f, func(string, string) verdict.Verdict { return verdict.Verdict{Kind: verdict.Unknown} })
	d.retestAll(context.Background()) // not running: nothing happens
	if len(a3checks(f)) != 0 {
		t.Fatalf("re-test ran while the capture is down: %v", a3checks(f))
	}
	engage(t, d, f)
	d.retestAll(context.Background())
	got := a3checks(f)
	if !slices.Equal(got, []string{"learned-example.net"}) {
		t.Fatalf("probed %v", got)
	}
}

// With the real validator: an entry whose name no longer resolves is Unknown on
// every round, and stays; one that opens directly is dropped after two rounds.
func TestA3RetestWithTheRealValidator(t *testing.T) {
	d, f := a3rig(t)
	engage(t, d, f)
	d.retestGap = time.Millisecond
	_, _ = d.st.Add(a3net, store.Entry{Domain: "fine-example.org", Host: "www.fine-example.org", Source: store.SourceAuto})
	_, _ = d.st.Add(a3net, store.Entry{Domain: "norecord-example.net", Source: store.SourceAuto})

	cert, roots := a3cert(t, []string{"www.fine-example.org"})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	d.val = &verdict.Validator{
		Direct: &probe.Prober{
			Dial: func(ctx context.Context, n, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, n, ln.Addr().String())
			},
			Roots: roots, Timeout: time.Second,
		},
		Engines: func() []observer.Engine { return nil },
		Resolve: func(_ context.Context, h string) ([]netip.Addr, error) {
			if h == "norecord-example.net" {
				return nil, errors.New("no such host")
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	}
	d.sys.check = d.check
	for round := 0; round < 2; round++ {
		d.retestAll(context.Background())
	}
	if _, ok := a3entry(d, "fine-example.org"); ok {
		t.Error("entry that opens directly is still listed after two rounds")
	}
	if e, ok := a3entry(d, "norecord-example.net"); !ok || e.OK != 0 {
		t.Errorf("entry with no address: %+v %v (Unknown keeps it)", e, ok)
	}
}

func a3cert(t *testing.T, names []string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a3"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: names, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// ---------------------------------------------------------------------------
// API: add / remove
// ---------------------------------------------------------------------------

func TestA3APIAddRemoveSemantics(t *testing.T) {
	d, _ := a3rig(t)
	// Manual add of a name an automatic entry already covers is stored (the
	// parent may be re-tested away; the user's entry must not go with it).
	_, _ = d.st.Add(a3net, store.Entry{Domain: "discord.com", Source: store.SourceAuto})
	r, err := call(t, d, ipc.Request{Cmd: "add", Domain: "cdn.discord.com"})
	if err != nil {
		t.Fatal(err)
	}
	if r["added"] != true {
		t.Fatalf("%v", r)
	}
	// remove: exact names only, normalised
	if _, err := call(t, d, ipc.Request{Cmd: "remove", Domain: "voice.discord.com"}); err == nil {
		t.Error("removing a name that is only covered must error")
	}
	if _, err := call(t, d, ipc.Request{Cmd: "remove", Domain: "*.Discord.COM."}); err != nil {
		t.Error(err)
	}
	if _, err := call(t, d, ipc.Request{Cmd: "remove", Domain: "discord.com"}); err == nil {
		t.Error("second remove must error")
	}
	if _, err := call(t, d, ipc.Request{Cmd: "remove", Domain: ""}); err == nil {
		t.Error("empty remove must error")
	}
	// manual entries keep the exact name (no registrable reduction)
	if _, err := call(t, d, ipc.Request{Cmd: "add", Domain: "www.example.org"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a3entry(d, "www.example.org"); !ok {
		t.Error("manual entry reduced to its registrable domain")
	}
	// engine re-pin of a manual entry
	r, _ = call(t, d, ipc.Request{Cmd: "add", Domain: "www.example.org", Engine: "ciadpi"})
	if r["added"] != true {
		t.Errorf("re-pin: %v", r)
	}
	if e, _ := a3entry(d, "www.example.org"); e.Engine != "ciadpi" {
		t.Errorf("%+v", e)
	}
	// Status counters follow.
	if st := d.status(); st.Entries != len(d.st.List(a3net)) {
		t.Errorf("status entries %d", st.Entries)
	}
}

// The user adds a subdomain by hand under a learned parent; a later automatic
// removal of the parent leaves the subdomain listed.
func TestA3APIManualSubdomainOfAutoParentIsKept(t *testing.T) {
	d, _ := a3rig(t)
	_, _ = d.st.Add(a3net, store.Entry{Domain: "discord.com", Source: store.SourceAuto})
	r, _ := call(t, d, ipc.Request{Cmd: "add", Domain: "cdn.discord.com"})
	// What retest() does to an entry that measures clean twice:
	_, _ = d.st.Remove(a3net, "discord.com")
	if _, ok := d.st.Match(a3net, "cdn.discord.com"); !ok {
		t.Errorf("`add cdn.discord.com` returned %v and the host is unlisted once the parent is gone", r)
	}
}

func TestA3APIListAndRemoveAreNetworkScoped(t *testing.T) {
	d, f := a3rig(t)
	_, _ = d.st.Add(a3net, store.Entry{Domain: "first.example.net", Source: store.SourceManual})
	_, _ = d.st.Touch("asn:2", "other")
	_, _ = d.st.Add("asn:2", store.Entry{Domain: "elsewhere.com", Source: store.SourceManual})
	if _, err := call(t, d, ipc.Request{Cmd: "remove", Domain: "elsewhere.com"}); err == nil {
		t.Fatal("removed an entry that belongs to another network")
	}
	f.set(func(f *fakeSys) { f.net = netid.Info{Key: "asn:2", Online: true} })
	if _, err := call(t, d, ipc.Request{Cmd: "remove", Domain: "elsewhere.com"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a3entry(d, "first.example.net"); !ok {
		t.Fatal("first network's list touched")
	}
}

// ---------------------------------------------------------------------------
// onNetChange / rekey wiring
// ---------------------------------------------------------------------------

func TestA3NetChangeRekeysOnlySameAttachment(t *testing.T) {
	d, f := a3rig(t)
	_, _ = d.st.Touch("gw:abc", "wifi")
	_, _ = d.st.Add("gw:abc", store.Entry{Domain: "learned.com", Source: store.SourceAuto})
	// Moving to a *different* known network must not absorb the provisional list.
	d.onNetChange(netid.Info{Key: "gw:abc", Provisional: true, GatewayKey: "gw:abc"},
		netid.Info{Key: a3net, GatewayKey: "gw:other", Online: true})
	if _, ok := a3entry(d, "learned.com"); ok {
		t.Fatal("provisional list folded into an unrelated network")
	}
	if len(d.st.List("gw:abc")) == 0 {
		t.Fatal("provisional list vanished")
	}
	// Same attachment, now identified: inherited.
	f.set(func(f *fakeSys) { f.net.Key = a3net })
	d.onNetChange(netid.Info{Key: "gw:abc", Provisional: true, GatewayKey: "gw:abc"},
		netid.Info{Key: a3net, GatewayKey: "gw:abc", Online: true})
	if _, ok := a3entry(d, "learned.com"); !ok {
		t.Fatal("entry lost on rekey")
	}
	if len(d.st.List("gw:abc")) != 0 {
		t.Fatal("provisional network still present")
	}
}

func TestA3OnEventCandidateQueue(t *testing.T) {
	d, _ := a3rig(t)
	d.cands = make(chan candidate, 1)
	d.onEvent(observer.Event{SNI: "a.x.com", Dest: "203.0.113.5:443", Outcome: observer.Failed})
	d.onEvent(observer.Event{SNI: "a.x.com", Dest: "203.0.113.5:443", Outcome: observer.Direct})
	d.onEvent(observer.Event{SNI: "", Dest: "203.0.113.5:443", Outcome: observer.Fallback})
	d.onEvent(observer.Event{SNI: "a.x.com", Dest: "bogus", Outcome: observer.Fallback})
	if len(d.cands) != 0 {
		t.Fatalf("%d candidates queued for events that are not repaired named flows", len(d.cands))
	}
	d.onEvent(observer.Event{SNI: "a.x.com", Dest: "203.0.113.5:443", Outcome: observer.Fallback, Engine: "tlsrec"})
	done := make(chan struct{})
	go func() { // a full queue must not block the observer
		d.onEvent(observer.Event{SNI: "b.x.com", Dest: "203.0.113.5:443", Outcome: observer.Fallback})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("onEvent blocked on a full candidate queue")
	}
}

// ---------------------------------------------------------------------------
// concurrency (-race)
// ---------------------------------------------------------------------------

func TestA3ConcurrentListOperations(t *testing.T) {
	d, f := a3rig(t)
	d.retestGap = time.Microsecond
	engage(t, d, f)
	var flip atomic.Int32
	a3setCheck(f, func(_, host string) verdict.Verdict {
		switch flip.Add(1) % 5 {
		case 0:
			return verdict.Verdict{Kind: verdict.Clean}
		case 1:
			return verdict.Verdict{Kind: verdict.Suspect, Engine: "tlsrec", Engines: map[string]string{"tlsrec": "ok"}}
		case 2:
			return verdict.Verdict{Kind: verdict.Blocked, Engine: "ciadpi", Engines: map[string]string{"tlsrec": "reset", "ciadpi": "ok"}}
		}
		return verdict.Verdict{Kind: verdict.Unknown}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				h := "h" + itoa(i%6) + ".s" + itoa((w+i)%4) + ".com"
				switch (w + i) % 7 {
				case 0:
					d.onEvent(ev(h, observer.Direct))
				case 1:
					d.onEvent(ev(h, observer.Fallback))
				case 2:
					d.judge(ctx, a3cand(h))
				case 3:
					_, _ = d.handle(ctx, ipc.Request{Cmd: "add", Domain: h})
				case 4:
					_, _ = d.handle(ctx, ipc.Request{Cmd: "remove", Domain: "s" + itoa(i%4) + ".com"})
				case 5:
					_ = d.status()
					_ = d.mode(h)
				case 6:
					if i%10 == 0 {
						_, _ = d.openReset()
					}
					d.retestAll(ctx)
				}
			}
		}(w)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, e := range d.st.List(a3net) {
		if seen[e.Domain] {
			t.Errorf("duplicate %s", e.Domain)
		}
		seen[e.Domain] = true
	}
}

func itoa(i int) string {
	b := []byte{}
	if i == 0 {
		return "0"
	}
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func ev(host string, o observer.Outcome) observer.Event {
	return observer.Event{Time: time.Now(), SNI: host, Dest: "203.0.113.5:443", Outcome: o}
}
