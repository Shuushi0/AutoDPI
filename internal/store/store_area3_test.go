package store

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func a3open(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func a3reopen(t *testing.T, p string) *Store {
	t.Helper()
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func a3has(s *Store, key, dom string) (Entry, bool) {
	for _, e := range s.List(key) {
		if e.Domain == dom {
			return e, true
		}
	}
	return Entry{}, false
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ---- per-network isolation ----------------------------------------------------

func TestA3NetworksAreIsolated(t *testing.T) {
	s, p := a3open(t)
	for _, k := range []string{"asn:1", "asn:2"} {
		if _, err := s.Touch(k, k); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []string{"asn:1", "asn:2"} {
		if ok, _ := s.Add(k, Entry{Domain: "shared.example.net", Source: SourceAuto}); !ok {
			t.Fatal("add failed")
		}
	}
	if ok, _ := s.Add("asn:1", Entry{Domain: "blocked.example.org", Source: SourceAuto}); !ok {
		t.Fatal("add failed")
	}
	if _, ok := s.Match("asn:2", "blocked.example.org"); ok {
		t.Fatal("entry leaked to another network")
	}
	if _, ok := s.Match("asn:3", "shared.example.net"); ok {
		t.Fatal("unknown network matched")
	}
	if ok, _ := s.Remove("asn:1", "example.net"); !ok {
		t.Fatal("remove failed")
	}
	if _, ok := a3has(s, "asn:2", "example.net"); !ok {
		t.Fatal("remove on asn:1 removed asn:2's entry")
	}
	// Unknown networks error rather than being created behind the caller's back.
	if _, err := s.Add("asn:9", Entry{Domain: "x.example.net", Source: SourceAuto}); err == nil {
		t.Fatal("Add on unknown network must fail")
	}
	if n := len(s.Networks()); n != 2 {
		t.Fatalf("%d networks, want 2", n)
	}
	// And all of that survived a restart.
	r := a3reopen(t, p)
	if _, ok := a3has(r, "asn:1", "example.net"); ok {
		t.Fatal("removal not persisted")
	}
	if _, ok := a3has(r, "asn:2", "example.net"); !ok {
		t.Fatal("entry lost")
	}
}

// ---- Add / coverage -----------------------------------------------------------

func TestA3AddNormalisesAndGroups(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("n", "")
	if ok, err := s.Add("n", Entry{Domain: "*.CDN.Example.Net.", Host: "CDN.example.NET", Source: SourceAuto}); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	e, ok := a3has(s, "n", "example.net")
	if !ok || e.Host != "cdn.example.net" {
		t.Fatalf("entry %+v ok=%v", e, ok)
	}
	// Host outside the domain is dropped, not stored.
	_, _ = s.Add("n", Entry{Domain: "other.org", Host: "evil.com", Source: SourceAuto})
	if e, _ := a3has(s, "n", "other.org"); e.Host != "" {
		t.Fatalf("host outside domain kept: %+v", e)
	}
	// Same domain again, any case and any subdomain: not added, nothing changes.
	for _, d := range []string{"Example.NET", "a.b.example.net", "*.example.net"} {
		if ok, _ := s.Add("n", Entry{Domain: d, Source: SourceAuto}); ok {
			t.Errorf("Add(%q) reported a change", d)
		}
	}
	for _, bad := range []string{"", "localhost", "1.2.3.4", "foo.local", "a..b"} {
		if _, err := s.Add("n", Entry{Domain: bad, Source: SourceAuto}); err == nil {
			t.Errorf("Add(%q) accepted", bad)
		}
	}
	seen := map[string]int{}
	for _, e := range s.List("n") {
		seen[e.Domain]++
	}
	for d, c := range seen {
		if c != 1 {
			t.Errorf("%q listed %d times", d, c)
		}
	}
}

func TestA3NarrowerEntriesAreSubsumed(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "a.foo.com", Source: SourceManual}) // manual, narrower
	_, _ = s.Add("n", Entry{Domain: "b.foo.com", Source: SourceManual, Engine: "x"})
	// Registrable-domain reduction makes auto entries foo.com
	if ok, _ := s.Add("n", Entry{Domain: "c.foo.com", Source: SourceAuto}); !ok {
		t.Fatal("auto parent not added")
	}
	for _, d := range []string{"a.foo.com", "b.foo.com"} {
		if _, ok := a3has(s, "n", d); !ok {
			t.Errorf("manual %q removed by an automatic parent", d)
		}
	}
	if _, ok := a3has(s, "n", "foo.com"); !ok {
		t.Fatal("parent missing")
	}
	// A manual parent upgrades the auto parent in place.
	_, _ = s.Add("n", Entry{Domain: "foo.com", Source: SourceManual})
	if e, _ := a3has(s, "n", "foo.com"); e.Source != SourceManual {
		t.Fatalf("auto parent not upgraded to manual: %+v", e)
	}
}

func TestA3ManualUpgradeOfAutoEntryAndEngineChange(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "discord.com", Source: SourceAuto, OK: 1})
	drain(s)
	if ok, _ := s.Add("n", Entry{Domain: "discord.com", Source: SourceManual, Engine: "ciadpi"}); !ok {
		t.Fatal("manual add on top of an auto entry did not change the list")
	}
	e, _ := a3has(s, "n", "discord.com")
	if e.Source != SourceManual || e.Engine != "ciadpi" || e.OK != 0 {
		t.Fatalf("%+v", e)
	}
	if !drain(s) {
		t.Fatal("engine change not signalled")
	}
	// Re-adding the identical manual entry is a no-op and stays quiet.
	if ok, _ := s.Add("n", Entry{Domain: "discord.com", Source: SourceManual, Engine: "ciadpi"}); ok {
		t.Fatal("identical manual add reported a change")
	}
	if drain(s) {
		t.Fatal("no-op add signalled a change")
	}
	// Adding the auto variant never downgrades a manual entry.
	if ok, _ := s.Add("n", Entry{Domain: "discord.com", Source: SourceAuto}); ok {
		t.Fatal("auto add changed a manual entry")
	}
	if e, _ := a3has(s, "n", "discord.com"); e.Source != SourceManual {
		t.Fatalf("manual entry downgraded: %+v", e)
	}
}

// A manual entry under a listed parent is stored. The parent is an automatic
// entry that a re-test may remove later, which must not take the user's
// "permanent" subdomain with it.
func TestA3ManualSubdomainUnderAutoParentSurvivesParentRemoval(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "discord.com", Source: SourceAuto})
	if ok, err := s.Add("n", Entry{Domain: "cdn.discord.com", Source: SourceManual, Engine: "ciadpi"}); err != nil || !ok {
		t.Fatalf("manual add under a covering auto entry: added=%v err=%v", ok, err)
	}
	// What a re-test does when the bare domain looks clean:
	_, _ = s.Remove("n", "discord.com")
	if e, ok := s.Match("n", "cdn.discord.com"); !ok || e.Source != SourceManual || e.Engine != "ciadpi" {
		t.Errorf("manually added cdn.discord.com is gone or changed after its parent was removed: %+v %v", e, ok)
	}
	// Under a manual parent, though, a manual entry adds nothing.
	_, _ = s.Add("n", Entry{Domain: "example.org", Source: SourceManual})
	if ok, _ := s.Add("n", Entry{Domain: "a.example.org", Source: SourceManual}); ok {
		t.Error("manual entry under a manual parent was stored")
	}
}

// ---- Rekey ---------------------------------------------------------------------

func TestA3RekeyBasics(t *testing.T) {
	s, p := a3open(t)
	if err := s.Rekey("missing", "asn:1"); err != nil { // no source: no-op
		t.Fatal(err)
	}
	if err := s.Rekey("a", "a"); err != nil {
		t.Fatal(err)
	}
	_, _ = s.Touch("gw:x", "wifi")
	_, _ = s.Add("gw:x", Entry{Domain: "foo.net", Source: SourceAuto, Engine: "ciadpi"})
	if err := s.Rekey("gw:x", "asn:1"); err != nil { // destination absent: renamed wholesale
		t.Fatal(err)
	}
	if got := s.Networks(); len(got) != 1 || got[0].Key != "asn:1" || got[0].Label != "wifi" {
		t.Fatalf("%+v", got)
	}
	if e, ok := a3has(s, "asn:1", "foo.net"); !ok || e.Engine != "ciadpi" {
		t.Fatalf("%+v %v", e, ok)
	}
	r := a3reopen(t, p)
	if _, ok := a3has(r, "asn:1", "foo.net"); !ok || len(r.List("gw:x")) != 0 {
		t.Fatal("rekey not persisted")
	}
}

func TestA3RekeyIntoExistingKeepsBothSidesWithoutDuplicates(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("asn:1", "AS1")
	_, _ = s.Touch("gw:x", "wifi")
	_, _ = s.Add("asn:1", Entry{Domain: "removed.net", Source: SourceAuto})
	_, _ = s.Remove("asn:1", "removed.net") // user dropped it on the stable network
	_, _ = s.Add("gw:x", Entry{Domain: "learned.net", Source: SourceAuto})
	_, _ = s.Add("gw:x", Entry{Domain: "both.net", Source: SourceAuto})
	_, _ = s.Add("asn:1", Entry{Domain: "own.net", Source: SourceAuto})
	_, _ = s.Add("asn:1", Entry{Domain: "both.net", Source: SourceAuto})
	if err := s.Rekey("gw:x", "asn:1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := a3has(s, "asn:1", "removed.net"); ok {
		t.Error("removed entry resurrected by rekey")
	}
	for _, d := range []string{"learned.net", "own.net", "both.net"} {
		if _, ok := a3has(s, "asn:1", d); !ok {
			t.Errorf("%q lost", d)
		}
	}
	if len(s.List("asn:1")) != 3 {
		t.Errorf("entries: %+v", s.List("asn:1"))
	}
	if len(s.Networks()) != 1 {
		t.Errorf("source network not removed: %+v", s.Networks())
	}
}

// Rekey keeps the user's manual entry (and its engine) whichever side it was on.
func TestA3RekeyDoesNotDowngradeManualEntry(t *testing.T) {
	for _, tc := range []struct{ name, manualOn string }{{"manual in source", "gw:x"}, {"manual in destination", "asn:1"}} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := a3open(t)
			_, _ = s.Touch("asn:1", "")
			_, _ = s.Touch("gw:x", "")
			for _, k := range []string{"asn:1", "gw:x"} {
				e := Entry{Domain: "foo.net", Source: SourceAuto, Engine: "tlsrec"}
				if k == tc.manualOn {
					e = Entry{Domain: "foo.net", Source: SourceManual, Engine: "ciadpi"}
				}
				_, _ = s.Add(k, e)
			}
			if err := s.Rekey("gw:x", "asn:1"); err != nil {
				t.Fatal(err)
			}
			e, ok := a3has(s, "asn:1", "foo.net")
			if !ok {
				t.Fatal("entry lost")
			}
			if e.Source != SourceManual || e.Engine != "ciadpi" {
				t.Errorf("manual entry downgraded by Rekey: %+v", e)
			}
		})
	}
}

// A manual entry the source network pinned under an automatic parent of the
// destination is kept too.
func TestA3RekeyKeepsManualSubdomainUnderParent(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("asn:1", "")
	_, _ = s.Touch("gw:x", "")
	_, _ = s.Add("asn:1", Entry{Domain: "foo.net", Source: SourceAuto})
	_, _ = s.Add("gw:x", Entry{Domain: "cdn.foo.net", Source: SourceManual})
	_ = s.Rekey("gw:x", "asn:1")
	if _, ok := a3has(s, "asn:1", "cdn.foo.net"); !ok {
		t.Fatalf("manual subdomain lost: %+v", s.List("asn:1"))
	}
}

// ---- Remove / Update / Match ---------------------------------------------------

func TestA3RemoveIsExact(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "discord.com", Source: SourceAuto})
	if ok, _ := s.Remove("n", "cdn.discord.com"); ok {
		t.Fatal("removing a subdomain removed something")
	}
	if _, ok := a3has(s, "n", "discord.com"); !ok {
		t.Fatal("parent removed through a subdomain")
	}
	if ok, _ := s.Remove("n", "*.Discord.COM."); !ok {
		t.Fatal("Remove must normalise")
	}
	if ok, _ := s.Remove("n", "discord.com"); ok {
		t.Fatal("double remove reported a change")
	}
	if ok, _ := s.Remove("zz", "discord.gg"); ok {
		t.Fatal("remove on unknown network")
	}
	if ok, _ := s.Remove("n", ""); ok {
		t.Fatal("empty remove")
	}
}

func TestA3UpdateAndMatch(t *testing.T) {
	s, p := a3open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "discord.com", Source: SourceAuto})
	if err := s.Update("n", "nothere.com", func(e *Entry) { t.Fatal("fn called for a missing entry") }); err != nil {
		t.Fatal(err)
	}
	if err := s.Update("zz", "discord.com", func(e *Entry) { t.Fatal("fn called for a missing network") }); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	_ = s.Update("n", "discord.com", func(e *Entry) { e.OK, e.Checked = 1, now })
	e, _ := s.Match("n", "x.y.discord.com")
	if e.OK != 1 || !e.Checked.Equal(now) {
		t.Fatalf("%+v", e)
	}
	// Match returns a copy.
	e.Engine = "mutated"
	if e2, _ := s.Match("n", "discord.com"); e2.Engine == "mutated" {
		t.Fatal("Match leaked a pointer into the store")
	}
	if r := a3reopen(t, p); func() bool { e, _ := r.Match("n", "discord.com"); return e.OK != 1 }() {
		t.Fatal("Update not persisted")
	}
	// Lookalikes must not match.
	for _, h := range []string{"notdiscord.com", "discord.com.evil.net", "discord.co", "com"} {
		if _, ok := s.Match("n", h); ok {
			t.Errorf("%q matched discord.com", h)
		}
	}
	// Any spelling of a listed name matches (case, trailing dot).
	for _, h := range []string{"CDN.Discord.COM", "discord.com.", "*.discord.com"} {
		if _, ok := s.Match("n", h); !ok {
			t.Errorf("Match(%q) == false although discord.com is listed", h)
		}
	}
}

// Match answers with the entry that decides the route: a manual one (the
// user's engine) over an automatic parent, otherwise the broadest.
func TestA3MatchPrefersManualThenBroadest(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "api.foo.net", Source: SourceManual, Engine: "ciadpi"})
	_, _ = s.Add("n", Entry{Domain: "foo.net", Source: SourceAuto, Engine: "tlsrec"})
	// Both kept (manual is never auto-removed). The rule-sets carry each under
	// its own engine and nothing may be dropped or duplicated.
	by := s.ByEngine("n", []string{"tlsrec", "ciadpi"}, "tlsrec")
	total := 0
	seen := map[string]bool{}
	for _, l := range by {
		for _, d := range l {
			if seen[d] {
				t.Errorf("%q in two rule-sets", d)
			}
			seen[d] = true
			total++
		}
	}
	if total != len(s.List("n")) {
		t.Errorf("ByEngine carries %d domains, list has %d", total, len(s.List("n")))
	}
	if !contains(by["ciadpi"], "api.foo.net") || !contains(by["tlsrec"], "foo.net") {
		t.Errorf("%v", by)
	}
	if e, _ := s.Match("n", "api.foo.net"); e.Domain != "api.foo.net" || e.Engine != "ciadpi" {
		t.Errorf("Match(api.foo.net) = %+v, want the pinned manual entry", e)
	}
	if e, _ := s.Match("n", "www.foo.net"); e.Domain != "foo.net" {
		t.Errorf("Match(www.foo.net) = %+v", e)
	}
	_, _ = s.Add("n", Entry{Domain: "x.bar.org", Source: SourceManual})
	_, _ = s.Add("n", Entry{Domain: "bar.org", Source: SourceManual, Engine: "ciadpi"})
	if e, _ := s.Match("n", "x.bar.org"); e.Domain != "bar.org" {
		t.Errorf("broadest manual entry should decide, got %+v", e)
	}
}

func TestA3ByEngineUnknownAndEmptyFallBack(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "a.net", Source: SourceAuto, Engine: "gone"})
	_, _ = s.Add("n", Entry{Domain: "b.net", Source: SourceAuto, Engine: ""})
	_, _ = s.Add("n", Entry{Domain: "c.net", Source: SourceAuto, Engine: "ciadpi"})
	by := s.ByEngine("n", []string{"tlsrec", "ciadpi"}, "tlsrec")
	if !contains(by["tlsrec"], "a.net") || !contains(by["tlsrec"], "b.net") || !contains(by["ciadpi"], "c.net") || len(by["gone"]) != 0 {
		t.Fatalf("%v", by)
	}
	if got := s.ByEngine("nope", []string{"tlsrec"}, "tlsrec"); len(got) != 0 {
		t.Fatalf("unknown network: %v", got)
	}
}

// ---- signals -------------------------------------------------------------------

func TestA3ChangedSignalOnlyForRuleSetRelevantChanges(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("n", "")
	drain(s)
	_ = s.SetPaused(true)
	if drain(s) {
		t.Error("pause signalled a rule-set change")
	}
	_, _ = s.Touch("n", "relabel")
	if drain(s) {
		t.Error("Touch of an existing network signalled")
	}
	_, _ = s.Touch("fresh", "")
	if drain(s) {
		t.Error("creating an empty network signalled")
	}
	_, _ = s.Add("n", Entry{Domain: "new.net", Source: SourceAuto})
	if !drain(s) {
		t.Error("Add did not signal")
	}
	_, _ = s.Remove("n", "new.net")
	if !drain(s) {
		t.Error("Remove did not signal")
	}
	_, _ = s.Remove("n", "new.net")
	if drain(s) {
		t.Error("no-op Remove signalled")
	}
	_ = s.Rekey("n", "m")
	if !drain(s) {
		t.Error("Rekey did not signal")
	}
}

// ---- persistence ---------------------------------------------------------------

func TestA3PersistenceRoundTripAllFields(t *testing.T) {
	s, p := a3open(t)
	_, _ = s.Touch("asn:1", "AS1 Foo")
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, _ = s.Add("asn:1", Entry{Domain: "foo.net", Host: "api.foo.net", Engine: "ciadpi", Source: SourceAuto, Added: now, OK: 1})
	_ = s.Update("asn:1", "foo.net", func(e *Entry) { e.Checked = now.Add(time.Minute) })
	_ = s.SetPaused(true)
	_, _ = s.Touch("asn:2", "")

	r := a3reopen(t, p)
	if !r.Paused() {
		t.Error("paused lost")
	}
	e, ok := a3has(r, "asn:1", "foo.net")
	if !ok || e.Host != "api.foo.net" || e.Engine != "ciadpi" || e.Source != SourceAuto || e.OK != 1 ||
		!e.Added.Equal(now) || !e.Checked.Equal(now.Add(time.Minute)) {
		t.Errorf("entry round trip: %+v", e)
	}
	if got := r.Networks(); len(got) != 2 {
		t.Errorf("networks: %+v", got)
	}
	// file hygiene
	fi, err := os.Stat(p)
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("state file mode %v err %v", fi.Mode(), err)
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	for _, de := range ents {
		if strings.HasPrefix(de.Name(), ".state-") {
			t.Errorf("temp file left behind: %s", de.Name())
		}
	}
}

func TestA3CorruptFileIsMovedAsideAndStoreStillWorks(t *testing.T) {
	for name, content := range map[string]string{
		"truncated": `{"version":2,"networks":{"a":{"entries":{"x.com":{"domain":"x.`,
		"array":     `[]`,
		"garbage":   "\x00\x01\x02",
		"wrongtype": `{"networks":{"a":{"entries":{"x.com":"nope"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "state.json")
			_ = os.WriteFile(p, []byte(content), 0o600)
			s, err := Open(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Touch("asn:1", ""); err != nil {
				t.Fatal(err)
			}
			matches, _ := filepath.Glob(p + ".corrupt-*")
			if len(matches) != 1 {
				t.Fatalf("corrupt file not preserved: %v", matches)
			}
			if b, _ := os.ReadFile(matches[0]); string(b) != content {
				t.Error("backup differs from the original")
			}
			if len(a3reopen(t, p).Networks()) == 0 {
				t.Error("new state not persisted")
			}
		})
	}
	// null JSON and null members load as empty, not as a crash.
	p := filepath.Join(t.TempDir(), "state.json")
	_ = os.WriteFile(p, []byte("null"), 0o600)
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Touch("a", ""); err != nil {
		t.Fatal(err)
	}
}

// When the state file cannot be written, Add reports the error and the entry
// is not live in memory either (commitLocked). Directory permissions are a
// Unix way to make the write fail; commit_test.go covers every system.
func TestA3SaveFailureLeavesNothingInMemory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory permissions")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	s, p := a3open(t)
	_, _ = s.Touch("n", "")
	dir := filepath.Dir(p)
	_ = os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	ok, err := s.Add("n", Entry{Domain: "ghost.net", Source: SourceAuto})
	if err == nil {
		t.Skip("directory permissions not enforced here")
	}
	if ok {
		t.Error("Add reported a change it could not save")
	}
	if _, listed := s.Match("n", "ghost.net"); listed {
		t.Error("the unsaved entry is live in memory")
	}
	_ = os.Chmod(dir, 0o700)
	if _, listed := a3reopen(t, p).Match("n", "ghost.net"); listed {
		t.Error("unexpected: entry persisted")
	}
}

// ---- concurrency ---------------------------------------------------------------

func TestA3ConcurrentUseKeepsInvariants(t *testing.T) {
	s, p := a3open(t)
	nets := []string{"asn:1", "asn:2", "asn:3"}
	for _, k := range nets {
		_, _ = s.Touch(k, k)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 150; i++ {
				k := nets[(w+i)%len(nets)]
				h := fmt.Sprintf("h%d.site%d.example.net", i%7, i%5)
				switch (w + i) % 8 {
				case 0:
					_, _ = s.Add(k, Entry{Domain: h, Source: SourceAuto})
				case 1:
					_, _ = s.Add(k, Entry{Domain: h, Source: SourceManual})
				case 2:
					_, _, _ = s.Edit(k, fmt.Sprintf("site%d.example.net", i%5), func(e *Entry) bool { return e.Source == SourceAuto && i%2 == 0 })
				case 3:
					_, _ = s.Remove(k, fmt.Sprintf("site%d.example.net", i%5))
				case 4:
					_ = s.Update(k, fmt.Sprintf("site%d.example.net", i%5), func(e *Entry) { e.OK++ })
				case 5:
					_ = s.ByEngine(k, []string{"a"}, "a")
					_ = s.Networks()
				case 6:
					_, _ = s.Match(k, h)
					_, _ = s.Get(k, h)
				case 7:
					_, _ = s.Touch(k, "again")
				}
			}
		}(w)
	}
	go func() { // a reader draining the signal like storeLoop
		for {
			select {
			case <-s.Changed():
			case <-stop:
				return
			}
		}
	}()
	wg.Wait()
	close(stop)
	r := a3reopen(t, p)
	for _, k := range nets {
		if len(r.List(k)) != len(s.List(k)) {
			t.Errorf("%s: persisted %d entries, memory %d", k, len(r.List(k)), len(s.List(k)))
		}
	}
}

func TestA3ConcurrentRekeyAndUse(t *testing.T) {
	s, _ := a3open(t)
	_, _ = s.Touch("asn:1", "")
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				k := fmt.Sprintf("gw:%d", (w*100+i)%5)
				_, _ = s.Touch(k, "")
				_, _ = s.Add(k, Entry{Domain: fmt.Sprintf("a%d.net", i%9), Source: SourceAuto})
				_ = s.Rekey(k, "asn:1")
				_ = s.List("asn:1")
			}
		}(w)
	}
	wg.Wait()
	for _, n := range s.Networks() {
		if strings.HasPrefix(n.Key, "gw:") && n.Entries == 0 {
			t.Errorf("empty network %s", n.Key)
		}
	}
}
