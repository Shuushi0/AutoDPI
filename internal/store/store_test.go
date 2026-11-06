package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func drain(s *Store) bool {
	select {
	case <-s.Changed():
		return true
	default:
		return false
	}
}

func TestTouchCreatesAnEmptyNetworkOnce(t *testing.T) {
	s, _ := open(t)
	created, err := s.Touch("asn:9121", "AS9121")
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if n := len(s.List("asn:9121")); n != 0 {
		t.Fatalf("a new network holds %d entries, want none (no seeds)", n)
	}
	if created, _ = s.Touch("asn:9121", ""); created {
		t.Fatal("second Touch reports creation")
	}
}

func TestAddGroupsAndCovers(t *testing.T) {
	s, _ := open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "discordapp.com", Source: SourceAuto})

	// cdn.discordapp.com is already covered by the discordapp.com entry.
	if ok, err := s.Add("n", Entry{Domain: "cdn.discordapp.com", Source: SourceAuto}); err != nil || ok {
		t.Fatalf("covered add: ok=%v err=%v", ok, err)
	}
	// Auto entries collapse to the registrable domain.
	if ok, err := s.Add("n", Entry{Domain: "api.shop.example.co.uk", Engine: "ciadpi", Source: SourceAuto}); err != nil || !ok {
		t.Fatalf("add: ok=%v err=%v", ok, err)
	}
	if e, ok := s.Match("n", "img.shop.example.co.uk"); !ok || e.Domain != "example.co.uk" || e.Engine != "ciadpi" {
		t.Fatalf("Match = %+v %v", e, ok)
	}
	// A manual entry keeps its exact name.
	if ok, _ := s.Add("n", Entry{Domain: "blocked.example.org", Source: SourceManual}); !ok {
		t.Fatal("manual add failed")
	}
	if _, ok := s.Match("n", "other.example.org"); ok {
		t.Fatal("manual entry must not widen")
	}
	// A broader entry swallows narrower ones.
	_, _ = s.Add("n", Entry{Domain: "a.deep.zone.net", Source: SourceManual})
	_, _ = s.Add("n", Entry{Domain: "zone.net", Source: SourceManual})
	if _, ok := s.Match("n", "a.deep.zone.net"); !ok {
		t.Fatal("zone.net should cover a.deep.zone.net")
	}
	for _, e := range s.List("n") {
		if e.Domain == "a.deep.zone.net" {
			t.Fatal("narrower entry should have been removed")
		}
	}
}

func TestPersistenceAndCorruption(t *testing.T) {
	s, p := open(t)
	_, _ = s.Touch("n", "home")
	_, _ = s.Add("n", Entry{Domain: "foo.example.net", Engine: "tlsrec", Source: SourceAuto})
	if err := s.SetPaused(true); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Paused() {
		t.Fatal("paused flag lost")
	}
	if e, ok := s2.Match("n", "x.example.net"); !ok || e.Engine != "tlsrec" {
		t.Fatalf("entry lost: %+v %v", e, ok)
	}
	// Windows has no Unix modes (the install folder's access list guards it).
	if fi, _ := os.Stat(p); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("state perms %v", fi.Mode().Perm())
	}

	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s3, err := Open(p)
	if err != nil || len(s3.Networks()) != 0 {
		t.Fatalf("corrupt file should yield empty store, err=%v", err)
	}
	if m, _ := filepath.Glob(p + ".corrupt-*"); len(m) != 1 {
		t.Fatal("corrupt file was not moved aside")
	}
}

func TestByEngineFallback(t *testing.T) {
	s, _ := open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "one.example.net", Engine: "tlsrec", Source: SourceAuto})
	_, _ = s.Add("n", Entry{Domain: "two.example.org", Engine: "gone", Source: SourceAuto})
	got := s.ByEngine("n", []string{"ciadpi", "tlsrec"}, "ciadpi")
	if len(got["tlsrec"]) != 1 || got["tlsrec"][0] != "example.net" {
		t.Fatalf("tlsrec = %v", got["tlsrec"])
	}
	if !slices.Contains(got["ciadpi"], "example.org") {
		t.Fatalf("unknown engine should fall back to default, got %v", got["ciadpi"])
	}
}

func TestRekeyMerges(t *testing.T) {
	s, _ := open(t)
	_, _ = s.Touch("gw:aa", "")
	_, _ = s.Add("gw:aa", Entry{Domain: "learned.example.net", Source: SourceAuto})
	_, _ = s.Touch("asn:1", "AS1")
	if err := s.Rekey("gw:aa", "asn:1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Match("asn:1", "learned.example.net"); !ok {
		t.Fatal("learned entry not merged")
	}
	for _, n := range s.Networks() {
		if n.Key == "gw:aa" {
			t.Fatal("old key still present")
		}
	}
}

// What the user removed from the stable network stays removed when the
// provisional network of a reconnect is folded into it later, as long as the
// provisional one never learned it.
func TestRekeyKeepsRemovedEntriesRemoved(t *testing.T) {
	s, _ := open(t)
	_, _ = s.Touch("asn:1", "AS1")
	_, _ = s.Add("asn:1", Entry{Domain: "once.example.net", Source: SourceAuto})
	if ok, _ := s.Remove("asn:1", "example.net"); !ok {
		t.Fatal("not removed")
	}
	_, _ = s.Touch("gw:aa", "")
	_ = s.Rekey("gw:aa", "asn:1")
	if _, ok := s.Match("asn:1", "once.example.net"); ok {
		t.Fatal("removed entry came back through Rekey")
	}
}

func TestAddKeepsProbeHost(t *testing.T) {
	s, _ := open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "gateway.example.net", Host: "gateway.example.net", Source: SourceAuto})
	e, ok := s.Match("n", "gateway.example.net")
	if !ok || e.Domain != "example.net" || e.Host != "gateway.example.net" {
		t.Fatalf("got %+v", e)
	}
	_, _ = s.Add("n", Entry{Domain: "other.example.org", Host: "unrelated.example.com", Source: SourceAuto})
	if e, _ := s.Match("n", "other.example.org"); e.Host != "" {
		t.Fatalf("a host outside the domain must be dropped, got %q", e.Host)
	}
}

func TestChangedSignalCoalesces(t *testing.T) {
	s, _ := open(t)
	_, _ = s.Touch("n", "")
	drain(s)
	_, _ = s.Add("n", Entry{Domain: "a.example.net", Source: SourceAuto})
	_, _ = s.Add("n", Entry{Domain: "b.example.org", Source: SourceAuto})
	if !drain(s) {
		t.Fatal("expected a change signal")
	}
	if drain(s) {
		t.Fatal("signals should coalesce")
	}
}

// A re-test that moves an entry to another engine changes which rule-set it
// belongs in: the daemon only rewrites rule-sets on Changed.
func TestUpdateSignalsChange(t *testing.T) {
	s, _ := open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "example.net", Source: SourceAuto})
	drain(s)
	if err := s.Update("n", "example.net", func(e *Entry) { e.Engine = "ciadpi" }); err != nil {
		t.Fatal(err)
	}
	if !drain(s) {
		t.Fatal("Update changed an entry's engine without a change signal")
	}
	if got := s.ByEngine("n", []string{"tlsrec", "ciadpi"}, "tlsrec"); !slices.Contains(got["ciadpi"], "example.net") {
		t.Fatalf("ByEngine = %v", got)
	}
}

func TestUpdateWithoutEngineChangeIsQuiet(t *testing.T) {
	s, _ := open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "example.net", Source: SourceAuto})
	drain(s)
	_ = s.Update("n", "example.net", func(e *Entry) { e.OK++ })
	if drain(s) {
		t.Fatal("bookkeeping-only update should not trigger a rule-set rewrite")
	}
}

func TestEditRemovesAndReportsMissing(t *testing.T) {
	s, _ := open(t)
	_, _ = s.Touch("n", "")
	_, _ = s.Add("n", Entry{Domain: "example.net", Source: SourceAuto})
	if found, _, _ := s.Edit("n", "other.net", func(*Entry) bool { t.Fatal("fn called for a missing entry"); return false }); found {
		t.Fatal("found a missing entry")
	}
	drain(s)
	found, removed, err := s.Edit("n", "example.net", func(e *Entry) bool { return e.Source == SourceAuto })
	if err != nil || !found || !removed {
		t.Fatalf("found=%v removed=%v err=%v", found, removed, err)
	}
	if !drain(s) {
		t.Fatal("removal not signalled")
	}
	if _, ok := s.Get("n", "example.net"); ok {
		t.Fatal("entry still there")
	}
}

// A hand-edited or damaged state file with null members must not crash the
// daemon at boot (launchd would restart it forever).
func TestOpenToleratesNullMembers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	raw := `{"version":2,"networks":{"asn:1":null,"asn:2":{"entries":{"discord.com":null,"roblox.com":{"domain":"roblox.com","source":"auto"}}}}}`
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if l := s.List("asn:2"); len(l) != 1 || l[0].Domain != "roblox.com" {
		t.Fatalf("List = %+v", l)
	}
	_ = s.Networks()
	if _, err := s.Touch("asn:1", "AS1"); err != nil {
		t.Fatal(err)
	}
	_ = s.ByEngine("asn:2", []string{"tlsrec"}, "tlsrec")
}

// ---- version 1 -> 2 ------------------------------------------------------------

const v1State = `{
  "version": 1,
  "paused": true,
  "networks": {
    "asn:15897": {
      "label": "AS15897",
      "created": "2026-10-01T10:00:00Z",
      "seen": "2026-10-28T10:00:00Z",
      "entries": {
        "discord.com": {"domain": "discord.com", "source": "seed", "added": "2026-10-01T10:00:00Z"},
        "discordapp.com": {"domain": "discordapp.com", "host": "cdn.discordapp.com", "source": "seed", "added": "2026-10-01T10:00:00Z", "clean": 1},
        "roblox.com": {"domain": "roblox.com", "host": "www.roblox.com", "engine": "ciadpi", "source": "auto", "added": "2026-10-02T10:00:00Z", "checked": "2026-10-27T10:00:00Z", "verified": true},
        "mine.example.org": {"domain": "mine.example.org", "engine": "tlsrec", "source": "manual", "added": "2026-10-03T10:00:00Z", "verified": true},
        "ghost.example.net": null
      },
      "clean": {
        "www.google.com": {"host": "www.google.com", "added": "2026-10-05T10:00:00Z", "expires": "2026-11-05T10:00:00Z"},
        "www.github.com": {"host": "www.github.com", "added": "2026-10-05T10:00:00Z", "expires": "2026-11-05T10:00:00Z"},
        "null.example.com": null
      }
    },
    "gw:abc": null,
    "asn:1": {"label": "other", "entries": null, "clean": {"x.example.net": {"host": "x.example.net"}}}
  }
}`

func TestMigrationFromVersion1(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(p, []byte(v1State), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	m := s.Migration()
	if m.From != 1 || m.SeedsKept != 2 || m.DroppedClean != 4 || m.Backup != p+".v1" {
		t.Fatalf("migration = %+v", m)
	}
	if !s.Paused() {
		t.Error("paused flag lost")
	}
	want := map[string]Entry{
		"discord.com":      {Source: SourceAuto},
		"discordapp.com":   {Source: SourceAuto, Host: "cdn.discordapp.com", OK: 1},
		"roblox.com":       {Source: SourceAuto, Host: "www.roblox.com", Engine: "ciadpi"},
		"mine.example.org": {Source: SourceManual, Engine: "tlsrec"},
	}
	got := s.List("asn:15897")
	if len(got) != len(want) {
		t.Fatalf("entries = %+v", got)
	}
	for _, e := range got {
		w, ok := want[e.Domain]
		if !ok || e.Source != w.Source || e.Host != w.Host || e.Engine != w.Engine || e.OK != w.OK {
			t.Errorf("%s migrated to %+v, want %+v", e.Domain, e, w)
		}
	}
	if len(s.Networks()) != 2 {
		t.Errorf("networks = %+v", s.Networks())
	}

	// The old file is kept byte for byte, 0600; the new one is version 2 without
	// seeds, verified flags or clean lists.
	b, err := os.ReadFile(p + ".v1")
	if err != nil || string(b) != v1State {
		t.Fatalf("backup: err=%v, identical=%v", err, string(b) == v1State)
	}
	if fi, _ := os.Stat(p + ".v1"); fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %v", fi.Mode().Perm())
	}
	var raw struct {
		Version  int `json:"version"`
		Networks map[string]struct {
			Entries map[string]map[string]any `json:"entries"`
			Clean   any                       `json:"clean"`
		} `json:"networks"`
	}
	nb, _ := os.ReadFile(p)
	if err := json.Unmarshal(nb, &raw); err != nil || raw.Version != 2 {
		t.Fatalf("new file: version=%d err=%v", raw.Version, err)
	}
	for k, n := range raw.Networks {
		if n.Clean != nil {
			t.Errorf("%s: clean list written", k)
		}
		for d, e := range n.Entries {
			if e["source"] == "seed" || e["verified"] != nil {
				t.Errorf("%s/%s: legacy fields written: %v", k, d, e)
			}
		}
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("state mode %v", fi.Mode().Perm())
	}

	// A second Open is quiet: nothing to migrate, backup untouched.
	if err := os.WriteFile(p+".v1", []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Migration().From != 0 {
		t.Errorf("migrated twice: %+v", s2.Migration())
	}
	if b, _ := os.ReadFile(p + ".v1"); string(b) != "sentinel" {
		t.Error("backup rewritten by a version 2 start")
	}
}

// A state file without a version field is version 1.
func TestMigrationOfUnversionedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	_ = os.WriteFile(p, []byte(`{"networks":{"a":{"entries":{"x.net":{"domain":"x.net","source":"seed"}}}}}`), 0o600)
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := s.Get("a", "x.net"); !ok || e.Source != SourceAuto || s.Migration().From != 1 {
		t.Fatalf("%+v %v %+v", e, ok, s.Migration())
	}
}

func TestPruneEmptyDropsOnlyEmptyProvisional(t *testing.T) {
	s, _ := open(t)
	_, _ = s.Touch("gw:empty", "")
	_, _ = s.Touch("gw:full", "")
	_, _ = s.Add("gw:full", Entry{Domain: "a.example.net", Source: SourceAuto})
	_, _ = s.Touch("asn:1", "AS1")
	n, err := s.PruneEmpty()
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, %v; want 1", n, err)
	}
	keys := map[string]bool{}
	for _, nw := range s.Networks() {
		keys[nw.Key] = true
	}
	if keys["gw:empty"] || !keys["gw:full"] || !keys["asn:1"] {
		t.Fatalf("networks after prune: %v", keys)
	}
}
