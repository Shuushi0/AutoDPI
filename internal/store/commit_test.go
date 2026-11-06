package store

import (
	"os"
	"path/filepath"
	"testing"
)

// A change the file did not take is not made: memory, the rule-set signal and
// the caller's answer all agree with the file.
func TestFailedSaveChangesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub")
	s, err := Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Touch("k", "Net"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("k", Entry{Domain: "kept.example.com", Source: SourceManual}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Changed():
	default:
	}
	// The folder becomes a file: every save fails, on every system.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if added, err := s.Add("k", Entry{Domain: "new.example.com", Source: SourceManual}); err == nil || added {
		t.Fatalf("Add = %v, %v; want an error and no change", added, err)
	}
	if removed, err := s.Remove("k", "kept.example.com"); err == nil || removed {
		t.Fatalf("Remove = %v, %v; want an error and no change", removed, err)
	}
	if err := s.SetPaused(true); err == nil || s.Paused() {
		t.Fatalf("SetPaused: err %v, paused %v; want an error and not paused", err, s.Paused())
	}
	if n, err := s.ClearAuto("k", true); err != nil || n != 0 {
		t.Fatalf("ClearAuto with nothing automatic: %d, %v", n, err)
	}
	if _, _, err := s.Edit("k", "kept.example.com", func(e *Entry) bool { e.Engine = "ciadpi"; return false }); err == nil {
		t.Fatal("Edit saved into a folder that is a file")
	}
	got := s.List("k")
	if len(got) != 1 || got[0].Domain != "kept.example.com" || got[0].Engine != "" {
		t.Fatalf("list after failed saves: %+v", got)
	}
	select {
	case <-s.Changed():
		t.Fatal("a failed save signalled a rule-set change")
	default:
	}
}
