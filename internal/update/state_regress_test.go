//go:build !windows

package update

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The daemon's install: Swap, then u.save() whose error is only logged, then
// restartSelf. A full disk (the 90 MB copy fitted, the state file does not),
// or any other failed write of update.json, after the swap.
func TestASaveThatFailsAfterTheSwapLosesTheWayBack(t *testing.T) {
	r := newRig(t)
	st := r.stageVersion(t, "B")
	s := State{Failed: "0.0.1", Skipped: "0.0.2"}
	must(t, s.Save(r.file))
	w := fsWriteFile
	t.Cleanup(func() { fsWriteFile = w })
	fsWriteFile = func(name string, b []byte, perm os.FileMode) error {
		if strings.HasSuffix(name, ".tmp") {
			return &os.PathError{Op: "write", Path: name, Err: syscall.ENOSPC}
		}
		return w(name, b, perm)
	}
	must(t, Swap(r.p, st, "A", &s))
	err := s.Save(r.file) // daemon: u.save() logs and goes on to restartSelf
	t.Logf("save after swap: %v", err)
	fsWriteFile = w
	v, a, s2 := r.reboot(t)
	t.Logf("after restart: running=%s action=%v %s kept=%s", v, a, dump(s2), r.kept())
	if v == "B" && (s2.Pending == nil || r.kept() != "A") {
		t.Errorf("B runs unconfirmed, nothing records it and the previous program was deleted by cleanup: no rollback is possible any more")
	}
}

// What LoadState makes of files it may meet.
func TestLoadStateOnOddFiles(t *testing.T) {
	// Exactly what 0.1.1 writes (its State has no "tries").
	v011 := `{
  "checked": "2026-11-10T10:00:00Z",
  "etag": "W/\"abc\"",
  "failed": "0.1.2",
  "pending": {"from": "0.1.1", "to": "0.1.2", "at": "2026-11-10T10:00:00Z", "starts": 2},
  "last": {"from": "0.1.0", "to": "0.1.1", "at": "2026-11-01T10:00:00Z", "ok": true}
}`
	cases := map[string]string{
		"v0.1.1":    v011,
		"empty":     "",
		"truncated": v011[:120],
		"zeros":     strings.Repeat("\x00", 300), // NTFS/APFS after power loss with unflushed data
		// A later version that writes a field in another type: a list of
		// failed versions, a time as a number.
		"newer: failed is a list":   `{"failed": ["0.1.3"], "pending": {"from":"0.1.2","to":"0.1.3","at":"2026-11-10T10:00:00Z","starts":1}}`,
		"newer: checked is unix":    `{"checked": 1762768800, "failed": "0.1.3", "pending": {"from":"0.1.2","to":"0.1.3","at":"2026-11-10T10:00:00Z","starts":1}}`,
		"newer: pending.at is unix": `{"failed": "0.1.3", "pending": {"from":"0.1.2","to":"0.1.3","at":1762768800,"starts":1}, "skipped": "0.1.4"}`,
	}
	for name, body := range cases {
		f := filepath.Join(t.TempDir(), "update.json")
		must(t, os.WriteFile(f, []byte(body), 0o644))
		s := LoadState(f)
		t.Logf("%-26s -> %s skipped=%q checked=%v", name, dump(s), s.Skipped, s.Checked.IsZero())
	}
}

// Windows: antivirus holds the freshly written copy (sharing violation) when
// it is renamed into place, and for a moment the file put aside as well.
// Swap's restore is best effort: on its failure the install path is empty
// and Swap still says "nothing is swapped".
func TestASwapWhoseRestoreFailsLeavesNoProgram(t *testing.T) {
	r := newRig(t)
	st := r.stageVersion(t, "B")
	s := State{}
	ren := fsRename
	t.Cleanup(func() { fsRename = ren })
	fails := 0
	fsRename = func(a, b string) error {
		if b == r.p.Installed && fails < 2 { // the new copy, then the restore
			fails++
			return &os.LinkError{Op: "rename", Old: a, New: b, Err: syscall.EACCES}
		}
		return ren(a, b)
	}
	err := Swap(r.p, st, "A", &s)
	fsRename = ren
	t.Logf("swap: %v; install path: %s; .old: %s", err, r.installed(), r.kept())
	if r.installed() != "A" {
		t.Errorf("after a failed swap the install path holds %s; the service cannot start again (no Resume can run to repair it)", r.installed())
	}
	// The daemon (A, still running from .autodpi.old) tries again an hour later
	// (Tries < MaxTries) with the same download.
	err = Swap(r.p, st, "A", &s)
	t.Logf("retry: %v; install path: %s; .old: %s", err, r.installed(), r.kept())
	if r.kept() != "A" && r.installed() != "A" {
		t.Errorf("the retry's clearPath deleted the only copy of the running version: nothing to start, nothing to go back to")
	}
}
