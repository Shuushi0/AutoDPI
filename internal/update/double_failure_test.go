//go:build !windows

package update

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// failRenames makes the renames whose "from -> to" base names contain one of
// the given fragments fail with EACCES, as a file held by another program
// does, for as long as hold() says so.
func failRenames(t *testing.T, hold func() bool, fragments ...string) {
	t.Helper()
	old, tries := fsRename, backTries
	oldPause := backPause
	backTries, backPause = 2, 0
	t.Cleanup(func() { fsRename, backTries, backPause = old, tries, oldPause })
	fsRename = func(from, to string) error {
		step := filepath.Base(from) + " -> " + filepath.Base(to)
		for _, f := range fragments {
			if strings.Contains(step, f) && hold() {
				return &os.LinkError{Op: "rename", Old: from, New: to, Err: syscall.EACCES}
			}
		}
		return old(from, to)
	}
}

func always() bool { return true }

// The Windows way (two renames), with the new program held by an antivirus
// and the way back blocked as well: the program was left out of its place,
// the swap counted as undone, and the next try deleted the only copy as a
// leftover. After the next reboot there was nothing to start.
func TestTwoFailedRenamesNeverLoseTheProgram(t *testing.T) {
	r := newRig(t)
	oldIn := inPlace
	inPlace = false
	t.Cleanup(func() { inPlace = oldIn })
	st := r.stageVersion(t, "B")
	held := true
	failRenames(t, func() bool { return held }, ".autodpi.new -> autodpi", ".autodpi.old -> autodpi")

	s := State{}
	err := Swap(r.p, st, "A", &s)
	if !errors.Is(err, ErrHalfSwapped) {
		t.Fatalf("Swap = %v, want ErrHalfSwapped: the program is not at its place and that must not read as \"nothing happened\"", err)
	}
	if on := LoadState(r.file); on.Swap == nil {
		t.Fatal("the intent is gone from disk: nothing would settle this at the next start")
	}
	// The antivirus still holds the files when the updater tries again.
	if err := Swap(r.p, r.stageVersion(t, "B"), "A", &s); !errors.Is(err, ErrHalfSwapped) {
		t.Fatalf("second Swap = %v", err)
	}
	if r.kept() != "A" && r.installed() != "A" {
		t.Fatalf("the only copy of the program is gone: installed %s, kept %s", r.installed(), r.kept())
	}
	// It lets go: the next look puts the program back.
	held = false
	if !Heal(r.p) || r.installed() != "A" {
		t.Fatalf("not healed: installed %s", r.installed())
	}
	if v, a, on := r.reboot(t); v != "A" || a != Nothing || on.Pending != nil || on.Swap != nil {
		t.Fatalf("after the next start: running %s, action %v, %s", v, a, dump(on))
	}
}

// The same for the app beside the program (a folder: two renames on every
// system). It used to end up only at its kept-aside name, which the next
// start deleted, and no later update ever brought it back.
func TestTwoFailedRenamesNeverLoseTheApp(t *testing.T) {
	r := newRig(t)
	st := r.stageVersion(t, "B")
	held := true
	failRenames(t, func() bool { return held }, ".AutoDPI.app.new -> AutoDPI.app", ".AutoDPI.app.old -> AutoDPI.app")
	s := State{}
	err := Swap(r.p, st, "A", &s)
	if err == nil {
		t.Fatal("Swap succeeded although the app could not be put in place")
	}
	held = false
	v, _, on := r.reboot(t)
	if r.app() == "<missing>" {
		t.Fatalf("the app is gone (running %s, %s)", v, dump(on))
	}
	if r.app() != v {
		t.Fatalf("program %s runs with app %s (%s)", v, r.app(), dump(on))
	}
	// And a second start does not take it away either.
	if r.reboot(t); r.app() == "<missing>" {
		t.Fatal("the app went with the second start's cleanup")
	}
}

// A rollback whose app cannot be put back at that moment: the program is on
// the previous version, and the app follows at the next start instead of
// staying on the version that was taken back for good.
func TestRollbackFinishesTheAppAtTheNextStart(t *testing.T) {
	r := newRig(t)
	s := State{}
	if err := Swap(r.p, r.stageVersion(t, "B"), "A", &s); err != nil {
		t.Fatal(err)
	}
	held := true
	failRenames(t, func() bool { return held }, "AutoDPI.app -> ", ".AutoDPI.app.old -> AutoDPI.app")
	if err := Rollback(r.p, &s, "test"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if err := s.Save(r.file); err != nil {
		t.Fatal(err)
	}
	if r.installed() != "A" || !s.FinishRollback {
		t.Fatalf("program %s, finish=%v", r.installed(), s.FinishRollback)
	}
	// Still held at the next start: the kept copy must survive it.
	r.reboot(t)
	if _, err := os.Stat(oldPath(AppPath)); err != nil {
		t.Fatal("the kept copy of the app was cleaned up while it was still needed")
	}
	held = false
	if _, _, on := r.reboot(t); r.app() != "A" || on.FinishRollback || on.Failed != "B" {
		t.Fatalf("app %s, %s finish=%v", r.app(), dump(on), on.FinishRollback)
	}
}

// A rollback (two renames) whose way back fails as well: something must be
// at the path afterwards.
func TestFailedRollbackLeavesAProgram(t *testing.T) {
	r := newRig(t)
	oldIn := inPlace
	inPlace = false
	t.Cleanup(func() { inPlace = oldIn })
	s := State{}
	if err := Swap(r.p, r.stageVersion(t, "B"), "A", &s); err != nil {
		t.Fatal(err)
	}
	held := true
	failRenames(t, func() bool { return held }, ".autodpi.old -> autodpi", ".autodpi.failed")
	err := Rollback(r.p, &s, "test")
	if err == nil {
		t.Fatal("Rollback reported success")
	}
	if got := r.installed(); got != "A" && got != "B" {
		t.Fatalf("install path holds %s after a failed rollback", got)
	}
	if s.Pending == nil {
		t.Fatal("a rollback that did not happen was recorded as one")
	}
}
