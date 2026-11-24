//go:build !windows

package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Commit: crash after cleanup, before the caller's save.
func TestReviewCommitCrashLeavesPendingWithoutWayBack(t *testing.T) {
	for at := 1; ; at++ {
		r := newRig(t)
		s := State{}
		must(t, Swap(r.p, r.stageVersion(t, "B"), "A", &s))
		must(t, s.Save(r.file))
		j := &injector{at: at}
		j.hook(t)
		crashed, op := j.run(func() { Commit(r.p, &s); _ = s.Save(r.file) })
		j.at = 0
		if !crashed {
			break
		}
		v, _, s2 := r.reboot(t)
		if s2.Pending != nil && r.kept() == "<none>" {
			err := Rollback(r.p, &s2, "x")
			t.Errorf("crash before %q: %s runs, state Pending %s->%s, but nothing kept; a later rollback says: %v", op, v, s2.Pending.From, s2.Pending.To, err)
		}
	}
}

// Over a pending one: does the app match the binary after every crash?
func TestReviewOverPendingAppMatches(t *testing.T) {
	for at := 1; ; at++ {
		r := newRig(t)
		s := State{}
		must(t, Swap(r.p, r.stageVersion(t, "B"), "A", &s))
		s.Pending.Starts = 1
		must(t, s.Save(r.file))
		st := r.stageVersion(t, "C")
		j := &injector{at: at}
		j.hook(t)
		crashed, op := j.run(func() {
			must(t, Swap(r.p, st, "B", &s))
			_ = s.Save(r.file)
		})
		j.at = 0
		if !crashed {
			break
		}
		v, _, s2 := r.reboot(t)
		if r.app() != v {
			t.Errorf("crash before %q: daemon %s, app %s", op, v, r.app())
		}
		// and a rollback from there lands on A for both
		if s2.Pending != nil && s2.Pending.To == v {
			if err := Rollback(r.p, &s2, "x"); err != nil {
				t.Errorf("crash before %q: rollback: %v", op, err)
			} else if r.installed() != "A" || r.app() != "A" {
				t.Errorf("crash before %q: rollback gives daemon %s app %s", op, r.installed(), r.app())
			}
		}
	}
}

// Windows-style two renames for the program (inPlace=false).
func TestReviewTwoRenameCrash(t *testing.T) {
	old := inPlace
	inPlace = false
	t.Cleanup(func() { inPlace = old })
	for at := 1; ; at++ {
		r := newRig(t)
		st := r.stageVersion(t, "B")
		s := State{}
		must(t, s.Save(r.file))
		j := &injector{at: at}
		j.hook(t)
		crashed, op := j.run(func() {
			must(t, Swap(r.p, st, "A", &s))
			_ = s.Save(r.file)
		})
		j.at = 0
		if !crashed {
			break
		}
		if v, _, _ := r.reboot(t); v != "A" && v != "B" {
			t.Logf("crash before %q: install path holds %s", op, v)
		}
	}
}

// back(): app replace fails, and restoring the program fails too.
func TestReviewBackRestoreFails(t *testing.T) {
	r := newRig(t)
	st := r.stageVersion(t, "B")
	s := State{}
	must(t, s.Save(r.file))
	orig := fsRename
	t.Cleanup(func() { fsRename = orig })
	n := 0
	fsRename = func(a, b string) error {
		n++
		// 1: program fresh->dst ok; 2: app dst->aside ok; 3: app fresh->dst FAIL;
		// 4: app aside->dst ok; 5: program aside->dst (restore) FAIL
		if n == 3 || n == 5 {
			return errors.New("injected")
		}
		return orig(a, b)
	}
	err := Swap(r.p, st, "A", &s)
	fsRename = orig
	t.Logf("swap: %v", err)
	v, a, s2 := r.reboot(t)
	t.Logf("after reboot: running %s action %v %s kept=%s", v, a, dump(s2), r.kept())
	if v == "B" && s2.Pending == nil {
		t.Errorf("B runs, unconfirmed and permanent (%s)", fmt.Sprint(r.kept()))
	}
	_ = os.Remove
}

// `sudo autodpi install`: service.Install starts the new daemon, whose Resume
// runs cleanup, while InstallTray's ReplaceTree is copying the app into
// newPath(AppPath). Here cleanup runs once, while the copy is half done.
func TestReviewReplaceTreeVersusDaemonStartCleanup(t *testing.T) {
	r := newRig(t)
	src := t.TempDir() + "/AutoDPI.app"
	must(t, os.MkdirAll(src+"/Contents/MacOS", 0o755))
	must(t, os.WriteFile(src+"/Contents/Info.plist", []byte("plist"), 0o644))
	must(t, os.WriteFile(src+"/Contents/MacOS/app", []byte("bin"), 0o755))
	must(t, os.WriteFile(src+"/Contents/v", []byte("NEW"), 0o644))
	orig := fsMkdirAll
	t.Cleanup(func() { fsMkdirAll = orig })
	fsMkdirAll = func(name string, perm os.FileMode) error {
		if filepath.Base(name) == "MacOS" {
			cleanup(r.p) // the fresh daemon's Resume, after Info.plist was copied
		}
		return orig(name, perm)
	}
	err := ReplaceTree(src, AppPath)
	fsMkdirAll = orig
	var have []string
	for _, f := range []string{"/Contents/Info.plist", "/Contents/MacOS/app", "/Contents/v"} {
		if _, err := os.Stat(AppPath + f); err == nil {
			have = append(have, f)
		}
	}
	t.Logf("ReplaceTree err=%v; installed app has %v", err, have)
	if err == nil && len(have) != 3 {
		t.Errorf("ReplaceTree reported success but the installed app is missing files: %v", have)
	}
}
