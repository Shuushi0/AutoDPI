//go:build !windows

package update

// Tester's crash harness: every disk-changing call install.go makes goes
// through the fs* seams (fsops_inject.go). For each n the n-th call "crashes"
// (the process dies before it runs), then the machine "reboots": whatever
// binary is at the install path starts and runs Resume on the state file as
// it is on disk. Invariants checked after each reboot:
//   I1 a runnable binary (a known version) is at the install path
//   I2 a version that was never confirmed is never made permanent: if the
//      running version is the new one and unconfirmed, the state says Pending
//      for it and the previous binary is still kept
//   I3 the state never names a version as failed/pending that is not the case

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/paths"
)

type crash struct{ op string }

type injector struct {
	n, at   int
	ops     []string
	written []string // files whose data was written in this run (never fsynced)
}

func (j *injector) step(op string) {
	j.n++
	j.ops = append(j.ops, op)
	if j.at > 0 && j.n == j.at {
		panic(crash{op})
	}
}

func (j *injector) hook(t *testing.T) {
	r, ra, w, o, m, l := fsRename, fsRemoveAll, fsWriteFile, fsOpenFile, fsMkdirAll, fsLink
	t.Cleanup(func() { fsRename, fsRemoveAll, fsWriteFile, fsOpenFile, fsMkdirAll, fsLink = r, ra, w, o, m, l })
	fsLink = func(a, b string) error {
		j.step("link " + filepath.Base(a) + " -> " + filepath.Base(b))
		return l(a, b)
	}
	fsRename = func(a, b string) error {
		j.step("rename " + filepath.Base(a) + " -> " + filepath.Base(b))
		return r(a, b)
	}
	fsRemoveAll = func(a string) error {
		if _, err := os.Lstat(a); err != nil {
			return nil // nothing to do: not a crash point
		}
		j.step("removeall " + filepath.Base(a))
		return ra(a)
	}
	fsWriteFile = func(name string, b []byte, perm os.FileMode) error {
		j.step("writefile " + filepath.Base(name))
		j.written = append(j.written, name)
		return w(name, b, perm)
	}
	fsOpenFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		j.step("create " + filepath.Base(name))
		j.written = append(j.written, name)
		return o(name, flag, perm)
	}
	fsMkdirAll = func(name string, perm os.FileMode) error { return m(name, perm) }
}

// run calls f and reports whether it crashed.
func (j *injector) run(f func()) (crashed bool, at string) {
	defer func() {
		if r := recover(); r != nil {
			c, ok := r.(crash)
			if !ok {
				panic(r)
			}
			crashed, at = true, c.op
		}
	}()
	f()
	return false, ""
}

type rig struct {
	p     paths.Set
	stage string
	file  string
}

func newRig(t *testing.T) rig {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	root := t.TempDir()
	p := paths.Set{Support: root, Installed: filepath.Join(root, "autodpi")}
	old := AppPath
	AppPath = filepath.Join(root, "Applications", "AutoDPI.app")
	t.Cleanup(func() { AppPath = old })
	must(t, os.MkdirAll(filepath.Join(AppPath, "Contents"), 0o755))
	must(t, os.WriteFile(p.Installed, []byte("A"), 0o755))
	must(t, os.WriteFile(filepath.Join(AppPath, "Contents", "v"), []byte("A"), 0o644))
	return rig{p: p, file: StateFile(p)}
}

func (r rig) stageVersion(t *testing.T, v string) Staged {
	stage := filepath.Join(r.p.Support, "update", "stage")
	_ = os.RemoveAll(stage)
	must(t, os.MkdirAll(filepath.Join(stage, "AutoDPI.app", "Contents"), 0o755))
	must(t, os.WriteFile(filepath.Join(stage, "autodpi"), []byte(v), 0o755))
	must(t, os.WriteFile(filepath.Join(stage, "AutoDPI.app", "Contents", "v"), []byte(v), 0o644))
	return Staged{Version: v, Dir: stage}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (r rig) installed() string {
	b, err := os.ReadFile(r.p.Installed)
	if err != nil {
		return "<missing>"
	}
	if len(b) == 0 {
		return "<empty>"
	}
	return string(b)
}

func (r rig) kept() string {
	b, err := os.ReadFile(oldPath(r.p.Installed))
	if err != nil {
		return "<none>"
	}
	return string(b)
}

func (r rig) app() string {
	b, err := os.ReadFile(filepath.Join(AppPath, "Contents", "v"))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

// reboot starts whatever is installed: Resume on the state on disk, saved.
func (r rig) reboot(t *testing.T) (string, Action, State) {
	v := r.installed()
	s := LoadState(r.file)
	if v == "<missing>" || v == "<empty>" {
		return v, Nothing, s // launchd cannot start anything
	}
	a := Resume(r.p, v, &s)
	_ = s.Save(r.file)
	return v, a, s
}

func dump(s State) string {
	p := "nil"
	if s.Pending != nil {
		p = fmt.Sprintf("{%s->%s starts=%d}", s.Pending.From, s.Pending.To, s.Pending.Starts)
	}
	return fmt.Sprintf("pending=%s failed=%q", p, s.Failed)
}

// The daemon's install: Swap, then save, then restart.
func TestCrashAtEveryStepOfAnInstall(t *testing.T) {
	var bad []string
	for at := 1; ; at++ {
		r := newRig(t)
		st := r.stageVersion(t, "B")
		s := State{}
		must(t, s.Save(r.file))
		j := &injector{at: at}
		j.hook(t)
		crashed, op := j.run(func() {
			if err := Swap(r.p, st, "A", &s); err != nil {
				t.Fatalf("swap: %v", err)
			}
			_ = s.Save(r.file)
		})
		j.at = 0
		if !crashed {
			t.Logf("install has %d crash points", at-1)
			break
		}
		v, a, s2 := r.reboot(t)
		switch {
		case v != "A" && v != "B":
			bad = append(bad, fmt.Sprintf("crash before %q: install path holds %s (I1)", op, v))
		case v == "B" && (s2.Pending == nil || r.kept() != "A"):
			bad = append(bad, fmt.Sprintf("crash before %q: B runs unconfirmed and is permanent: action=%v %s kept=%s app=%s (I2)", op, a, dump(s2), r.kept(), r.app()))
		case r.app() != v:
			bad = append(bad, fmt.Sprintf("crash before %q: daemon %s with app %s", op, v, r.app()))
		}
	}
	for _, b := range bad {
		t.Error(b)
	}
}

// Resume's own rollback (the 4th start of a crashing new version).
func TestCrashAtEveryStepOfAStartupRollback(t *testing.T) {
	var bad []string
	for at := 1; ; at++ {
		r := newRig(t)
		st := r.stageVersion(t, "B")
		s := State{}
		must(t, Swap(r.p, st, "A", &s))
		s.Pending.Starts = MaxStarts
		must(t, s.Save(r.file))
		j := &injector{at: at}
		j.hook(t)
		crashed, op := j.run(func() { r.reboot(t) })
		j.at = 0
		if !crashed {
			t.Logf("startup rollback has %d crash points", at-1)
			break
		}
		// keep starting whatever is there, as launchd would, B crashing each time
		var v string
		var s2 State
		for i := 0; i < 2*MaxStarts+2; i++ {
			v, _, s2 = r.reboot(t)
			if v != "B" {
				break
			}
		}
		switch {
		case v != "A":
			bad = append(bad, fmt.Sprintf("crash before %q: after the reboots %s runs, %s (I1/loop)", op, v, dump(s2)))
		case s2.Failed != "B":
			bad = append(bad, fmt.Sprintf("crash before %q: A is back but B is not remembered as failed: %s, will be installed again", op, dump(s2)))
		}
	}
	for _, b := range bad {
		t.Error(b)
	}
}

// An install over an unconfirmed one (user's "install now" / pendingMax).
func TestCrashAtEveryStepOfAnInstallOverAPendingOne(t *testing.T) {
	var bad []string
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
			if err := Swap(r.p, st, "B", &s); err != nil {
				t.Fatalf("swap: %v", err)
			}
			_ = s.Save(r.file)
		})
		j.at = 0
		if !crashed {
			t.Logf("supersede has %d crash points", at-1)
			break
		}
		v, _, s2 := r.reboot(t)
		switch {
		case v != "B" && v != "C":
			bad = append(bad, fmt.Sprintf("crash before %q: install path holds %s (I1)", op, v))
		case s2.Pending == nil || r.kept() != "A":
			bad = append(bad, fmt.Sprintf("crash before %q: %s runs unconfirmed with no way back to A: %s kept=%s (I2)", op, v, dump(s2), r.kept()))
		case s2.Pending.To != v:
			bad = append(bad, fmt.Sprintf("crash before %q: %s runs, state says %s (I3)", op, v, dump(s2)))
		}
	}
	for _, b := range bad {
		t.Error(b)
	}
}

// The confirmation's rollback (judge): Rollback, save, restart.
func TestCrashAtEveryStepOfAConfirmRollback(t *testing.T) {
	var bad []string
	for at := 1; ; at++ {
		r := newRig(t)
		s := State{}
		must(t, Swap(r.p, r.stageVersion(t, "B"), "A", &s))
		s.Pending.Starts = 1
		must(t, s.Save(r.file))
		j := &injector{at: at}
		j.hook(t)
		crashed, op := j.run(func() {
			if err := Rollback(r.p, &s, "capture did not work"); err == nil {
				_ = s.Save(r.file)
			}
		})
		j.at = 0
		if !crashed {
			t.Logf("confirm rollback has %d crash points", at-1)
			break
		}
		v, _, s2 := r.reboot(t)
		switch {
		case v != "A" && v != "B":
			bad = append(bad, fmt.Sprintf("crash before %q: install path holds %s (I1)", op, v))
		case v == "A" && s2.Failed != "B":
			bad = append(bad, fmt.Sprintf("crash before %q: A is back, B not marked failed: %s (B is auto-installed again)", op, dump(s2)))
		case v == "B" && (s2.Pending == nil || r.kept() != "A"):
			bad = append(bad, fmt.Sprintf("crash before %q: B runs with no way back: %s kept=%s (I2)", op, dump(s2), r.kept()))
		}
	}
	for _, b := range bad {
		t.Error(b)
	}
}

func TestCrashAtEveryStepOfACommit(t *testing.T) {
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
		if v, _, _ := r.reboot(t); v != "B" {
			t.Errorf("crash before %q: %s", op, v)
		}
	}
}

var _ = time.Now
