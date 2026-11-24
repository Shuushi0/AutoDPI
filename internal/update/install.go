package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fsx"
	"github.com/Shuushi0/AutoDPI/internal/paths"
)

// Every call that changes the disk goes through these, so that a test can
// stop the process before any one of them and look at what a start after
// that finds (crash_test.go).
var (
	fsRename    = fsx.Rename
	fsRemoveAll = os.RemoveAll
	fsLink      = os.Link
	fsWriteFile = fsx.WriteFile
	fsOpenFile  = os.OpenFile
	fsMkdirAll  = os.MkdirAll
)

// State is what the updater keeps between runs, in StateFile.
type State struct {
	Checked time.Time `json:"checked,omitempty"`
	ETag    string    `json:"etag,omitempty"`
	Latest  *Release  `json:"latest,omitempty"`  // the newest release seen, nil when this is the newest
	Skipped string    `json:"skipped,omitempty"` // a version the user chose to skip
	Failed  string    `json:"failed,omitempty"`  // a version that was rolled back: not installed automatically again
	Pending *Pending  `json:"pending,omitempty"` // a swap waiting for the new daemon to prove itself
	// Swap is a swap that was begun: written before the first file moves, and
	// turned into Pending when the last one has. Whatever the process dies of
	// in between, the next start finds out from it what happened (Resume).
	Swap *Pending `json:"swap,omitempty"`
	Last *Result  `json:"last,omitempty"`
	// FinishRollback: the program went back to the previous version and a
	// file beside it (the app) could not be put back then. The next start
	// tries again, and the copies kept for it stay until it has.
	FinishRollback bool `json:"finish_rollback,omitempty"`
	// By is the version that made the last check: the ETag is only an answer
	// to "anything newer than that?".
	By string `json:"by,omitempty"`
	// Fetches counts downloads of one version that arrived and did not match
	// their signed hashes.
	Fetches *Tries `json:"fetches,omitempty"`
	// Tries counts installs of one version that failed for a reason that may
	// pass (a full disk, a file in use, a self test that could not run).
	Tries *Tries `json:"tries,omitempty"`
}

// Tries is how often installing Version has failed.
type Tries struct {
	Version string `json:"version"`
	N       int    `json:"n"`
}

// MaxTries is how often an install that failed for a passing reason is tried
// before the version is left alone.
const MaxTries = 3

// Pending is a swap the new daemon has not confirmed yet.
type Pending struct {
	From   string    `json:"from"`
	To     string    `json:"to"`
	At     time.Time `json:"at"`
	Starts int       `json:"starts"` // daemon starts since the swap
}

// Result is how the last update ended.
type Result struct {
	From  string    `json:"from"`
	To    string    `json:"to"`
	At    time.Time `json:"at"`
	OK    bool      `json:"ok"`
	Error string    `json:"error,omitempty"`
}

// MaxStarts is how often the new daemon may start without confirming itself
// before the old one comes back: it crashed or was restarted that often.
const MaxStarts = 3

// AppPath is the macOS menu bar app an update replaces when it is there.
var AppPath = "/Applications/AutoDPI.app"

func StateFile(p paths.Set) string { return filepath.Join(p.Support, "update.json") }

// WorkDir is where releases are downloaded and unpacked.
func WorkDir(p paths.Set) string { return filepath.Join(p.Support, "update") }

func LoadState(file string) State {
	var s State
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func (s State) Save(file string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsWriteFile(file, b, 0o644)
}

// target is one file or bundle an update replaces.
type target struct {
	src, dst string
	optional bool // replaced only when the user has it
}

func targets(p paths.Set, stage string) []target {
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	ts := []target{{src: filepath.Join(stage, "autodpi"+exe), dst: p.Installed}}
	switch runtime.GOOS {
	case "darwin":
		ts = append(ts, target{src: filepath.Join(stage, "AutoDPI.app"), dst: AppPath, optional: true})
	case "windows":
		ts = append(ts, target{src: filepath.Join(stage, "autodpi-tray.exe"), dst: filepath.Join(p.Support, "autodpi-tray.exe"), optional: true})
	}
	return ts
}

func oldPath(dst string) string {
	return filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".old")
}
func newPath(dst string) string {
	return filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".new")
}

// Apply is Probe followed by Swap.
func Apply(p paths.Set, st Staged, from string, s *State) error {
	if err := Probe(context.Background(), p, st); err != nil {
		return err
	}
	return Swap(p, st, from, s)
}

// Probe runs the staged release's own checks on this machine and changes
// nothing. It can take minutes on a slow machine: callers do not hold locks
// that a status request needs. ErrSelfTest is a verdict on the release; any
// other error is about this attempt and may pass.
func Probe(ctx context.Context, p paths.Set, st Staged) error {
	exe := targets(p, st.Dir)[0].src
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("%w: %v", ErrGone, err)
	}
	return selfTest(ctx, exe, st.Version)
}

// Swap puts the staged release in for version from and records it as pending
// in s, which it also saves. The caller restarts the service. On an error
// nothing is swapped.
//
// The order is what a power cut or a crash at any point must survive:
//
//  1. the new files are copied beside the old ones and forced to disk;
//  2. the intent (State.Swap) is saved, and nothing moves unless that worked:
//     a new version without a record could never be confirmed or taken back;
//  3. each file is put in place, the program itself without a moment in which
//     there is none at its path (see replace);
//  4. the intent becomes Pending and is saved again. If that save fails or
//     never happens, the next start reads the intent and does the same.
func Swap(p paths.Set, st Staged, from string, s *State) error {
	if s.Swap != nil {
		// An earlier try's: only a start settles it (Resume). What can be
		// done from here is to make sure there is something to start.
		Heal(p)
		return ErrHalfSwapped
	}
	Heal(p)
	ts := targets(p, st.Dir)
	if _, err := os.Lstat(ts[0].dst); err != nil {
		return fmt.Errorf("%s is not at its place and no copy of it could be put back: %w", filepath.Base(ts[0].dst), err)
	}
	var use []target
	for _, t := range ts {
		if t.optional {
			if _, err := os.Stat(t.dst); err != nil {
				continue // not installed here
			}
			if _, err := os.Stat(t.src); err != nil {
				continue // not in this archive
			}
		}
		_ = fsRemoveAll(newPath(t.dst))
		if err := copyTree(t.src, newPath(t.dst)); err != nil {
			cleanNew(use)
			_ = fsRemoveAll(newPath(t.dst))
			return err
		}
		matchOwner(t.dst, newPath(t.dst))
		use = append(use, t)
	}
	// On top of an update that was never confirmed (the user's "install now",
	// or one that waited for days): what is kept to go back to stays the last
	// version that WAS confirmed. The unconfirmed one is moved elsewhere and
	// is gone with the next cleanup; were it kept instead, a rollback of this
	// update would land on a version nobody ever saw working.
	over := s.Pending != nil
	if over {
		from = s.Pending.From
	}
	file := StateFile(p)
	intent := &Pending{From: from, To: st.Version, At: time.Now()}
	s.Swap = intent
	if err := s.Save(file); err != nil {
		s.Swap = nil
		cleanNew(use)
		return fmt.Errorf("record the update before it starts: %w", err)
	}
	type moved struct {
		t     target
		aside string
	}
	var done []moved
	back := func() (whole bool) {
		whole = true
		for _, m := range done {
			if err := restore(m.t.dst, m.aside); err != nil {
				whole = false
			}
		}
		if !whole {
			// Something new is still in place, or nothing is (the way back
			// failed too, as it does while an antivirus holds the files).
			// The intent stays, on disk and in s, and so do the new copies:
			// if what stayed is the program, the next start finds itself to
			// be the new version, treats it as pending with the copy to go
			// back to still there, and puts the app beside it in place too.
			// Cleared, that version would have been permanent.
			return false
		}
		cleanNew(use)
		s.Swap = nil
		_ = s.Save(file)
		return true
	}
	for _, t := range use {
		aside := asideFor(t.dst, over)
		if err := replace(t.dst, newPath(t.dst), aside); err != nil {
			if _, serr := os.Lstat(t.dst); serr != nil {
				// It was moved aside and nothing took its place: this one has
				// to be put back as well. Left out, the swap counted as
				// undone with nothing at the path, and the next try deleted
				// the copy that was aside as a leftover.
				done = append(done, moved{t, aside})
			}
			if !back() {
				return fmt.Errorf("%w: %v", ErrHalfSwapped, err)
			}
			return err
		}
		done = append(done, moved{t, aside})
	}
	s.Pending, s.Swap = intent, nil
	// Should this save fail, the files are in place and the intent is on
	// disk: the start that follows settles it (Resume).
	_ = s.Save(file)
	return nil
}

// ErrHalfSwapped is Swap's answer when files were replaced, the swap then
// failed and not everything could be put back. What runs at the install path
// is undecided; the intent is recorded, and the next start of the service
// decides (Resume). The caller restarts the service and changes nothing else.
var ErrHalfSwapped = errors.New("the update was only partly put in place")

// asideFor is where the copy that an update replaces is kept: the place a
// rollback reads, unless that already holds the last confirmed version.
func asideFor(dst string, over bool) string {
	aside := oldPath(dst)
	if _, err := os.Lstat(aside); over && err == nil {
		aside = failedPath(dst)
	}
	clearPath(aside)
	return aside
}

// inPlace: a file can be replaced by a rename onto it. Not on Windows, where
// a program that runs can be renamed away but not written over.
var inPlace = runtime.GOOS != "windows"

// replace puts fresh at dst and what was at dst at aside.
//
// A regular file where inPlace holds is first given a second name (a hard
// link) and then replaced by one rename: there is no moment without a
// program at dst, whatever happens between the two calls. A folder, and any
// file on Windows, takes two renames; the moment in between is as short as
// the system makes it, and both are retried there, because an antivirus
// reading what was just written fails the rename for a moment and a failed
// way back would leave nothing at dst at all.
func replace(dst, fresh, aside string) error {
	dir := filepath.Dir(dst)
	defer fsx.SyncDir(dir)
	if fi, err := os.Lstat(dst); err == nil && fi.Mode().IsRegular() && inPlace {
		if err := fsLink(dst, aside); err == nil {
			if err := fsRename(fresh, dst); err != nil {
				_ = os.Remove(aside)
				return fmt.Errorf("put the new %s in place: %w", filepath.Base(dst), err)
			}
			return nil
		}
	}
	if err := fsRename(dst, aside); err != nil {
		return fmt.Errorf("move %s aside: %w", dst, err)
	}
	if err := fsRename(fresh, dst); err != nil {
		if rerr := renameBack(aside, dst); rerr != nil {
			return fmt.Errorf("put the new %s in place: %w; the previous one could not be put back either (%v) and is at %s", filepath.Base(dst), err, rerr, aside)
		}
		return fmt.Errorf("put the new %s in place: %w", filepath.Base(dst), err)
	}
	return nil
}

// renameBack is the rename that puts a file back where nothing is: tried for
// much longer than any other, because giving up leaves the path empty. On
// Windows what fails it is another program holding the file (an antivirus
// reading a freshly written 30 MB program can take many seconds), and
// fsRename already waits a second there each time.
func renameBack(from, to string) error {
	err := fsRename(from, to)
	for i := 0; err != nil && i < backTries; i++ {
		if _, serr := os.Lstat(from); serr != nil {
			break
		}
		time.Sleep(backPause)
		err = fsRename(from, to)
	}
	return err
}

// Variables so that tests need not wait.
var (
	backTries = 30
	backPause = 100 * time.Millisecond
)

// Heal puts a copy back wherever a file an update replaces is missing from
// its place although a copy of it was kept aside: the one case in which the
// kept copies must not be treated as leftovers. Preferred is the previous
// version, then whatever else there is: any program at the path can be
// started and can settle the rest, none cannot. It reports whether the
// program itself is at its place afterwards.
func Heal(p paths.Set) bool {
	ts := targets(p, "")
	for _, t := range ts {
		if _, err := os.Lstat(t.dst); err == nil {
			continue
		}
		cands := []string{oldPath(t.dst)}
		more, _ := filepath.Glob(oldPath(t.dst) + "-*")
		cands = append(cands, more...)
		cands = append(cands, failedPath(t.dst))
		more, _ = filepath.Glob(failedPath(t.dst) + "-*")
		cands = append(cands, more...)
		for _, c := range cands {
			if _, err := os.Lstat(c); err != nil {
				continue
			}
			if fsRename(c, t.dst) == nil {
				fsx.SyncDir(filepath.Dir(t.dst))
				break
			}
		}
	}
	_, err := os.Lstat(ts[0].dst)
	return err == nil
}

// restore puts the copy at aside back at dst.
func restore(dst, aside string) error {
	defer fsx.SyncDir(filepath.Dir(dst))
	if fi, err := os.Lstat(aside); err == nil && fi.Mode().IsRegular() && inPlace {
		return fsRename(aside, dst) // over the new one, in one step
	}
	gone := failedPath(dst) + fmt.Sprintf("-%d", time.Now().UnixNano())
	moved := fsRename(dst, gone) == nil
	if err := fsRename(aside, dst); err != nil {
		// One of the two has to end up at the path: the copy to go back to
		// if it lets itself be moved after all, else what was there.
		if renameBack(aside, dst) == nil {
			_ = fsRemoveAll(gone)
			return nil
		}
		if moved {
			_ = renameBack(gone, dst)
		}
		return err
	}
	_ = fsRemoveAll(gone) // fails for a running program on Windows: cleanup's job
	return nil
}

// clearPath frees path for a rename onto it. What cannot be removed is
// renamed out of the way: on Windows a tray app that never restarted after
// the last update still runs from the file kept aside then, in this session
// or another user's, and must not stand in the way of a whole update.
func clearPath(path string) {
	_ = fsRemoveAll(path)
	if _, err := os.Lstat(path); err == nil {
		_ = fsRename(path, fmt.Sprintf("%s-%d", path, time.Now().UnixNano()))
	}
}

// ReplaceTree puts a copy of src at dst in one step, keeping the owner of the
// copy it replaces. On an error dst is as it was.
func ReplaceTree(src, dst string) error {
	// Names of its own, which the updater neither uses nor cleans up: this
	// runs right after the service was started, whose first act is to clear
	// the updater's leftovers (Resume). Sharing the updater's names meant
	// that start could delete the copy being made here half way, and the
	// old app with it.
	base := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst))
	fresh, old := base+".installing", base+".replaced"
	_ = fsRemoveAll(fresh)
	if err := copyTree(src, fresh); err != nil {
		_ = fsRemoveAll(fresh)
		return err
	}
	matchOwner(dst, fresh)
	_ = fsRemoveAll(old)
	err := fsRename(dst, old)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = fsRemoveAll(fresh)
		return fmt.Errorf("move %s aside: %w", dst, err)
	}
	existed := err == nil
	if err := fsRename(fresh, dst); err != nil {
		if existed {
			_ = fsRename(old, dst)
		}
		_ = fsRemoveAll(fresh)
		return fmt.Errorf("put the new %s in place: %w", filepath.Base(dst), err)
	}
	_ = fsRemoveAll(old)
	return nil
}

func cleanNew(ts []target) {
	for _, t := range ts {
		_ = fsRemoveAll(newPath(t.dst))
	}
}

// ErrSelfTest is the answer when the new version gave a verdict against
// itself on this machine: it is another version than the release says, or its
// self test found its helper programs unusable here. Nothing was changed, and
// downloading the same release again would end the same way. A self test that
// could not run or finish (a timeout while antivirus scans the new files, a
// full disk) is not this error: that may pass.
var ErrSelfTest = errors.New("the new version failed its self test")

// ErrGone is Probe's answer when the download is no longer there.
var ErrGone = errors.New("the downloaded version is gone")

// SelfTestVerdict is the exit code of `autodpi selftest` when the checks ran
// and found this copy unusable here; any other failure exits with 1.
const SelfTestVerdict = 3

func selfTest(parent context.Context, exe, version string) error {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "version")
	hide(cmd)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("the new autodpi did not answer: %w", err)
	}
	if !strings.HasPrefix(string(out), "autodpi "+version+" ") {
		return fmt.Errorf("%w: the new autodpi says %q, expected version %s", ErrSelfTest, strings.TrimSpace(string(out)), version)
	}
	ctx2, cancel2 := context.WithTimeout(parent, 2*time.Minute)
	defer cancel2()
	cmd = exec.CommandContext(ctx2, exe, "selftest")
	// Killed at the limit or by a stop, it may leave a helper behind that
	// still holds the output pipe: not waited for.
	cmd.WaitDelay = 2 * time.Second
	hide(cmd)
	msg, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	last := strings.TrimSpace(string(msg))
	if i := strings.LastIndexByte(last, '\n'); i >= 0 {
		last = strings.TrimSpace(last[i+1:])
	}
	var exit *exec.ExitError
	if ctx2.Err() == nil && errors.As(err, &exit) && exit.ExitCode() == SelfTestVerdict {
		return fmt.Errorf("%w: %s", ErrSelfTest, last)
	}
	if ctx2.Err() != nil {
		return fmt.Errorf("the new version's self test did not finish in 2 minutes")
	}
	return fmt.Errorf("the new version's self test could not run: %s (%v)", last, err)
}

// Action is what Resume decided.
type Action int

const (
	Nothing    Action = iota
	Confirm           // this daemon is a fresh update: confirm it once it runs well (Commit)
	RolledBack        // the update kept failing and the old version is back: restart into it
)

// Resume runs once when the daemon starts, before anything else.
func Resume(p paths.Set, current string, s *State) Action {
	Heal(p)
	if sw := s.Swap; sw != nil {
		// A swap was begun and its end never recorded (see Swap).
		s.Swap = nil
		if sw.To == current {
			// It got as far as the program: this is the new version. What
			// was still waiting beside it (the app) is put in place now.
			over := s.Pending != nil
			for _, t := range targets(p, "")[1:] {
				if _, err := os.Lstat(newPath(t.dst)); err != nil {
					continue
				}
				if _, err := os.Lstat(t.dst); err != nil {
					_ = fsRename(newPath(t.dst), t.dst)
					continue
				}
				_ = replace(t.dst, newPath(t.dst), asideFor(t.dst, over))
			}
			sw.Starts = 0
			s.Pending = sw
		} else {
			// It did not: this is the version from before, whose own record
			// (a Pending of its own, or none) still holds.
			cleanNew(targets(p, ""))
		}
	}
	if pd := s.Pending; pd != nil && pd.To != current && pd.From == current {
		// A way back that was begun and never recorded (the program went back
		// and the process died before the state was saved): finish it and
		// remember the version, or it would be installed again at once. A
		// manual install does not come by here: it ends the update first
		// (Forget).
		s.FinishRollback = true
		s.Failed = pd.To
		s.Last = &Result{From: pd.From, To: pd.To, At: time.Now(), Error: "the new version was taken back"}
	}
	if s.Pending == nil || s.Pending.To != current {
		// No update in flight, or this is not the version it installed (it was
		// rolled back, or installed again by hand): leftovers can go.
		s.Pending = nil
		if s.FinishRollback {
			// The files beside the program that did not go back with it.
			// While one still does not, its kept copy is no leftover.
			s.FinishRollback = false
			for _, t := range targets(p, "")[1:] {
				if _, err := os.Lstat(oldPath(t.dst)); err == nil && putBack(t.dst) != nil {
					s.FinishRollback = true
				}
			}
			if s.FinishRollback {
				return Nothing
			}
		}
		cleanup(p)
		return Nothing
	}
	s.Pending.Starts++
	if s.Pending.Starts > MaxStarts {
		if err := Rollback(p, s, "the new version stopped again and again"); err != nil {
			// Not restored: this version runs on, still unconfirmed. Counting
			// further would only try the same again at every start.
			s.Pending.Starts = MaxStarts
			s.Last = &Result{From: s.Pending.From, To: s.Pending.To, At: time.Now(), Error: "could not go back to " + s.Pending.From + ": " + err.Error()}
			return Confirm
		}
		return RolledBack
	}
	return Confirm
}

// Commit confirms the pending update: the old files go.
//
// The record is saved before anything is removed: with the order the other
// way round, a crash in between left "pending" on disk with no previous copy
// behind it, a rollback that could only fail and newer releases held back for
// days. When the save fails nothing changes and the error is returned.
func Commit(p paths.Set, s *State) error {
	if s.Pending == nil {
		return nil
	}
	pending, last, latest := s.Pending, s.Last, s.Latest
	s.Last = &Result{From: s.Pending.From, To: s.Pending.To, At: time.Now(), OK: true}
	if s.Latest != nil && Compare(s.Latest.Version, s.Pending.To) <= 0 {
		s.Latest = nil
	}
	s.Pending = nil
	if err := s.Save(StateFile(p)); err != nil {
		s.Pending, s.Last, s.Latest = pending, last, latest
		return err
	}
	cleanup(p)
	return nil
}

// Rollback puts the previous files back and remembers the version as failed.
// It runs inside the version it removes, and Windows neither deletes nor
// overwrites a program that is running, but it does let it be renamed: the
// new files are moved aside first and removed by a later cleanup. When the
// program itself cannot be put back, nothing is recorded and the error says
// why: a rollback that did not happen must not be reported as one.
func Rollback(p paths.Set, s *State, why string) error {
	if s.Pending == nil {
		return nil
	}
	for i, t := range targets(p, "") {
		if _, err := os.Stat(oldPath(t.dst)); err != nil {
			if i == 0 {
				return fmt.Errorf("the previous %s is gone: %w", filepath.Base(t.dst), err)
			}
			continue
		}
		if err := putBack(t.dst); err != nil {
			if i == 0 {
				Heal(p) // whatever happened, something has to be at the path
				return err
			}
			// The apps beside it are not worth staying on a broken service
			// for: the next start puts them back (Resume), and until then
			// their kept copies stay.
			s.FinishRollback = true
		}
	}
	s.Failed = s.Pending.To
	s.Last = &Result{From: s.Pending.From, To: s.Pending.To, At: time.Now(), Error: why}
	s.Pending = nil
	return nil
}

// putBack replaces dst with the copy an update moved aside.
func putBack(dst string) error {
	if err := restore(dst, oldPath(dst)); err != nil {
		return fmt.Errorf("put the previous %s back: %w", filepath.Base(dst), err)
	}
	return nil
}

// Forget ends an update in flight without deciding it: whoever installs or
// removes the program by hand has decided. Without this the record of a
// pending update outlived a manual install of the same version, and its
// rollback later put the version from before the update over what the user
// had just installed.
func Forget(p paths.Set) {
	file := StateFile(p)
	s := LoadState(file)
	if s.Pending != nil || s.Swap != nil || s.Tries != nil || s.FinishRollback {
		s.Pending, s.Swap, s.Tries, s.FinishRollback = nil, nil, nil, false
		_ = s.Save(file)
	}
	cleanup(p)
}

func failedPath(dst string) string {
	return filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".failed")
}

// cleanup removes what a finished update leaves: the previous files, what a
// rollback moved aside and the download folder. A file still in use (an old
// tray app that has not restarted yet on Windows) stays until the next start.
func cleanup(p paths.Set) {
	// Never while a kept copy is the only copy there is.
	Heal(p)
	// Temporary files of a state save that a power cut left behind (a save
	// under way has one a few milliseconds old).
	if tmps, _ := filepath.Glob(filepath.Join(filepath.Dir(StateFile(p)), "."+filepath.Base(StateFile(p))+".tmp-*")); len(tmps) > 0 {
		for _, f := range tmps {
			if fi, err := os.Stat(f); err == nil && time.Since(fi.ModTime()) > time.Hour {
				_ = os.Remove(f)
			}
		}
	}
	for _, t := range targets(p, "") {
		_ = fsRemoveAll(oldPath(t.dst))
		_ = fsRemoveAll(newPath(t.dst))
		_ = fsRemoveAll(failedPath(t.dst))
		for _, pattern := range []string{oldPath(t.dst) + "-*", failedPath(t.dst) + "-*"} {
			aside, _ := filepath.Glob(pattern)
			for _, f := range aside {
				_ = fsRemoveAll(f) // see clearPath; one still running stays for the next start
			}
		}
	}
	_ = fsRemoveAll(WorkDir(p))
}

// copyTree copies a file or a directory tree, keeping the executable bits.
func copyTree(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case fi.IsDir():
		if err := fsMkdirAll(dst, 0o755); err != nil {
			return err
		}
		ents, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		fsx.SyncDir(dst)
		return nil
	case fi.Mode().IsRegular():
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := fsOpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		// To disk before it is renamed into place: a power cut after the
		// rename must not find an empty program there.
		if err := out.Sync(); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return errors.New(src + " is not a regular file or folder")
}
