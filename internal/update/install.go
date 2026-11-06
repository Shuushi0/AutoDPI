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

	"github.com/Shuushi0/AutoDPI/internal/paths"
)

// State is what the updater keeps between runs, in StateFile.
type State struct {
	Checked time.Time `json:"checked,omitempty"`
	ETag    string    `json:"etag,omitempty"`
	Latest  *Release  `json:"latest,omitempty"`  // the newest release seen, nil when this is the newest
	Skipped string    `json:"skipped,omitempty"` // a version the user chose to skip
	Failed  string    `json:"failed,omitempty"`  // a version that was rolled back: not installed automatically again
	Pending *Pending  `json:"pending,omitempty"` // a swap waiting for the new daemon to prove itself
	Last    *Result   `json:"last,omitempty"`
}

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
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, file)
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

// Apply swaps the staged release in for version from and records it as
// pending in s; the caller saves s and restarts the service. On an error
// nothing is swapped.
func Apply(p paths.Set, st Staged, from string, s *State) error {
	ts := targets(p, st.Dir)
	if err := selfTest(ts[0].src, st.Version); err != nil {
		return err
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
		_ = os.RemoveAll(newPath(t.dst))
		if err := copyTree(t.src, newPath(t.dst)); err != nil {
			cleanNew(use)
			_ = os.RemoveAll(newPath(t.dst))
			return err
		}
		matchOwner(t.dst, newPath(t.dst))
		use = append(use, t)
	}
	var done []target
	for _, t := range use {
		_ = os.RemoveAll(oldPath(t.dst))
		if err := os.Rename(t.dst, oldPath(t.dst)); err != nil {
			undo(done)
			cleanNew(use)
			return fmt.Errorf("move %s aside: %w", t.dst, err)
		}
		if err := os.Rename(newPath(t.dst), t.dst); err != nil {
			_ = os.Rename(oldPath(t.dst), t.dst)
			undo(done)
			cleanNew(use)
			return fmt.Errorf("put the new %s in place: %w", filepath.Base(t.dst), err)
		}
		done = append(done, t)
	}
	s.Pending = &Pending{From: from, To: st.Version, At: time.Now()}
	return nil
}

func undo(done []target) {
	for _, t := range done {
		_ = os.RemoveAll(t.dst)
		_ = os.Rename(oldPath(t.dst), t.dst)
	}
}

func cleanNew(ts []target) {
	for _, t := range ts {
		_ = os.RemoveAll(newPath(t.dst))
	}
}

// selfTest runs the new binary's version command: it must start on this
// machine and be the version the release says.
func selfTest(exe, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "version")
	hide(cmd)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("the new autodpi does not run: %w", err)
	}
	if !strings.HasPrefix(string(out), "autodpi "+version+" ") {
		return fmt.Errorf("the new autodpi says %q, expected version %s", strings.TrimSpace(string(out)), version)
	}
	return nil
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
	if s.Pending == nil || s.Pending.To != current {
		// No update in flight, or this is not the version it installed (it was
		// rolled back, or installed again by hand): leftovers can go.
		s.Pending = nil
		cleanup(p)
		return Nothing
	}
	s.Pending.Starts++
	if s.Pending.Starts > MaxStarts {
		Rollback(p, s, "the new version stopped again and again")
		return RolledBack
	}
	return Confirm
}

// Commit confirms the pending update: the old files go.
func Commit(p paths.Set, s *State) {
	if s.Pending == nil {
		return
	}
	s.Last = &Result{From: s.Pending.From, To: s.Pending.To, At: time.Now(), OK: true}
	if s.Latest != nil && Compare(s.Latest.Version, s.Pending.To) <= 0 {
		s.Latest = nil
	}
	s.Pending = nil
	cleanup(p)
}

// Rollback puts the previous files back and remembers the version as failed.
func Rollback(p paths.Set, s *State, why string) {
	if s.Pending == nil {
		return
	}
	for _, t := range targets(p, "") {
		if _, err := os.Stat(oldPath(t.dst)); err != nil {
			continue
		}
		_ = os.RemoveAll(t.dst)
		_ = os.Rename(oldPath(t.dst), t.dst)
	}
	s.Failed = s.Pending.To
	s.Last = &Result{From: s.Pending.From, To: s.Pending.To, At: time.Now(), Error: why}
	s.Pending = nil
}

// cleanup removes what a finished update leaves: the previous files and the
// download folder. A file still in use (an old tray app that has not
// restarted yet on Windows) stays until the next start.
func cleanup(p paths.Set) {
	for _, t := range targets(p, "") {
		_ = os.RemoveAll(oldPath(t.dst))
		_ = os.RemoveAll(newPath(t.dst))
	}
	_ = os.RemoveAll(WorkDir(p))
}

// copyTree copies a file or a directory tree, keeping the executable bits.
func copyTree(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case fi.IsDir():
		if err := os.MkdirAll(dst, 0o755); err != nil {
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
		return nil
	case fi.Mode().IsRegular():
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return errors.New(src + " is not a regular file or folder")
}
