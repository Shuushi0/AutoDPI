//go:build !windows

package update

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/paths"
)

// A manual install or removal ends an update that was waiting to be
// confirmed: its record and the copy kept for its rollback go.
func TestForgetEndsAPendingUpdate(t *testing.T) {
	root := t.TempDir()
	p := paths.Set{Support: root, Installed: filepath.Join(root, "autodpi")}
	old := AppPath
	AppPath = filepath.Join(root, "AutoDPI.app")
	t.Cleanup(func() { AppPath = old })
	for f, body := range map[string]string{p.Installed: "new", oldPath(p.Installed): "old", newPath(p.Installed): "half"} {
		if err := os.WriteFile(f, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s := State{Pending: &Pending{From: "0.1.0", To: "0.1.1"}, Failed: "0.0.9", Skipped: "0.2.0"}
	if err := s.Save(StateFile(p)); err != nil {
		t.Fatal(err)
	}
	Forget(p)
	got := LoadState(StateFile(p))
	if got.Pending != nil || got.Swap != nil {
		t.Errorf("the update is still in flight: %+v", got)
	}
	if got.Failed != "0.0.9" || got.Skipped != "0.2.0" {
		t.Errorf("what the user decided earlier was lost: %+v", got)
	}
	for _, f := range []string{oldPath(p.Installed), newPath(p.Installed)} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s is still there: a later rollback would use it", filepath.Base(f))
		}
	}
	if b, _ := os.ReadFile(p.Installed); string(b) != "new" {
		t.Errorf("the installed program was touched: %q", b)
	}
	// And the next start has nothing to take back.
	if a := Resume(p, "0.1.1", &got); a != Nothing {
		t.Errorf("Resume after Forget = %v, want Nothing", a)
	}
}

func TestCompareSuffixes(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.2.0-rc10", "0.2.0-rc9", 1},
		{"0.2.0-rc.10", "0.2.0-rc.9", 1},
		{"0.2.0-beta2", "0.2.0-rc1", -1},
		{"0.2.0-rc1", "0.2.0", -1},
		{"0.2.0-rc1", "0.2.0-rc1", 0},
		{"0.2.0-alpha", "0.2.0-alpha1", -1},
		{"0.2.1-rc1", "0.2.0", 1},
	} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
