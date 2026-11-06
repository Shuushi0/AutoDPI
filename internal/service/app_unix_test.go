//go:build !windows

package service

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/update"
)

// appFixture points the install at a temporary /Applications and records the
// commands instead of running them, so no test touches a real running app.
func appFixture(t *testing.T) (self string, calls *[]string) {
	t.Helper()
	root := t.TempDir()
	old := update.AppPath
	update.AppPath = filepath.Join(root, "Applications", "AutoDPI.app")
	t.Cleanup(func() { update.AppPath = old })
	if err := os.MkdirAll(filepath.Dir(update.AppPath), 0o755); err != nil {
		t.Fatal(err)
	}
	oldRun := runApp
	t.Cleanup(func() { runApp = oldRun })
	calls = &[]string{}
	runApp = func(name string, args ...string) error {
		*calls = append(*calls, name+" "+strings.Join(args, " "))
		if strings.HasSuffix(name, "pgrep") {
			return errors.New("no process")
		}
		return nil
	}
	return filepath.Join(root, "release", "autodpi"), calls
}

func writeApp(t *testing.T, dir, content string) {
	t.Helper()
	exe := filepath.Join(dir, "AutoDPI.app", "Contents", "MacOS", "AutoDPI")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func installedApp(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(update.AppPath, "Contents", "MacOS", "AutoDPI"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallTrayWithoutAppNextToBinary(t *testing.T) {
	self, calls := appFixture(t)
	writeApp(t, filepath.Dir(filepath.Dir(update.AppPath)), "unrelated")
	if err := InstallTray(paths.Set{}, self); !errors.Is(err, ErrTrayAbsent) {
		t.Fatalf("err = %v, want ErrTrayAbsent", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("ran %v with nothing to install", *calls)
	}
}

func TestInstallTrayReplacesAndReopensAsUser(t *testing.T) {
	self, calls := appFixture(t)
	writeApp(t, filepath.Dir(update.AppPath), "old")
	writeApp(t, filepath.Dir(self), "new")
	uid := os.Getuid()
	t.Setenv("SUDO_UID", strconv.Itoa(uid))
	t.Setenv("SUDO_USER", "someone")
	if uid == 0 {
		t.Skip("needs a non-root uid")
	}
	if err := InstallTray(paths.Set{}, self); err != nil {
		t.Fatal(err)
	}
	if got := installedApp(t); got != "new" {
		t.Fatalf("installed %q", got)
	}
	if len(*calls) != 3 {
		t.Fatalf("calls = %q", *calls)
	}
	if !strings.HasPrefix((*calls)[0], "/usr/bin/pkill -f ^") || !strings.HasSuffix((*calls)[0], "/Contents/MacOS/") {
		t.Fatalf("close = %q", (*calls)[0])
	}
	want := "/bin/launchctl asuser " + strconv.Itoa(uid) + " /usr/bin/sudo -u someone /usr/bin/open " + update.AppPath
	if (*calls)[2] != want {
		t.Fatalf("open = %q, want %q", (*calls)[2], want)
	}
}

func TestInstallTrayRootShellDoesNotOpenAsRoot(t *testing.T) {
	self, calls := appFixture(t)
	writeApp(t, filepath.Dir(self), "new")
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_USER", "")
	if err := InstallTray(paths.Set{}, self); err != nil {
		t.Fatal(err)
	}
	if got := installedApp(t); got != "new" {
		t.Fatalf("installed %q", got)
	}
	if len(*calls) != 0 {
		t.Fatalf("ran %q without knowing the user", *calls)
	}
}

// A copy that fails must leave the installed app and the running one alone.
func TestInstallTrayFailedCopyKeepsRunningApp(t *testing.T) {
	self, calls := appFixture(t)
	writeApp(t, filepath.Dir(update.AppPath), "old")
	writeApp(t, filepath.Dir(self), "new")
	link := filepath.Join(filepath.Dir(self), "AutoDPI.app", "Contents", "link")
	if err := os.Symlink("/etc/hosts", link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_UID", strconv.Itoa(os.Getuid()+1))
	t.Setenv("SUDO_USER", "someone")
	if err := InstallTray(paths.Set{}, self); err == nil || errors.Is(err, ErrTrayAbsent) {
		t.Fatalf("err = %v, want a copy error", err)
	}
	if got := installedApp(t); got != "old" {
		t.Fatalf("installed %q", got)
	}
	if len(*calls) != 0 {
		t.Fatalf("ran %q after a failed copy", *calls)
	}
	ents, err := os.ReadDir(filepath.Dir(update.AppPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("left behind: %v", ents)
	}
}

func TestSudoUser(t *testing.T) {
	for _, c := range []struct {
		uid, user string
		ok        bool
	}{
		{"501", "someone", true},
		{"0", "root", false},
		{"", "someone", false},
		{"501", "", false},
		{"x", "someone", false},
	} {
		t.Setenv("SUDO_UID", c.uid)
		t.Setenv("SUDO_USER", c.user)
		if _, user := sudoUser(); (user != "") != c.ok {
			t.Errorf("%q %q: user = %q", c.uid, c.user, user)
		}
	}
}
