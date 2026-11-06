//go:build windows

package sysx

// Tests for fix-list W1/W3/W4. Never run on a real machine yet. Those that
// need an elevated token Skip otherwise.

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEnsureTrustedDirCreatesLockedDown(t *testing.T) {
	if !IsRoot() {
		t.Skip("needs an elevated shell")
	}
	dir := filepath.Join(t.TempDir(), "AutoDPI")
	if err := EnsureTrustedDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckTrustedDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckProtectedDACL(dir, windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid, windows.WinBuiltinUsersSid); err != nil {
		t.Fatal(err)
	}
	// Idempotent on an existing directory.
	if err := EnsureTrustedDir(dir); err != nil {
		t.Fatalf("second call: %v", err)
	}
	// Users must not inherit anything into files below it (W3).
	f := filepath.Join(dir, "state.json")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(f, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if str := sd.String(); strings.Contains(str, ";;;BU)") || strings.Contains(str, ";;;AU)") || strings.Contains(str, ";;;WD)") {
		t.Errorf("a file in the locked-down directory is readable by ordinary users: %s", str)
	}
}

func TestEnsureTrustedDirRefusesJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "AutoDPI")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction: %v: %s", err, out)
	}
	if err := EnsureTrustedDir(link); err == nil {
		t.Fatal("a junction at the install path was accepted")
	}
}

func TestEnsureTrustedDirRefusesFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "AutoDPI")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureTrustedDir(f); err == nil {
		t.Fatal("a plain file at the install path was accepted")
	}
}

func TestOwnByRootOnOwnFile(t *testing.T) {
	if !IsRoot() {
		t.Skip("needs an elevated shell")
	}
	f := filepath.Join(t.TempDir(), "x.exe")
	if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := OwnByRoot(f); err != nil {
		t.Fatalf("OwnByRoot on a file this elevated process created: %v", err)
	}
}

// config.json in the locked-down directory: signed-in users may read it (the
// tray app runs unelevated), only SYSTEM and Administrators change it.
func TestShareConfigLetsSignedInUsersRead(t *testing.T) {
	if !IsRoot() {
		t.Skip("needs an elevated shell")
	}
	dir := filepath.Join(t.TempDir(), "AutoDPI")
	if err := EnsureTrustedDir(dir); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "config.json")
	if err := os.WriteFile(f, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ShareConfig(f); err != nil {
		t.Fatal(err)
	}
	if err := CheckProtectedDACL(f, windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid, windows.WinInteractiveSid); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(f, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if str := sd.String(); !strings.Contains(str, "(A;;FR;;;IU)") {
		t.Errorf("interactive users cannot read config.json: %s", str)
	}
	if err := ShareConfig(dir); err == nil {
		t.Error("a directory accepted")
	}
	if err := ShareConfig(filepath.Join(dir, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}
