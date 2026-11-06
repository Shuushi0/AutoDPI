//go:build windows

package sysx

// Area-5 review tests (Windows only). They are written to FAIL while the
// reviewed defect exists and to pass once it is fixed; tests that need an
// elevated token Skip otherwise. Run in an elevated PowerShell:
//   go test -run Area5 -v ./internal/sysx

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestArea5DirSDDLDecodes(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(dirSDDL)
	if err != nil {
		t.Fatal(err)
	}
	ctl, _, _ := sd.Control()
	if ctl&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("dirSDDL is not protected: control=%#x", ctl)
	}
	s := sd.String()
	for _, want := range []string{"(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)", "(A;;0x1200a9;;;BU)"} { // Users: the folder itself only (W3)
		if !strings.Contains(s, want) {
			t.Errorf("%s missing %s", s, want)
		}
	}
	if got := uint32(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE); got != 0x1200a9 {
		t.Errorf("0x1200a9 is not FILE_GENERIC_READ|EXECUTE (%#x)", got)
	}
}

func ownerOf(t *testing.T, path string) *windows.SID {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	o, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func trusted(o *windows.SID) bool { return isTrustedOwner(o) }

// A standard user may create C:\ProgramData\AutoDPI before the first
// install and then owns it; an owner keeps WRITE_DAC whatever the DACL says.
// Simulate that: directory owned by the (elevated) caller's *user* SID, then
// SecureDir. The directory must not stay owned by an untrusted principal.
func TestArea5SecureDirLeavesForeignOwner(t *testing.T) {
	if !IsRoot() {
		t.Skip("needs an elevated shell")
	}
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if trusted(u.User.Sid) {
		t.Skip("running as SYSTEM: user SID is trusted already")
	}
	dir := filepath.Join(t.TempDir(), "AutoDPI")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, u.User.Sid, nil, nil, nil); err != nil {
		t.Skipf("cannot simulate a user-owned directory: %v", err)
	}
	if err := SecureDir(dir); err != nil {
		t.Logf("SecureDir refused (acceptable): %v", err)
		return
	}
	if o := ownerOf(t, dir); !trusted(o) {
		t.Fatalf("SecureDir succeeded but %s is still owned by %s: that principal can rewrite the DACL and replace the service binary", dir, o)
	}
}

// A stale AF_UNIX socket (left behind by a crash or TerminateProcess) inside
// the directory must not make SecureDir fail: it runs from Install and at
// every daemon start.
func TestArea5SecureDirWithStaleUnixSocket(t *testing.T) {
	if !IsRoot() {
		t.Skip("needs an elevated shell")
	}
	dir := filepath.Join(t.TempDir(), "AutoDPI")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "ctl.sock")
	ln, err := listenUnixKeep(sock)
	if err != nil {
		t.Skipf("AF_UNIX unavailable: %v", err)
	}
	defer ln()
	if err := SecureDir(dir); err != nil {
		t.Fatalf("SecureDir with a socket file present: %v", err)
	}
}

// KillByPath must not return before the image is gone, otherwise the daemon's
// next step (rewriting sing-box.exe) can hit a sharing violation.
func TestArea5KillByPathIsSynchronous(t *testing.T) {
	if os.Getenv("AREA5_SLEEPER") == "1" {
		time.Sleep(time.Minute)
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fails := 0
	for i := 0; i < 15; i++ {
		img := filepath.Join(t.TempDir(), "area5-helper.exe")
		data, _ := os.ReadFile(self)
		if err := os.WriteFile(img, data, 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(img, "-test.run=^TestArea5KillByPathIsSynchronous$")
		cmd.Env = append(os.Environ(), "AREA5_SLEEPER=1")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(150 * time.Millisecond)
		if hit := KillByPath(img); len(hit) != 1 {
			t.Fatalf("KillByPath hit %v", hit)
		}
		// Immediately replace/remove the image, as embedded.ensure does.
		if err := os.Remove(img); err != nil {
			fails++
		}
		_ = cmd.Wait()
	}
	if fails > 0 {
		t.Fatalf("image still locked right after KillByPath in %d of 15 rounds (TerminateProcess is asynchronous; wait on the handle)", fails)
	}
}
