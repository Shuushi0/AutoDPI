//go:build windows

package ipc

// Area-5 review tests. Run elevated: go test -run Area5 -v ./internal/ipc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Shuushi0/AutoDPI/internal/sysx"
)

func startServe(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ctl.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Serve(ctx, path, func(context.Context, Request) (any, error) { return "ok", nil })
	for i := 0; i < 50; i++ {
		if _, err := os.Lstat(path); err == nil {
			time.Sleep(200 * time.Millisecond) // let secureSocket run
			return path
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("socket never appeared")
	return ""
}

func socketSD(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("open socket file (reparse point itself): %v", err)
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd
}

// Diagnostic: what does SetNamedSecurityInfo (what sysx.SetDACL uses) do to a
// socket file? The result is thrown away in secureSocket.
func TestArea5SetDACLOnSocketResult(t *testing.T) {
	if !sysx.IsRoot() {
		t.Skip("needs an elevated shell")
	}
	path := startServe(t)
	err := sysx.SetDACL(path, socketSDDL)
	t.Logf("sysx.SetDACL(socket) = %v", err)
	if err != nil {
		t.Errorf("DACL cannot be applied to the AF_UNIX socket file; secureSocket silently leaves the inherited ACL: %v", err)
	}
}

// The socket must end up with exactly the DACL the README promises: protected
// (no inheritance from the directory) and no ACE for BUILTIN\Users.
func TestArea5SocketDACLApplied(t *testing.T) {
	if !sysx.IsRoot() {
		t.Skip("needs an elevated shell")
	}
	path := startServe(t)
	sd := socketSD(t, path)
	s := sd.String()
	t.Logf("socket SDDL: %s", s)
	ctl, _, _ := sd.Control()
	if ctl&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("socket DACL is not protected: it still inherits the directory ACL: %s", s)
	}
	if strings.Contains(s, ";;;BU)") || strings.Contains(s, ";;;AU)") || strings.Contains(s, ";;;WD)") {
		t.Errorf("socket is reachable by all local users: %s", s)
	}
	if !strings.Contains(s, ";;;IU)") {
		t.Errorf("interactive users have no ACE on the socket: %s", s)
	}
}
