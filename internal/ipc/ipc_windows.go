package ipc

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/Shuushi0/AutoDPI/internal/sysx"
)

// socketSDDL: SYSTEM and Administrators, plus interactively logged-on users,
// may connect (read/write on the socket file). That is the Windows reading of
// macOS's "admin group, no sudo needed": on a desktop the interactive user
// is the one who runs `autodpi status`, while services, network logons
// and other non-interactive accounts are kept out.
const socketSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFW;;;IU)"

// secureSocket runs right after Listen. The socket lives in a directory of its
// own (paths_windows.go: ...\AutoDPI\ctl) that only SYSTEM/Administrators
// control, gets a protected DACL of its own, and the DACL is read back. If
// any of that fails the socket file is removed again, so nobody can connect
// to a channel we could not restrict (fail closed).
//
// Only an elevated daemon can (and needs to) restrict it; a dev run in
// AUTODPI_HOME keeps the default owner-only access.
func secureSocket(path string) error {
	if !sysx.IsRoot() {
		return nil
	}
	if err := lockSocket(path); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("cannot restrict it, removed: %w", err)
	}
	return nil
}

func lockSocket(path string) error {
	if err := sysx.CheckTrustedDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := sysx.SetDACL(path, socketSDDL); err != nil {
		return err
	}
	return sysx.CheckProtectedDACL(path, windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid, windows.WinInteractiveSid)
}
