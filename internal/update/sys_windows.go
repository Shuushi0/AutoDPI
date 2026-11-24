package update

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/Shuushi0/AutoDPI/internal/sysx"
)

// hide keeps the self-test from opening a console window.
func hide(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// matchOwner gives the new program the access list the installed one has:
// everybody may run it, only SYSTEM and Administrators may replace it. A file
// created in the install directory inherits the administrators-only half
// alone, and without the rest the tray app could not start its own new copy
// and an unelevated `autodpi status` got "Access is denied" after every
// update.
func matchOwner(old, fresh string) { _ = sysx.SecureExe(fresh) }
