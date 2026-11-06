package update

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// hide keeps the self-test from opening a console window.
func hide(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// matchOwner has nothing to do: the install directory's inherited access
// list covers the new files.
func matchOwner(old, fresh string) {}
