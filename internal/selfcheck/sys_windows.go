package selfcheck

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// background keeps a helper from opening a console window: the service runs
// this without one.
func background(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
