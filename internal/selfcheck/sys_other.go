//go:build !windows

package selfcheck

import "os/exec"

func background(*exec.Cmd) {}
