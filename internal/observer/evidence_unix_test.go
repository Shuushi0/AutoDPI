//go:build !windows

package observer

import "syscall"

var resetCode error = syscall.ECONNRESET
