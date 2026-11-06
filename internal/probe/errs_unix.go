//go:build !windows

package probe

import "syscall"

var (
	resetErrs   = []error{syscall.ECONNRESET, syscall.EPIPE}
	refusedErrs = []error{syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN}
)
