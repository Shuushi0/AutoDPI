//go:build !windows

package ipc

import (
	"errors"
	"syscall"
)

// refused: nobody listens on the socket (its file outlived a daemon that was
// killed).
func refused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
