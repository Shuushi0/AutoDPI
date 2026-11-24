package ipc

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// refused: nobody listens on the socket (its file outlived a daemon that was
// killed). Winsock has its own number for it (WSAECONNREFUSED, 10061), which
// syscall.ECONNREFUSED does not match on Windows; without it a service that
// is gone was reported as "could not be reached" for ever.
func refused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED) || errors.Is(err, syscall.ECONNREFUSED)
}
