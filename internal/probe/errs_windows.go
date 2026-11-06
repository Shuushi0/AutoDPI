package probe

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// Winsock reports its own codes (WSAECONNRESET, 10054, ...), which do not
// match the POSIX-style syscall.ECONNRESET placeholders on Windows.
// WSAECONNABORTED (10053) is deliberately not here: it is the local stack
// aborting the connection (software in the host, a timeout, our own close),
// not a peer RST, and calling it a reset would put hosts on the block list.
var (
	resetErrs = []error{windows.WSAECONNRESET, windows.ERROR_NETNAME_DELETED,
		syscall.ECONNRESET, syscall.EPIPE}
	refusedErrs = []error{windows.WSAECONNREFUSED, windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH, windows.WSAENETDOWN,
		windows.ERROR_CONNECTION_REFUSED, windows.ERROR_NETWORK_UNREACHABLE, windows.ERROR_HOST_UNREACHABLE}
)
