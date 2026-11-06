package observer

import "golang.org/x/sys/windows"

// The code Winsock really returns; syscall.ECONNRESET is only a placeholder
// on Windows and never comes out of a socket.
var resetCode error = windows.WSAECONNRESET
