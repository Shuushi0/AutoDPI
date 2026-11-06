//go:build windows

package sysx

import "net"

// listenUnixKeep binds an AF_UNIX socket and leaves the socket file behind
// (as a crashed daemon would), returning a cleanup.
func listenUnixKeep(path string) (func(), error) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	return func() { ln.Close() }, nil
}
