//go:build darwin

package netx

import (
	"strings"
	"syscall"
)

// Values from <netinet/in.h> and <netinet6/in6.h>; the syscall package does
// not export them.
const (
	ipBoundIf   = 25
	ipv6BoundIf = 125
)

func bindControl(index int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIf, index)
			} else {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, index)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}
