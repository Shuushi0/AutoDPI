package netx

import (
	"math/bits"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// IP_UNICAST_IF / IPV6_UNICAST_IF from <ws2ipdef.h>; x/sys/windows does not
// export them. They are what sing-box's own auto_detect_interface uses on
// Windows: the socket leaves through that interface even while a TUN holds
// a better default route.
const ipUnicastIf = 31

func bindControl(index int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipUnicastIf, index)
			} else {
				// The IPv4 option takes the index in network byte order
				// (Windows on amd64/arm64 is little-endian).
				serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(bits.ReverseBytes32(uint32(index))))
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}
