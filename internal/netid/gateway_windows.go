package netid

import (
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procSendARP = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SendARP")

// gatewayMAC returns the link-layer address of gw, or "". SendARP answers
// from the neighbour cache (or asks the network, bounded by the stack's own
// ARP timeout), the Windows counterpart of `arp -n` on macOS.
func gatewayMAC(gw string) string {
	a, err := netip.ParseAddr(gw)
	if err != nil || !a.Is4() || procSendARP.Find() != nil {
		return ""
	}
	ip := a.As4()
	var mac [8]byte
	n := uint32(len(mac))
	// IPAddr is the address in network byte order, read as a native DWORD.
	dst := *(*uint32)(unsafe.Pointer(&ip[0]))
	if r, _, _ := procSendARP.Call(uintptr(dst), 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&n))); r != 0 || n == 0 || n > 8 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("%02x", mac[i])
	}
	return strings.Join(parts, ":")
}
