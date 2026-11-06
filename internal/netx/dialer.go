package netx

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Dialer opens sockets pinned to the physical interface with IP_BOUND_IF, so
// they leave through the real network even while our TUN (or anyone else's
// 0/1 routes) captures the default path. Loopback destinations are left alone.
type Dialer struct {
	Timeout time.Duration
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	nd := &net.Dialer{Timeout: d.Timeout, KeepAlive: 30 * time.Second}
	if !loopback(addr) {
		if ifc, err := Physical(); err == nil {
			nd.Control = bindControl(ifc.Index)
		}
	}
	return nd.DialContext(ctx, network, addr)
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// Unroutable reports destinations the observer must never relay to: loopback,
// link-local, multicast and the unspecified address.
func Unroutable(ip netip.Addr) bool {
	ip = ip.Unmap()
	return !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
