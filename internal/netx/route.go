// Package netx holds the network plumbing (macOS: route(8)/netstat and
// IP_BOUND_IF; Windows: IP Helper and IP_UNICAST_IF): which interface carries the
// real default route, sockets pinned to it (so they bypass our own TUN), and a
// small DoH client.
package netx

import (
	"net"
	"strings"
	"sync"
	"time"
)

type Iface struct {
	Name  string
	Index int
}

// routeField picks "key: value" out of route(8) output (macOS).
func routeField(out, key string) string {
	for _, ln := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(ln), key+":"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// wideRoutes are destinations that take over (part of) the IPv4 default:
// default, the 0/1+128/1 pair of wg-quick/OpenVPN, and sing-tun's darwin split.
var wideRoutes = map[string]bool{
	"default": true, "0/1": true, "128.0/1": true,
	"1": true, "2/7": true, "4/6": true, "8/5": true, "16/4": true, "32/3": true, "64/2": true,
}

// foreignRoute scans macOS netstat -rn output (Destination Gateway Flags Netif ...).
func foreignRoute(out, own string) string {
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 || !wideRoutes[f[0]] {
			continue
		}
		if ifc := f[3]; strings.HasPrefix(ifc, "utun") && ifc != own {
			return ifc
		}
	}
	return ""
}

// HasGlobalIPv6 reports whether iface carries a routable IPv6 address
// (global unicast, not link-local or ULA), i.e. the network offers IPv6.
func HasGlobalIPv6(iface string) bool {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return false
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() != nil {
			continue
		}
		if n.IP.IsGlobalUnicast() && n.IP[0]&0xfe != 0xfc { // fc00::/7 is ULA
			return true
		}
	}
	return false
}

// InterfaceWithIP names the interface that carries ip, or "".
func InterfaceWithIP(ip string) string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.String() == ip {
				return ifc.Name
			}
		}
	}
	return ""
}

var phys struct {
	sync.Mutex
	at  time.Time
	gen uint64
	v   Iface
}

// Physical returns the interface behind the default route, cached briefly.
func Physical() (Iface, error) {
	phys.Lock()
	defer phys.Unlock()
	gen := RouteGen()
	if phys.v.Name != "" && phys.gen == gen && time.Since(phys.at) < CacheTTL(3*time.Second) {
		return phys.v, nil
	}
	name, _, err := DefaultRoute()
	if err != nil {
		return Iface{}, err
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return Iface{}, err
	}
	phys.v, phys.at, phys.gen = Iface{Name: name, Index: ifc.Index}, time.Now(), gen
	return phys.v, nil
}

// InvalidatePhysical forces the next Physical call to re-read the route table.
func InvalidatePhysical() {
	phys.Lock()
	phys.at = time.Time{}
	phys.Unlock()
}
