// Package netx holds the network plumbing (macOS: route(8)/netstat and
// IP_BOUND_IF; Windows: IP Helper and IP_UNICAST_IF): which interface carries the
// real default route, sockets pinned to it (so they bypass our own TUN), and a
// small DoH client.
package netx

import (
	"net"
	"sort"
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

// HasGlobalIPv6 reports whether iface carries an IPv6 address that can be
// routed on the internet. That is a hint, not proof: a phone hotspot hands out
// addresses its uplink never carries (see GlobalIPv6Prefixes).
func HasGlobalIPv6(iface string) bool { return len(GlobalIPv6Prefixes(iface)) > 0 }

// GlobalIPv6Prefixes lists the /64 prefixes of iface's internet-routable IPv6
// addresses, sorted. Prefixes, not addresses: the temporary (privacy) address
// changes every day on the same network.
func GlobalIPv6Prefixes(iface string) []string {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil
	}
	addrs, _ := ifc.Addrs()
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() != nil || !RoutableIPv6(n.IP) {
			continue
		}
		p := n.IP.Mask(net.CIDRMask(64, 128)).String()
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// notInternetV6 are the parts of 2000::/3 that are never a host's address on
// the internet. The documentation prefix is not academic: a phone hotspot was
// seen handing out 2001:db8::/64 with a default route (2026-11-12), and
// capturing that made every IPv6 connection open and then die.
var notInternetV6 = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"2001:db8::/32", // documentation (RFC 3849)
		"3fff::/20",     // documentation (RFC 9637)
		"2001::/32",     // Teredo
		"2001:2::/48",   // benchmarking
		"2001:10::/28",  // ORCHID
		"2001:20::/28",  // ORCHIDv2
		"2002::/16",     // 6to4, long dead
	} {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}()

// RoutableIPv6 reports whether ip is an IPv6 address a host can have on the
// internet: inside 2000::/3 (so not link-local, ULA, loopback or multicast)
// and outside the reserved parts of it.
func RoutableIPv6(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil || ip.To4() != nil || ip[0]&0xe0 != 0x20 {
		return false
	}
	for _, n := range notInternetV6 {
		if n.Contains(ip) {
			return false
		}
	}
	return true
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
