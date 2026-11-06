package netx

import (
	"errors"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Shuushi0/AutoDPI/internal/singbox"
)

// Interface types (ipifcons.h) that carry a real uplink. Wintun (our TUN,
// WireGuard, sing-box, Tailscale) is IF_TYPE_PROP_VIRTUAL (53); WARP and most
// VPN clients use 53 or IF_TYPE_TUNNEL (131). PPP covers PPPoE dial-up, which
// is also how the built-in Windows VPN clients appear (see ForeignTunnel).
const (
	ifTypeWWANPP  = 243
	ifTypeWWANPP2 = 244
)

func physicalType(t uint32) bool {
	switch t {
	case windows.IF_TYPE_ETHERNET_CSMACD, windows.IF_TYPE_IEEE80211, windows.IF_TYPE_PPP, ifTypeWWANPP, ifTypeWWANPP2:
		return true
	}
	return false
}

type route4 struct {
	ifIndex uint32
	luid    uint64
	prefix  netip.Prefix
	gateway netip.Addr
	metric  uint32 // route metric + interface metric: what Windows compares
}

type ifInfo struct {
	typ uint32
	up  bool
}

// ifaceInfo looks the interface up by LUID, or by index when luid is 0.
func ifaceInfo(index uint32, luid uint64) (ifInfo, bool) {
	row := windows.MibIfRow2{InterfaceLuid: luid, InterfaceIndex: index}
	if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
		return ifInfo{}, false
	}
	return ifInfo{typ: row.Type, up: row.OperStatus == windows.IfOperStatusUp}, true
}

func interfaceMetric(luid uint64) uint32 {
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return 0
	}
	return row.Metric
}

// routes4 reads the active IPv4 routing table.
func routes4() ([]route4, error) {
	var t *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &t); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	metric := map[uint64]uint32{}
	var out []route4
	for _, r := range t.Rows() {
		if r.DestinationPrefix.Prefix.Family != windows.AF_INET {
			continue
		}
		dst := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.DestinationPrefix.Prefix))
		nh := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.NextHop))
		m, ok := metric[r.InterfaceLuid]
		if !ok {
			m = interfaceMetric(r.InterfaceLuid)
			metric[r.InterfaceLuid] = m
		}
		out = append(out, route4{
			ifIndex: r.InterfaceIndex,
			luid:    r.InterfaceLuid,
			prefix:  netip.PrefixFrom(netip.AddrFrom4(dst.Addr), int(r.DestinationPrefix.PrefixLength)),
			gateway: netip.AddrFrom4(nh.Addr),
			metric:  r.Metric + m,
		})
	}
	return out, nil
}

func ifName(index uint32) string {
	if ifc, err := net.InterfaceByIndex(int(index)); err == nil {
		return ifc.Name
	}
	return ""
}

// DefaultRoute returns the interface and gateway of the best IPv4 default
// route on a physical interface (Ethernet, Wi-Fi, WWAN, PPP). On Windows our
// TUN and full-tunnel VPNs install 0.0.0.0/0 routes of their own on virtual
// adapters (unlike macOS, where they add 0/1+128/1), so those are skipped to
// keep the macOS meaning: the real uplink underneath every tunnel.
func DefaultRoute() (iface, gateway string, err error) {
	rs, err := routes4()
	if err != nil {
		return "", "", err
	}
	// Our own TUN is skipped by address, not only by type: whatever the
	// adapter reports as its type, a default route through the interface that
	// carries our TUN address is not the uplink.
	ownTun := InterfaceWithIP(singbox.TunIP)
	var best *route4
	for i := range rs {
		r := &rs[i]
		if r.prefix.Bits() != 0 {
			continue
		}
		if ownTun != "" && ifName(r.ifIndex) == ownTun {
			continue
		}
		info, ok := ifaceInfo(r.ifIndex, r.luid)
		if !ok || !info.up || !physicalType(info.typ) {
			continue
		}
		// Prefer a non-PPP uplink: a PPP default next to Ethernet/Wi-Fi is
		// more likely a built-in VPN than the uplink itself.
		if best == nil || better(r, info.typ, best) {
			best = r
		}
	}
	if best == nil {
		return "", "", errors.New("no default route")
	}
	name := ifName(best.ifIndex)
	if name == "" {
		return "", "", errors.New("default route interface has no name")
	}
	gw := ""
	if !best.gateway.IsUnspecified() {
		gw = best.gateway.String()
	}
	return name, gw, nil
}

func better(r *route4, typ uint32, best *route4) bool {
	bi, _ := ifaceInfo(best.ifIndex, best.luid)
	rPPP, bPPP := typ == windows.IF_TYPE_PPP, bi.typ == windows.IF_TYPE_PPP
	if rPPP != bPPP {
		return !rPPP
	}
	return r.metric < best.metric
}

// RouteTo returns the interface a packet to ip would leave through.
func RouteTo(ip string) (string, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", err
	}
	var sa windows.Sockaddr
	if a.Is4() {
		sa = &windows.SockaddrInet4{Addr: a.As4()}
	} else {
		sa = &windows.SockaddrInet6{Addr: a.As16()}
	}
	var idx uint32
	if err := windows.GetBestInterfaceEx(sa, &idx); err != nil {
		return "", err
	}
	if name := ifName(idx); name != "" {
		return name, nil
	}
	return "", errors.New("no route")
}

// ForeignTunnel reports a VPN (Cloudflare WARP, WireGuard, OpenVPN, ...) that
// owns or competes for IPv4 traffic: an interface other than the one
// carrying ownIP that holds 0/1 or 128/1 (wg-quick/OpenVPN style, any
// adapter type), or 0.0.0.0/0 on a non-physical adapter, or 0.0.0.0/0 on a
// PPP adapter while a non-PPP uplink (Ethernet, Wi-Fi, WWAN) also has a
// default route (the built-in Windows VPN clients appear as PPP; a PPP
// default that is the only one is plain PPPoE and not foreign), or that
// public destinations route to.
func ForeignTunnel(ownIP string) (iface string, found bool) {
	own := InterfaceWithIP(ownIP)
	rs, rerr := routes4()
	// Is there a default route on a physical, non-PPP uplink that is not ours?
	nonPPPDefault := false
	if rerr == nil {
		for _, r := range rs {
			if r.prefix.Bits() != 0 {
				continue
			}
			info, ok := ifaceInfo(r.ifIndex, r.luid)
			if ok && info.up && physicalType(info.typ) && info.typ != windows.IF_TYPE_PPP {
				if name := ifName(r.ifIndex); name != "" && name != own {
					nonPPPDefault = true
					break
				}
			}
		}
	}
	foreign := func(idx uint32, luid uint64, bitsLen int) bool {
		name := ifName(idx)
		if name == "" || name == own {
			return false
		}
		info, ok := ifaceInfo(idx, luid)
		if !ok || !info.up || info.typ == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			return false
		}
		if bitsLen == 0 && info.typ == windows.IF_TYPE_PPP {
			return nonPPPDefault
		}
		return bitsLen == 1 || !physicalType(info.typ)
	}
	if rerr == nil {
		for _, r := range rs {
			if r.prefix.Bits() <= 1 && foreign(r.ifIndex, r.luid, r.prefix.Bits()) {
				return ifName(r.ifIndex), true
			}
		}
	}
	for _, probe := range []string{"1.1.1.1", "8.8.8.8"} {
		name, err := RouteTo(probe)
		if err != nil || name == own {
			continue
		}
		// bitsLen 0 here means "a default-like route", as before, so a PPP
		// next to a physical uplink counts through the same rule.
		if ifc, err := net.InterfaceByName(name); err == nil && foreign(uint32(ifc.Index), 0, 0) {
			return name, true
		}
	}
	return "", false
}
