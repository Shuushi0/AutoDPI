//go:build !windows

package netx

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

func runCmd(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

// DefaultRoute returns the interface and gateway of the system default route.
// With a full-tunnel VPN or our own TUN up, this still names the physical
// interface because those only add more specific 0/1 and 128/1 routes.
func DefaultRoute() (iface, gateway string, err error) {
	out, err := runCmd("/sbin/route", "-n", "get", "default")
	iface, gateway = routeField(out, "interface"), routeField(out, "gateway")
	if iface == "" {
		if err == nil {
			err = errors.New("no default route")
		}
		return "", "", err
	}
	return iface, gateway, nil
}

// RouteTo returns the interface a packet to ip would leave through.
func RouteTo(ip string) (string, error) {
	out, err := runCmd("/sbin/route", "-n", "get", ip)
	if ifc := routeField(out, "interface"); ifc != "" {
		return ifc, nil
	}
	if err == nil {
		err = errors.New("no route")
	}
	return "", err
}

// ForeignTunnel reports a VPN (Cloudflare WARP, WireGuard, ...) that owns or
// competes for IPv4 traffic: a utun other than the one carrying ownIP that
// holds a default-like route, or that public destinations resolve to. Asking
// the routing table rather than route(8) alone also sees a VPN whose routes
// lose to ours.
func ForeignTunnel(ownIP string) (iface string, found bool) {
	own := InterfaceWithIP(ownIP)
	if out, err := runCmd("/usr/sbin/netstat", "-rn", "-f", "inet"); err == nil {
		if ifc := foreignRoute(out, own); ifc != "" {
			return ifc, true
		}
	}
	for _, probe := range []string{"1.1.1.1", "8.8.8.8"} {
		if ifc, err := RouteTo(probe); err == nil && strings.HasPrefix(ifc, "utun") && ifc != own {
			return ifc, true
		}
	}
	return "", false
}
