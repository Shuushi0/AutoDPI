//go:build windows

package netid

import (
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/netx"
)

func TestArea5GatewayMACOfDefaultGateway(t *testing.T) {
	_, gw, err := netx.DefaultRoute()
	if err != nil || gw == "" {
		t.Skip("no gateway")
	}
	mac := gatewayMAC(gw)
	t.Logf("gateway %s -> %q", gw, mac)
	if mac == "" {
		t.Error("SendARP returned nothing for the default gateway (wrong IPAddr byte order or no ARP on this link?)")
	}
	if len(mac) != 17 {
		t.Errorf("unexpected MAC format %q", mac)
	}
}

func TestArea5GatewayMACGarbage(t *testing.T) {
	for _, in := range []string{"", "::1", "not-an-ip", "0.0.0.0"} {
		if got := gatewayMAC(in); got != "" {
			t.Errorf("gatewayMAC(%q) = %q", in, got)
		}
	}
}
