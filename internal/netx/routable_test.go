package netx

import (
	"net"
	"testing"
)

func TestRoutableIPv6(t *testing.T) {
	for ip, want := range map[string]bool{
		"2a02:ff0:1::5":        true,
		"2606:4700:4700::1111": true,
		"2001:db8::1":          false, // documentation: handed out by a phone hotspot, 2026-11-12
		"2001:db8:ffff::1":     false,
		"3fff:1::1":            false, // documentation (RFC 9637)
		"2001:0:1::1":          false, // Teredo
		"2002:c000:204::1":     false, // 6to4
		"fd00::1":              false, // ULA
		"fe80::1":              false, // link-local
		"::1":                  false,
		"ff02::1":              false,
		"192.0.2.1":            false,
		"::ffff:192.0.2.1":     false,
	} {
		if got := RoutableIPv6(net.ParseIP(ip)); got != want {
			t.Errorf("RoutableIPv6(%s) = %v, want %v", ip, got, want)
		}
	}
}
