package netx

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRouteField(t *testing.T) {
	out := `   route to: default
destination: default
       mask: default
    gateway: 10.232.79.148
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	if got := routeField(out, "interface"); got != "en0" {
		t.Fatalf("interface = %q", got)
	}
	if got := routeField(out, "gateway"); got != "10.232.79.148" {
		t.Fatalf("gateway = %q", got)
	}
	if routeField(out, "nope") != "" {
		t.Fatal("missing key must be empty")
	}
}

func TestUnroutable(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "169.254.3.4", "fe80::1", "::ffff:127.0.0.1"} {
		if !Unroutable(netip.MustParseAddr(s)) {
			t.Errorf("%s should be unroutable", s)
		}
	}
	for _, s := range []string{"162.159.136.232", "10.0.0.5", "2606:4700::1"} {
		if Unroutable(netip.MustParseAddr(s)) {
			t.Errorf("%s should be routable", s)
		}
	}
}

func TestLoopbackDialsAreNotPinned(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Pinning a loopback socket to en0 would fail; the dialer must skip it.
	c, err := (&Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("loopback dial failed: %v", err)
	}
	c.Close()
}
