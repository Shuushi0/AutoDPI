//go:build windows

package netx

import (
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestArea5Routes4Sane(t *testing.T) {
	rs, err := routes4()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("empty IPv4 routing table")
	}
	var loop bool
	for _, r := range rs {
		if !r.prefix.IsValid() {
			t.Errorf("invalid prefix in %+v", r)
		}
		if r.prefix.Addr().String() == "127.0.0.0" && r.prefix.Bits() == 8 {
			loop = true
		}
		if _, ok := ifaceInfo(r.ifIndex, r.luid); !ok {
			t.Logf("no interface info for route %v via if %d", r.prefix, r.ifIndex)
		}
	}
	if !loop {
		t.Error("127.0.0.0/8 not found: row decoding is probably wrong")
	}
}

func TestArea5DefaultRouteAgreesWithBestInterface(t *testing.T) {
	name, gw, err := DefaultRoute()
	if err != nil {
		t.Skipf("no default route: %v", err)
	}
	t.Logf("default route: %s via %q", name, gw)
	to, err := RouteTo("1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	// With no tunnel up, the route to a public IP leaves through the uplink.
	if f, found := ForeignTunnel("172.19.0.1"); !found && to != name {
		t.Errorf("DefaultRoute=%s but RouteTo(1.1.1.1)=%s", name, to)
	} else {
		t.Logf("foreign tunnel=%q found=%v, RouteTo=%s", f, found, to)
	}
}

// IP_UNICAST_IF takes the index in network byte order for IPv4 and host order
// for IPv6; read the option back inside the Control callback.
func TestArea5BindControlByteOrder(t *testing.T) {
	ifc, err := Physical()
	if err != nil {
		t.Skip(err)
	}
	var got4 int
	d := net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		if err := bindControl(ifc.Index)(network, address, c); err != nil {
			return err
		}
		return c.Control(func(fd uintptr) {
			got4, _ = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf)
		})
	}}
	c, err := d.Dial("tcp4", "127.0.0.1:1") // refused is fine; the option is set before connect
	if err == nil {
		c.Close()
	}
	want := int(uint32(ifc.Index)<<24 | uint32(ifc.Index)&0xff00<<8 | uint32(ifc.Index)>>8&0xff00 | uint32(ifc.Index)>>24)
	if got4 != want {
		t.Errorf("IP_UNICAST_IF read back %#x, want %#x for index %d", got4, want, ifc.Index)
	}
}
