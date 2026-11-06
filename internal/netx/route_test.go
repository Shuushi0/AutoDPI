package netx

import "testing"

func TestInterfaceWithIP(t *testing.T) {
	if got := InterfaceWithIP("127.0.0.1"); got == "" {
		t.Fatal("loopback address not found on any interface")
	}
	if got := InterfaceWithIP("203.0.113.250"); got != "" {
		t.Fatalf("TEST-NET address found on %s", got)
	}
}

func TestForeignRoute(t *testing.T) {
	const table = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.39.8.15         UGScg                 en0
1                  172.19.0.1         UGSc                utun4
2/7                172.19.0.1         UGSc                utun4
10.39.8/24         link#14            UCS                   en0
127                127.0.0.1          UCS                   lo0
`
	if got := foreignRoute(table, "utun4"); got != "" {
		t.Fatalf("our own split routes reported as foreign: %s", got)
	}
	if got := foreignRoute(table, ""); got != "utun4" {
		t.Fatalf("an unknown tunnel's routes must count, got %q", got)
	}
	wg := table + "0/1                10.66.0.1          UGSc                utun7\n"
	if got := foreignRoute(wg, "utun4"); got != "utun7" {
		t.Fatalf("a wg-quick style 0/1 route on another utun must count, got %q", got)
	}
}
