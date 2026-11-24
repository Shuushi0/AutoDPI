package singbox

import (
	"strings"
	"testing"
)

const sampleProfile = `
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32, 2606:4700:110:8000::2/128
DNS = 1.1.1.1
MTU = 1280
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
`

func TestParseWgcf(t *testing.T) {
	p, err := ParseWgcf(strings.NewReader(sampleProfile))
	if err != nil {
		t.Fatal(err)
	}
	if p.Endpoint != "engage.cloudflareclient.com" || p.Port != 2408 || p.MTU != 1280 || len(p.Addresses) != 2 {
		t.Fatalf("%+v", p)
	}
	if _, err := ParseWgcf(strings.NewReader("[Interface]\nPrivateKey = x\n")); err == nil {
		t.Fatal("incomplete profile must be rejected")
	}
}

// A bare address is what WireGuard itself accepts; sing-box wants the prefix
// and refuses the whole configuration without it, every engine included.
func TestWgcfBareAddressGetsItsPrefix(t *testing.T) {
	p, err := ParseWgcf(strings.NewReader("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 172.16.0.2, 2606:4700:110:8a36::2\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = engage.cloudflareclient.com:2408\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Addresses) != 2 || p.Addresses[0] != "172.16.0.2/32" || p.Addresses[1] != "2606:4700:110:8a36::2/128" {
		t.Fatalf("addresses = %v", p.Addresses)
	}
}
