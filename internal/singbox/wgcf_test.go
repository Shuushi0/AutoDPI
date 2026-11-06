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
