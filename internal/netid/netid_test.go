package netid

import (
	"net/netip"
	"testing"
)

func TestParseOrigin(t *testing.T) {
	asn, err := parseOrigin("9121 | 88.240.0.0/13 | TR | ripencc | 2007-03-12")
	if err != nil || asn != 9121 {
		t.Fatalf("asn=%d err=%v", asn, err)
	}
	// Multi-origin prefixes list several ASNs; the first wins.
	if asn, _ := parseOrigin("15169 36040 | 8.8.8.0/24 | US | arin | 2023-12-28"); asn != 15169 {
		t.Fatalf("asn=%d", asn)
	}
	if _, err := parseOrigin("  | x"); err == nil {
		t.Fatal("expected error for empty record")
	}
}

func TestParseASName(t *testing.T) {
	if got := parseASName("9121 | TR | ripencc | 1996-12-02 | TTNET, TR"); got != "TTNET, TR" {
		t.Fatalf("name = %q", got)
	}
	if parseASName("garbage") != "" {
		t.Fatal("short record must yield no name")
	}
}

func TestOriginName(t *testing.T) {
	n, err := originName(netip.MustParseAddr("88.240.12.7"))
	if err != nil || n != "7.12.240.88.origin.asn.cymru.com" {
		t.Fatalf("%q %v", n, err)
	}
	if _, err := originName(netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Fatal("IPv6 must be rejected")
	}
}
