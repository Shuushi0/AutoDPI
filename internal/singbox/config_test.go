package singbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// sing-box is only embedded in release builds; tests use the dev copy.
func singBoxBin(t *testing.T) string {
	t.Helper()
	name := "sing-box"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, p := range []string{filepath.Join(os.Getenv("AUTODPI_BINDIR"), name), filepath.Join("..", "..", "bin", name)} {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	t.Skip("sing-box binary not available (set AUTODPI_BINDIR)")
	return ""
}

func sampleOptions(t *testing.T) Options {
	dir := t.TempDir()
	engines := []Engine{
		{Name: "ciadpi", Kind: Socks, Port: 21081},
		{Name: "tlsrec", Kind: TLSRecord, Port: 21083},
		{Name: "tlsfrag", Kind: TLSSegment, Port: 21084},
	}
	for _, e := range engines {
		if err := WriteRuleSet(dir, e.Name, []string{"discord.com", "roblox.com"}); err != nil {
			t.Fatal(err)
		}
	}
	return Options{Engines: engines, ObserverPort: 21082, RuleDir: dir, Tun: true, BlockQUIC: true, IPv4Only: true}
}

func check(t *testing.T, cfg []byte) {
	t.Helper()
	bin := singBoxBin(t)
	f := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(f, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := exec.Command(bin, "check", "-c", f)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("sing-box check failed: %v\n%s\n%s", err, out.String(), cfg)
	}
}

func TestTunConfigValidates(t *testing.T) {
	cfg, err := Build(sampleOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	check(t, cfg)
}

func TestTestModeConfigValidates(t *testing.T) {
	o := sampleOptions(t)
	o.Tun, o.TestPort = false, 21090
	cfg, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), `"tun"`) {
		t.Fatal("test mode must not open a TUN")
	}
	check(t, cfg)
}

func TestWireGuardTierValidates(t *testing.T) {
	o := sampleOptions(t)
	o.Engines = append(o.Engines, Engine{Name: "warp", Kind: WireGuard, Port: 21085})
	_ = WriteRuleSet(o.RuleDir, "warp", nil)
	o.WireGuard = &WireGuardProfile{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Addresses:  []string{"172.16.0.2/32"},
		MTU:        1280,
		PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Endpoint:   "engage.cloudflareclient.com",
		Port:       2408,
	}
	cfg, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	check(t, cfg)
}

func TestEmptyRuleSetIsAccepted(t *testing.T) {
	o := sampleOptions(t)
	for _, e := range o.Engines {
		_ = WriteRuleSet(o.RuleDir, e.Name, nil)
	}
	cfg, _ := Build(o)
	check(t, cfg)
}

func TestRuleOrder(t *testing.T) {
	cfg, err := Build(sampleOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatal(err)
	}
	sniff, list, obs := -1, -1, -1
	for i, r := range parsed.Route.Rules {
		if r["action"] == "sniff" {
			sniff = i
		}
		if rs, ok := r["rule_set"].([]any); ok && len(rs) > 0 && rs[0] == "blocked-ciadpi" && list < 0 {
			list = i
		}
		if r["outbound"] == "observer" {
			obs = i
		}
	}
	// Sniffing must precede anything matching a domain, and listed domains must
	// be decided before the observer catch-all.
	if sniff < 0 || !(sniff < list && list < obs) {
		t.Fatalf("rule order wrong: sniff=%d list=%d observer=%d", sniff, list, obs)
	}
}

func TestRejectsEmptyAndUnknown(t *testing.T) {
	if _, err := Build(Options{}); err == nil {
		t.Fatal("expected error without engines")
	}
	if _, err := Build(Options{Engines: []Engine{{Name: "x", Kind: "bogus"}}}); err == nil {
		t.Fatal("expected error for unknown kind")
	}
	if _, err := Build(Options{Engines: []Engine{{Name: "w", Kind: WireGuard}}}); err == nil {
		t.Fatal("expected error for wireguard without profile")
	}
}

func TestSpoofEngineRoutes(t *testing.T) {
	b, err := Build(Options{Engines: []Engine{{Name: "tlsspoof", Kind: TLSSpoof, Port: 30001}}, ObserverPort: 30000, RuleDir: "/x", Tun: true, IPv4Only: true})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Route struct{ Rules []map[string]any }
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range cfg.Route.Rules {
		if r["tls_spoof"] == "www.google.com" && r["tls_spoof_method"] == "wrong-sequence" && r["action"] == "route-options" {
			n++
		}
	}
	if n != 2 { // retry inbound + listed domains
		t.Fatalf("tls_spoof route-options rules: %d, want 2\n%s", n, b)
	}
}

func TestQUICRefusedOnlyForListed(t *testing.T) {
	b, err := Build(Options{Engines: []Engine{{Name: "tlsrec", Kind: TLSRecord, Port: 30001}, {Name: "ciadpi", Kind: Socks, Port: 30002}}, ObserverPort: 30000, RuleDir: "/x", Tun: true, BlockQUIC: true})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Route struct{ Rules []map[string]any }
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range cfg.Route.Rules {
		if r["network"] == nil || r["action"] != "reject" {
			continue
		}
		if r["method"] == "drop" {
			t.Fatalf("QUIC must not be dropped silently: %v", r)
		}
		sets, _ := r["rule_set"].([]any)
		if len(sets) != 2 {
			t.Fatalf("QUIC reject must be limited to the listed rule-sets: %v", r)
		}
		found = true
	}
	if !found {
		t.Fatal("no QUIC rule")
	}
}

func TestIPv6OnlyWhenNetworkHasIt(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		b, err := Build(Options{Engines: []Engine{{Name: "tlsrec", Kind: TLSRecord, Port: 30001}}, ObserverPort: 30000, RuleDir: "/x", Tun: true, IPv4Only: true, IPv6: v6})
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Inbounds []map[string]any
			Route    struct{ Rules []map[string]any }
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			t.Fatal(err)
		}
		addrs := cfg.Inbounds[0]["address"].([]any)
		if (len(addrs) == 2) != v6 {
			t.Errorf("IPv6=%v: tun addresses %v", v6, addrs)
		}
		for _, r := range cfg.Route.Rules {
			if r["ip_version"] != nil {
				t.Errorf("IPv6=%v: IPv6 must never be rejected after the TUN accepted it: %v", v6, r)
			}
		}
	}
}

// Windows sets StrictRoute (WFP filters against multi-homed DNS leaks); the
// config must carry it and still pass sing-box check.
func TestStrictRouteOption(t *testing.T) {
	for _, strict := range []bool{false, true} {
		o := sampleOptions(t)
		o.StrictRoute = strict
		cfg, err := Build(o)
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			Inbounds []map[string]any `json:"inbounds"`
		}
		if err := json.Unmarshal(cfg, &c); err != nil {
			t.Fatal(err)
		}
		if got := c.Inbounds[0]["strict_route"]; got != strict {
			t.Fatalf("strict_route = %v, want %v", got, strict)
		}
		check(t, cfg)
	}
}

type dnsSection struct {
	DNS struct {
		Servers []map[string]any `json:"servers"`
		Rules   []map[string]any `json:"rules"`
		Final   string           `json:"final"`
	} `json:"dns"`
	Route struct {
		Resolver string `json:"default_domain_resolver"`
	} `json:"route"`
}

func buildDNS(t *testing.T, doh []string) (dnsSection, []byte) {
	t.Helper()
	o := sampleOptions(t)
	o.DoH = doh
	cfg, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	var s dnsSection
	if err := json.Unmarshal(cfg, &s); err != nil {
		t.Fatal(err)
	}
	return s, cfg
}

func TestDefaultDoHIsTwoServersRaced(t *testing.T) {
	s, cfg := buildDNS(t, nil)
	if len(s.DNS.Servers) != 2 || s.DNS.Servers[0]["server"] != "1.1.1.1" || s.DNS.Servers[1]["server"] != "1.0.0.1" {
		t.Fatalf("servers = %v", s.DNS.Servers)
	}
	if s.DNS.Servers[0]["tag"] != s.Route.Resolver || s.DNS.Final != s.Route.Resolver {
		t.Fatalf("final/default resolver must be the first server: %v / %v", s.DNS.Final, s.Route.Resolver)
	}
	// One untagged evaluate per server, each followed by its own race rule per
	// usable rcode (NOERROR, NXDOMAIN): a lone NXDOMAIN must not fall through to
	// a stalled final server. The race rules read the untagged response (a
	// tagged one can be read stale, see dnsConfig); every evaluate after the
	// first is speculative, or it would wait for the race rules before it.
	var got []string
	for _, r := range s.DNS.Rules {
		switch r["action"] {
		case "evaluate":
			if r["tag"] != nil || (r["speculative"] == true) != (len(got) > 0) {
				t.Fatalf("evaluate malformed: %v", r)
			}
			got = append(got, "evaluate "+r["server"].(string))
		case "respond":
			if r["race"] != true || r["match_response"] != true {
				t.Fatalf("race rule malformed: %v", r)
			}
			got = append(got, "race "+r["response_rcode"].(string))
		default:
			t.Fatalf("unexpected rule %v", r)
		}
	}
	want := []string{"evaluate doh", "race NOERROR", "race NXDOMAIN", "evaluate doh2", "race NOERROR", "race NXDOMAIN"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("dns rules %v, want %v", got, want)
	}
	check(t, cfg)
}

func TestSingleDoHServerHasNoRaceRules(t *testing.T) {
	s, cfg := buildDNS(t, []string{"9.9.9.9"})
	if len(s.DNS.Servers) != 1 || len(s.DNS.Rules) != 0 || s.DNS.Servers[0]["server"] != "9.9.9.9" {
		t.Fatalf("dns = %+v", s.DNS)
	}
	check(t, cfg)
}

func TestDoHServerListIsCleaned(t *testing.T) {
	s, _ := buildDNS(t, []string{" 1.1.1.1", "", "1.1.1.1", "8.8.8.8", "8.8.4.4"})
	if len(s.DNS.Servers) != 3 {
		t.Fatalf("servers = %v", s.DNS.Servers)
	}
	tags := map[any]bool{}
	for _, sv := range s.DNS.Servers {
		tags[sv["tag"]] = true
	}
	if len(tags) != 3 {
		t.Fatalf("tags not unique: %v", s.DNS.Servers)
	}
	_, cfg := buildDNS(t, []string{"1.1.1.1", "8.8.8.8", "8.8.4.4"})
	check(t, cfg)
}

func TestDoHConfigValidatesWithIPv4Only(t *testing.T) {
	o := sampleOptions(t)
	o.IPv6 = true
	o.IPv4Only = false
	cfg, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	check(t, cfg)
}

func TestLocalNamesGoToTheGateway(t *testing.T) {
	b, err := Build(Options{
		Engines: []Engine{{Name: "tlsrec", Kind: TLSRecord, Port: 1}}, ObserverPort: 2, RuleDir: t.TempDir(),
		LocalDNS: "192.168.1.1", LocalSuffixes: []string{"lan", "corp.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"tag": "local"`, `"server": "192.168.1.1"`, `"corp.example.com"`, `"^[^.]+$"`} {
		if !strings.Contains(s, want) {
			t.Errorf("config lacks %s", want)
		}
	}
	// No gateway (or a scoped link-local one): no local server at all.
	for _, gw := range []string{"", "fe80::1%en0"} {
		b, _ := Build(Options{Engines: []Engine{{Name: "tlsrec", Kind: TLSRecord, Port: 1}}, ObserverPort: 2, RuleDir: t.TempDir(), LocalDNS: gw, LocalSuffixes: []string{"lan"}})
		if strings.Contains(string(b), `"tag": "local"`) {
			t.Errorf("gateway %q: local server present", gw)
		}
	}
}

func TestLocalDNSConfigValidates(t *testing.T) {
	o := sampleOptions(t)
	o.LocalDNS, o.LocalSuffixes = "192.168.1.1", []string{"lan", "local", "corp.example.com"}
	cfg, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	check(t, cfg)
	o.DoH = []string{"1.1.1.1"} // one resolver: no race rules, the local ones alone
	if cfg, err = Build(o); err != nil {
		t.Fatal(err)
	}
	check(t, cfg)
}
