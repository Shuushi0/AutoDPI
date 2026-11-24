package singbox

import (
	"encoding/json"
	"reflect"
	"runtime"
	"testing"
)

// What carries every user's traffic is pinned here value by value. `sing-box
// check` accepts all of these with another value too (a different stack, no
// auto_route, a misspelt dns_mode, the resolver over TCP), so none of the
// tests that run configurations through sing-box would notice the change;
// and a capture that is accepted and does something else is the failure that
// reaches users without an error anywhere. A change to one of these is a
// change to the product: it belongs in a commit that also changes this test,
// after a run on a real machine.
func TestCaptureSettingsArePinned(t *testing.T) {
	engines := []Engine{{Name: "tlsrec", Kind: TLSRecord, Port: 21081}, {Name: "ciadpi", Kind: Socks, Port: 21082}, {Name: "tlsspoof", Kind: TLSSpoof, Port: 21083}}
	build := func(o Options) map[string]any {
		t.Helper()
		o.Engines, o.ObserverPort, o.RuleDir = engines, 21080, t.TempDir()
		b, err := Build(o)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	get := func(m map[string]any, path ...string) any {
		var v any = m
		for _, p := range path {
			mm, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = mm[p]
		}
		return v
	}
	want := func(name string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", name, got, want)
		}
	}
	tun := func(m map[string]any) map[string]any {
		t.Helper()
		for _, in := range m["inbounds"].([]any) {
			if i := in.(map[string]any); i["type"] == "tun" {
				return i
			}
		}
		t.Fatal("no tun inbound")
		return nil
	}
	rule := func(m map[string]any, match func(map[string]any) bool) map[string]any {
		for _, r := range get(m, "route", "rules").([]any) {
			if rr := r.(map[string]any); match(rr) {
				return rr
			}
		}
		return nil
	}

	m := build(Options{Tun: true, IPv4Only: true, IPv6: true, BlockQUIC: true, StrictRoute: true,
		LocalDNS: "192.168.1.1", LocalSuffixes: []string{"lan"}})
	in := tun(m)
	want("tun stack", in["stack"], "mixed")
	want("tun auto_route", in["auto_route"], true)
	want("tun dns_mode", in["dns_mode"], "hijack")
	want("tun strict_route", in["strict_route"], true)
	want("tun address", in["address"], []any{TunIP + "/30", tunIP6})
	want("tun tag", in["tag"], "tun-in")
	if len(in) != 7 {
		t.Errorf("the tun inbound has %d settings, the test knows 7: %v", len(in), in)
	}
	want("route auto_detect_interface", get(m, "route", "auto_detect_interface"), true)
	want("route final", get(m, "route", "final"), "direct")
	want("route default_domain_resolver", get(m, "route", "default_domain_resolver"), "doh")
	want("dns strategy", get(m, "dns", "strategy"), "ipv4_only")
	want("dns final", get(m, "dns", "final"), "doh")

	// The resolvers: DoH by address, and the network's own over UDP.
	servers := map[string]map[string]any{}
	for _, s := range get(m, "dns", "servers").([]any) {
		ss := s.(map[string]any)
		servers[ss["tag"].(string)] = ss
	}
	want("resolver doh", servers["doh"], map[string]any{"type": "https", "tag": "doh", "server": "1.1.1.1"})
	want("resolver doh2", servers["doh2"], map[string]any{"type": "https", "tag": "doh2", "server": "1.0.0.1"})
	want("resolver local", servers["local"], map[string]any{"type": "udp", "tag": "local", "server": "192.168.1.1"})

	// The rules everything rests on, and their order: our own processes and
	// private addresses leave untouched BEFORE anything is handed to an
	// engine or the observer.
	procs := []any{"ciadpi", "autodpi"}
	if runtime.GOOS == "windows" {
		procs = []any{"ciadpi.exe", "autodpi.exe"}
	}
	rules := get(m, "route", "rules").([]any)
	index := func(match func(map[string]any) bool) int {
		for i, r := range rules {
			if match(r.(map[string]any)) {
				return i
			}
		}
		return -1
	}
	sniff := index(func(r map[string]any) bool { return r["action"] == "sniff" })
	hijack := index(func(r map[string]any) bool { return r["action"] == "hijack-dns" })
	self := index(func(r map[string]any) bool { return r["process_name"] != nil })
	private := index(func(r map[string]any) bool {
		return r["ip_is_private"] == true && r["outbound"] == "direct" && r["inbound"] == nil
	})
	observer := index(func(r map[string]any) bool { return r["outbound"] == "observer" })
	if sniff < 0 || hijack < 0 || self < 0 || private < 0 || observer < 0 {
		t.Fatalf("a rule is missing: sniff %d, hijack-dns %d, own processes %d, private %d, observer %d", sniff, hijack, self, private, observer)
	}
	if !(sniff < hijack && hijack < self && self < private && private < observer) || observer != len(rules)-1 {
		t.Errorf("rule order changed: sniff %d, hijack-dns %d, own processes %d, private %d, observer %d of %d", sniff, hijack, self, private, observer, len(rules))
	}
	want("sniff rule", rules[sniff], map[string]any{"inbound": []any{"tun-in"}, "action": "sniff"})
	want("hijack-dns rule", rules[hijack], map[string]any{"port": []any{float64(53)}, "action": "hijack-dns"})
	want("own processes rule", rules[self], map[string]any{"process_name": procs, "outbound": "direct"})
	want("observer rule", rules[observer], map[string]any{"port": []any{float64(443)}, "network": []any{"tcp"}, "outbound": "observer"})
	quic := rule(m, func(r map[string]any) bool { return r["action"] == "reject" && r["network"] != nil })
	want("QUIC block", quic, map[string]any{
		"rule_set": []any{"blocked-tlsrec", "blocked-ciadpi", "blocked-tlsspoof"},
		"port":     []any{float64(443)}, "network": []any{"udp"}, "action": "reject"})

	// The engines' own settings.
	rec := rule(m, func(r map[string]any) bool { return r["tls_record_fragment"] != nil && r["rule_set"] != nil })
	want("tlsrec list rule", rec, map[string]any{"rule_set": []any{"blocked-tlsrec"}, "action": "route-options", "tls_record_fragment": true})
	spoof := rule(m, func(r map[string]any) bool { return r["tls_spoof"] != nil && r["rule_set"] != nil })
	want("tlsspoof list rule", spoof, map[string]any{"rule_set": []any{"blocked-tlsspoof"}, "action": "route-options",
		"tls_spoof": "www.google.com", "tls_spoof_method": "wrong-sequence"})

	// The other side of every switch.
	m = build(Options{Tun: true})
	in = tun(m)
	want("tun address without IPv6", in["address"], []any{TunIP + "/30"})
	want("tun strict_route off", in["strict_route"], false)
	want("tun stack (again)", in["stack"], "mixed")
	want("dns strategy without ipv4_only", get(m, "dns", "strategy"), nil)
	if rule(m, func(r map[string]any) bool { return r["action"] == "reject" && r["network"] != nil }) != nil {
		t.Error("QUIC is blocked without block_quic")
	}
}
