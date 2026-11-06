// Package singbox generates the sing-box configuration (TUN capture, DoH,
// QUIC block for listed domains, per-engine rule-sets) and the rule-set files it hot-reloads.
package singbox

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Kind says how an engine is realised inside sing-box.
type Kind string

const (
	Socks      Kind = "socks"    // external SOCKS5 engine (ciadpi)
	TLSRecord  Kind = "tlsrec"   // sing-box tls_record_fragment
	TLSSegment Kind = "tlsfrag"  // sing-box tls_fragment
	TLSSpoof   Kind = "tlsspoof" // sing-box tls_spoof: decoy ClientHello first (root only)
	WireGuard  Kind = "wg"       // WireGuard endpoint (WARP), tier 2
)

type Engine struct {
	Name string
	Kind Kind
	Port int // Socks: the engine's own port; others: the retry inbound sing-box opens
}

// Addr is where the observer reaches this engine.
func (e Engine) Addr() string { return fmt.Sprintf("127.0.0.1:%d", e.Port) }

// Peer settings for the optional WARP tier, as found in a wgcf profile.
type WireGuardProfile struct {
	PrivateKey string
	Addresses  []string
	MTU        int
	PublicKey  string
	Endpoint   string // host
	Port       int
}

type Options struct {
	Engines      []Engine // ladder order; the first is the default for unassigned entries
	ObserverPort int
	ObservePorts []int // TCP ports handed to the observer; default 443
	RuleDir      string
	DoH          []string // DoH resolver hosts/IPs, default 1.1.1.1 and 1.0.0.1; several are raced
	// LocalDNS is the network's own resolver (its gateway); questions for
	// LocalSuffixes and single-label names go there instead of DoH, which
	// cannot know a home router's or a company's internal names. Empty: none.
	LocalDNS      string
	LocalSuffixes []string
	Tun           bool // capture the system; otherwise TestPort serves a mixed inbound
	TestPort      int
	BlockQUIC     bool
	IPv4Only      bool
	IPv6          bool // the physical network has IPv6: capture it as well
	StrictRoute   bool // TUN strict_route (Windows: WFP filters against multi-homed DNS leaks)
	LogLevel      string
	DirectProcs   []string // processes whose own traffic must never be captured
	SpoofSNI      string   // decoy server name for TLSSpoof engines, default www.google.com
	SpoofMethod   string   // how the server discards the decoy, default wrong-sequence
	WireGuard     *WireGuardProfile
}

const placeholder = "placeholder.invalid"

// TunIP is the TUN's own address; it identifies our utun (or wintun adapter)
// among others.
const TunIP = "172.19.0.1"

// tunIP6 gives the TUN an IPv6 address, which makes auto_route take IPv6
// too. Only when the physical network has IPv6 (Options.IPv6): on an
// IPv4-only network the address alone makes browsers believe IPv6 works,
// they connect to AAAA records from their own DoH, the TUN accepts the
// connection and nothing can carry it out, so the page shows
// ERR_CONNECTION_RESET instead of falling back to IPv4 (seen live in
// Vivaldi, 2026-10-29). When it is captured it goes through the same rules.
const tunIP6 = "fdfe:dcba:9876::1/126"

func RuleSetTag(engine string) string { return "blocked-" + engine }

func RuleSetPath(dir, engine string) string { return filepath.Join(dir, RuleSetTag(engine)+".json") }

// WriteRuleSet replaces the engine's rule-set file with domains. sing-box
// watches the file and reloads it without dropping connections.
func WriteRuleSet(dir, engine string, domains []string) error {
	return writeSet(RuleSetPath(dir, engine), domains)
}

func writeSet(path string, domains []string) error {
	ds := append([]string(nil), domains...)
	if len(ds) == 0 {
		ds = []string{placeholder} // an empty set is rejected
	}
	sort.Strings(ds)
	b, err := json.MarshalIndent(map[string]any{
		"version": 3,
		"rules":   []any{map[string]any{"domain_suffix": ds}},
	}, "", "  ")
	if err != nil {
		return err
	}
	// Write-then-rename so sing-box never reads a half-written file.
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after a successful rename
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Chmod(0o644)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return renameRetry(f.Name(), path)
}

// renameRetry is os.Rename, retried briefly: on Windows the rename fails
// with a sharing violation while sing-box has the old file open to reload it.
func renameRetry(from, to string) error {
	var err error
	for i := 0; i < 10; i++ {
		if err = os.Rename(from, to); err == nil || runtime.GOOS != "windows" {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

// selfProcs are the process names whose traffic sing-box must never capture.
// Windows reports image names with their extension.
func selfProcs() []string {
	if runtime.GOOS == "windows" {
		return []string{"ciadpi.exe", "autodpi.exe"}
	}
	return []string{"ciadpi", "autodpi"}
}

type obj = map[string]any

// DefaultDoH are the resolvers used when Options.DoH is empty: two addresses of
// one service, so that either can stall without taking DNS down.
var DefaultDoH = []string{"1.1.1.1", "1.0.0.1"}

func dohServers(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultDoH...)
	}
	return out
}

func dohTag(i int) string {
	if i == 0 {
		return "doh" // also route.default_domain_resolver
	}
	return fmt.Sprintf("doh%d", i+1)
}

// dnsConfig builds the dns section. One resolver is used as is. With several,
// every query goes to all of them at once (sing-box 1.14 "evaluate" +
// "race"): the first usable answer (NOERROR or NXDOMAIN) is returned and the
// other queries are cancelled, so a resolver that stalls costs nothing while
// another answers. If none gives a usable answer the query falls to the first
// resolver ("final"), which reports the failure after sing-box's DNS timeout.
//
// Each resolver's query is an untagged evaluate followed by its own race rules
// (match_response: true), the later evaluates speculative so that they are sent
// at once instead of after the pending race rules. A race rule on an untagged
// response reads that query's own result. On a tagged one (match_response:
// "<tag>") sing-box 1.14.4 reads the responses as it filed them when it last
// walked a rule, and an answer that landed in between counts as missing: the
// rule is dropped, and when that was the only usable answer the query fell to
// the first resolver, whose SERVFAIL reached the application (about one query
// in 450 with that resolver failing fast).
//
// Not covered by the race: route.default_domain_resolver must name one server
// and bypasses the rules. It only resolves domain-named outbound destinations,
// which this config never produces (flows arrive as IPs; the observer dials
// IPs), so it points at the first resolver.
func dnsConfig(servers []string, localDNS string, localSuffixes []string) obj {
	var list []any
	for i, s := range servers {
		list = append(list, obj{"type": "https", "tag": dohTag(i), "server": s})
	}
	dns := obj{"servers": list, "final": dohTag(0)}
	var rules []any
	if ip, err := netip.ParseAddr(localDNS); err == nil && ip.Zone() == "" && len(localSuffixes) > 0 {
		dns["servers"] = append(list, obj{"type": "udp", "tag": "local", "server": ip.String()})
		rules = append(rules,
			obj{"domain_suffix": localSuffixes, "action": "route", "server": "local"},
			obj{"domain_regex": []string{`^[^.]+$`}, "action": "route", "server": "local"}) // single-label names
	}
	if len(servers) < 2 {
		if len(rules) > 0 {
			dns["rules"] = rules
		}
		return dns
	}
	for i := range servers {
		ev := obj{"action": "evaluate", "server": dohTag(i)}
		if i > 0 {
			ev["speculative"] = true
		}
		rules = append(rules, ev)
		for _, rcode := range []string{"NOERROR", "NXDOMAIN"} {
			rules = append(rules, obj{"match_response": true, "response_rcode": rcode, "action": "respond", "race": true})
		}
	}
	dns["rules"] = rules
	return dns
}

func Build(o Options) ([]byte, error) {
	servers := dohServers(o.DoH)
	if o.LogLevel == "" {
		o.LogLevel = "warn"
	}
	if len(o.Engines) == 0 {
		return nil, fmt.Errorf("singbox: no engines configured")
	}
	if len(o.ObservePorts) == 0 {
		o.ObservePorts = []int{443}
	}
	if o.SpoofSNI == "" {
		o.SpoofSNI = "www.google.com"
	}
	if o.SpoofMethod == "" {
		o.SpoofMethod = "wrong-sequence"
	}

	dns := dnsConfig(servers, o.LocalDNS, o.LocalSuffixes)
	if o.IPv4Only {
		dns["strategy"] = "ipv4_only"
	}

	capture := "test-in"
	var inbounds []any
	if o.Tun {
		capture = "tun-in"
		addrs := []string{TunIP + "/30"}
		if o.IPv6 {
			addrs = append(addrs, tunIP6)
		}
		inbounds = append(inbounds, obj{
			"type": "tun", "tag": "tun-in",
			"address":    addrs,
			"auto_route": true,
			// sing-box 1.14: also set the utun's own (per-interface) DNS and
			// hijack port 53; the daemon may additionally point the system
			// resolver here (sysdns), since macOS service order decides.
			"dns_mode":     "hijack",
			"strict_route": o.StrictRoute,
		})
	} else {
		inbounds = append(inbounds, obj{
			"type": "mixed", "tag": "test-in", "listen": "127.0.0.1", "listen_port": o.TestPort,
		})
	}

	outbounds := []any{
		obj{"type": "direct", "tag": "direct"},
		obj{"type": "socks", "tag": "observer", "server": "127.0.0.1", "server_port": o.ObserverPort},
	}

	var retryRules, listRules []any
	var ruleSets []any
	var endpoints []any
	for _, e := range o.Engines {
		tag := RuleSetTag(e.Name)
		ruleSets = append(ruleSets, obj{
			"type": "local", "tag": tag, "format": "source", "path": RuleSetPath(o.RuleDir, e.Name),
		})
		in := e.Name + "-in"
		switch e.Kind {
		case Socks:
			outbounds = append(outbounds, obj{"type": "socks", "tag": e.Name, "server": "127.0.0.1", "server_port": e.Port})
			listRules = append(listRules, obj{"rule_set": []string{tag}, "outbound": e.Name})
		case TLSRecord, TLSSegment, TLSSpoof:
			opts := obj{"action": "route-options"}
			switch e.Kind {
			case TLSRecord:
				opts["tls_record_fragment"] = true
			case TLSSegment:
				opts["tls_fragment"] = true
			case TLSSpoof:
				opts["tls_spoof"], opts["tls_spoof_method"] = o.SpoofSNI, o.SpoofMethod
			}
			with := func(match obj) obj {
				for k, v := range opts {
					match[k] = v
				}
				return match
			}
			inbounds = append(inbounds, obj{"type": "socks", "tag": in, "listen": "127.0.0.1", "listen_port": e.Port})
			retryRules = append(retryRules,
				obj{"inbound": []string{in}, "ip_is_private": true, "action": "reject"},
				with(obj{"inbound": []string{in}}),
				obj{"inbound": []string{in}, "outbound": "direct"})
			listRules = append(listRules,
				with(obj{"rule_set": []string{tag}}),
				obj{"rule_set": []string{tag}, "outbound": "direct"})
		case WireGuard:
			if o.WireGuard == nil {
				return nil, fmt.Errorf("singbox: engine %s needs a WireGuard profile", e.Name)
			}
			p := o.WireGuard
			endpoints = append(endpoints, obj{
				"type": "wireguard", "tag": e.Name,
				"address": p.Addresses, "private_key": p.PrivateKey, "mtu": p.MTU,
				"peers": []any{obj{
					"address": p.Endpoint, "port": p.Port, "public_key": p.PublicKey,
					"allowed_ips": []string{"0.0.0.0/0", "::/0"},
				}},
			})
			inbounds = append(inbounds, obj{"type": "socks", "tag": in, "listen": "127.0.0.1", "listen_port": e.Port})
			retryRules = append(retryRules,
				obj{"inbound": []string{in}, "ip_is_private": true, "action": "reject"},
				obj{"inbound": []string{in}, "outbound": e.Name})
			listRules = append(listRules, obj{"rule_set": []string{tag}, "outbound": e.Name})
		default:
			return nil, fmt.Errorf("singbox: unknown engine kind %q", e.Kind)
		}
	}

	procs := append(selfProcs(), o.DirectProcs...)
	rules := append([]any{}, retryRules...)
	rules = append(rules,
		obj{"inbound": []string{capture}, "action": "sniff"},
		obj{"port": []int{53}, "action": "hijack-dns"},
		obj{"port": []int{5353}, "network": []string{"udp"}, "outbound": "direct"},
		obj{"process_name": procs, "outbound": "direct"},
		obj{"ip_is_private": true, "outbound": "direct"},
	)
	if o.BlockQUIC {
		// Only listed (blocked) domains lose QUIC, so their apps fall back to
		// TCP where the engines work. The default reject answers with ICMP
		// unreachable: a silent drop leaves a running QUIC stream (a YouTube
		// video) hanging instead of failing over. Everything else keeps QUIC;
		// the measured DPI does not inspect it.
		tags := make([]string, len(o.Engines))
		for i, e := range o.Engines {
			tags[i] = RuleSetTag(e.Name)
		}
		rules = append(rules, obj{"rule_set": tags, "port": []int{443}, "network": []string{"udp"}, "action": "reject"})
	}
	rules = append(rules, listRules...)
	rules = append(rules, obj{"port": o.ObservePorts, "network": []string{"tcp"}, "outbound": "observer"})

	cfg := obj{
		"log":       obj{"level": o.LogLevel, "timestamp": true},
		"dns":       dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": obj{
			"auto_detect_interface":   true,
			"default_domain_resolver": "doh",
			"rule_set":                ruleSets,
			"rules":                   rules,
			"final":                   "direct",
		},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	return json.MarshalIndent(cfg, "", "  ")
}
