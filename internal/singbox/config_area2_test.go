package singbox_test

// Area 2 review tests for the generated sing-box configuration (two-resolver
// DNS setup in particular). Everything here is loopback or `sing-box check`
// only: no TUN, no root. TestArea2Bug_* tests fail today and reproduce a
// confirmed finding.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"crypto/tls"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/netx"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
)

type dohCase struct {
	name string
	list []string
	bug  bool // config.Validate accepts it but sing-box check rejects it
}

var area2DoHCases = []dohCase{
	{"default", nil, false},
	{"one", []string{"1.1.1.1"}, false},
	{"two", []string{"1.1.1.1", "1.0.0.1"}, false},
	{"three", []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}, false},
	{"five", []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}, false},
	{"dups and blanks", []string{" 1.1.1.1 ", "", "1.1.1.1", "1.0.0.1", "  "}, false},
	{"hostname", []string{"dns.google"}, true},
	{"two hostnames", []string{"cloudflare-dns.com", "dns.google"}, true},
	{"ip and hostname", []string{"1.1.1.1", "dns.google"}, true},
	{"ipv6 literal", []string{"2606:4700:4700::1111"}, false},
	{"two ipv6 literals", []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}, false},
	{"bracketed ipv6", []string{"[2606:4700:4700::1111]"}, false},
	{"ip:port", []string{"1.1.1.1:443"}, true},
	{"host:port two", []string{"1.1.1.1:443", "1.0.0.1:443"}, true},
}

func area2Bin(t *testing.T) string {
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
	t.Skip("sing-box binary not available")
	return ""
}

// singBoxCheck returns sing-box's verdict on cfg.
func singBoxCheck(t *testing.T, cfg []byte) error {
	t.Helper()
	f := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(f, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := exec.Command(area2Bin(t), "check", "-c", f)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

func area2Engines(t *testing.T, dir string, kinds ...string) []singbox.Engine {
	t.Helper()
	all := map[string]singbox.Kind{"ciadpi": singbox.Socks, "tlsrec": singbox.TLSRecord, "tlsfrag": singbox.TLSSegment, "tlsspoof": singbox.TLSSpoof, "warp": singbox.WireGuard}
	var out []singbox.Engine
	for _, k := range kinds {
		e := singbox.Engine{Name: k, Kind: all[k], Port: freePort(t)}
		out = append(out, e)
		if err := singbox.WriteRuleSet(dir, k, []string{"discord.com"}); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

var area2Profile = &singbox.WireGuardProfile{
	PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Addresses: []string{"172.16.0.2/32"},
	MTU: 1280, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Endpoint: "engage.cloudflareclient.com", Port: 2408,
}

// checkRefs verifies reference integrity of a generated config: every tag a
// rule, rule-set or resolver mentions exists, and the DNS rules are built the
// way the race needs them.
func checkRefs(cfg []byte) []string {
	var c struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
			Final   string           `json:"final"`
		} `json:"dns"`
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
		Route     struct {
			Rules    []map[string]any `json:"rules"`
			RuleSet  []map[string]any `json:"rule_set"`
			Resolver string           `json:"default_domain_resolver"`
			Final    string           `json:"final"`
		} `json:"route"`
	}
	var bad []string
	if err := json.Unmarshal(cfg, &c); err != nil {
		return []string{err.Error()}
	}
	set := func(items []map[string]any) map[string]bool {
		m := map[string]bool{}
		for _, it := range items {
			tag, _ := it["tag"].(string)
			if tag == "" {
				bad = append(bad, fmt.Sprintf("untagged item %v", it))
			}
			if m[tag] {
				bad = append(bad, "duplicate tag "+tag)
			}
			m[tag] = true
		}
		return m
	}
	servers, inbounds, outbounds, endpoints, ruleSets := set(c.DNS.Servers), set(c.Inbounds), set(c.Outbounds), set(c.Endpoints), set(c.Route.RuleSet)
	if !servers[c.DNS.Final] || !servers[c.Route.Resolver] {
		bad = append(bad, "final/default_domain_resolver is not a dns server")
	}
	if !outbounds[c.Route.Final] {
		bad = append(bad, "route.final unknown")
	}
	// Every server is evaluated once, untagged, and its race rules follow it
	// (they read the latest untagged response).
	evaluated := map[string]bool{}
	lastEval := ""
	for _, r := range c.DNS.Rules {
		switch r["action"] {
		case "evaluate":
			s, _ := r["server"].(string)
			if !servers[s] {
				bad = append(bad, "evaluate: unknown server")
			}
			if evaluated[s] || r["tag"] != nil {
				bad = append(bad, fmt.Sprintf("evaluate %v: twice or tagged", r))
			}
			evaluated[s], lastEval = true, s
		case "respond":
			if r["match_response"] != true || r["race"] != true || lastEval == "" {
				bad = append(bad, fmt.Sprintf("race rule %v: not on an earlier untagged evaluate", r))
			}
		default:
			bad = append(bad, fmt.Sprintf("unexpected dns rule %v", r))
		}
	}
	if len(c.DNS.Rules) > 0 && len(evaluated) != len(servers) {
		bad = append(bad, fmt.Sprintf("%d of %d servers evaluated", len(evaluated), len(servers)))
	}
	for _, r := range c.Route.Rules {
		if o, ok := r["outbound"].(string); ok && !outbounds[o] && !endpoints[o] {
			bad = append(bad, "rule routes to unknown outbound "+o)
		}
		if rs, ok := r["rule_set"].([]any); ok {
			for _, x := range rs {
				if !ruleSets[x.(string)] {
					bad = append(bad, fmt.Sprintf("rule uses unknown rule_set %v", x))
				}
			}
		}
		if in, ok := r["inbound"].([]any); ok {
			for _, x := range in {
				if !inbounds[x.(string)] {
					bad = append(bad, fmt.Sprintf("rule uses unknown inbound %v", x))
				}
			}
		}
	}
	// ports unique among listening inbounds
	ports := map[int]string{}
	for _, in := range c.Inbounds {
		if p, ok := in["listen_port"].(float64); ok {
			if o, dup := ports[int(p)]; dup {
				bad = append(bad, fmt.Sprintf("port %d used by %s and %v", int(p), o, in["tag"]))
			}
			ports[int(p)] = fmt.Sprint(in["tag"])
		}
	}
	return bad
}

func TestArea2_ConfigMatrixValidatesAndIsConsistent(t *testing.T) {
	dohCases := area2DoHCases[:0:0]
	for _, c := range area2DoHCases {
		if !c.bug {
			dohCases = append(dohCases, c)
		}
	}
	engineSets := [][]string{
		{"tlsrec"}, {"ciadpi"}, {"tlsfrag"}, {"tlsspoof"},
		{"tlsrec", "ciadpi", "tlsspoof"}, // the default ladder
		{"tlsrec", "ciadpi", "tlsfrag", "tlsspoof", "warp"},
	}
	type mode struct {
		name                      string
		tun, v6, v4only, quic, sr bool
	}
	modes := []mode{
		{"tun default", true, false, true, true, false},
		{"tun v6", true, true, true, true, false},
		{"tun v6 dual-stack dns", true, true, false, false, false},
		{"tun strict", true, false, true, true, true},
		{"test port", false, false, true, true, false},
	}
	var fails []string
	n := 0
	for _, dc := range dohCases {
		validatorOK := func() bool {
			c := config.Default()
			c.DoHServers = dc.list
			if dc.list == nil {
				c.DoHServers = nil
			}
			return c.Validate() == nil
		}()
		for ei, kinds := range engineSets {
			if ei != 4 && dc.name != "default" && dc.name != "two" { // keep the matrix affordable
				continue
			}
			for _, m := range modes {
				if ei != 4 && ei != 5 && m.name != "tun default" && m.name != "test port" {
					continue
				}
				dir := t.TempDir()
				o := singbox.Options{
					Engines: area2Engines(t, dir, kinds...), ObserverPort: freePort(t), RuleDir: dir,
					Tun: m.tun, TestPort: freePort(t), BlockQUIC: m.quic, IPv4Only: m.v4only, IPv6: m.v6, StrictRoute: m.sr,
					DoH: dc.list, ObservePorts: []int{443}, DirectProcs: []string{"Discord"},
				}
				if slices.Contains(kinds, "warp") {
					o.WireGuard = area2Profile
				}
				cfg, err := singbox.Build(o)
				id := fmt.Sprintf("doh=%s engines=%v mode=%s", dc.name, kinds, m.name)
				if err != nil {
					fails = append(fails, id+": Build: "+err.Error())
					continue
				}
				n++
				if bad := checkRefs(cfg); len(bad) > 0 {
					fails = append(fails, id+": "+strings.Join(bad, "; "))
				}
				if err := singBoxCheck(t, cfg); err != nil {
					note := ""
					if validatorOK {
						note = " [config.Validate ACCEPTS this doh_servers value]"
					}
					fails = append(fails, id+": sing-box check: "+err.Error()+note)
				}
			}
		}
	}
	t.Logf("%d configs generated", n)
	for _, f := range fails {
		t.Error(f)
	}
}

// DNS-rule order in the TUN config: hijack of port 53 must come before every
// "direct" rule (otherwise a router/private resolver or our own process would
// bypass DoH, and the daemon's health query to 1.1.1.1:53 would not test the
// hijack), and every retry-inbound rule precedes sniff.
func TestArea2_TunRuleOrderProtectsDNS(t *testing.T) {
	dir := t.TempDir()
	cfg, err := singbox.Build(singbox.Options{
		Engines: area2Engines(t, dir, "tlsrec", "ciadpi", "tlsspoof"), ObserverPort: freePort(t), RuleDir: dir, Tun: true, BlockQUIC: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Route struct{ Rules []map[string]any } `json:"route"`
	}
	_ = json.Unmarshal(cfg, &c)
	idx := func(pred func(map[string]any) bool) int {
		for i, r := range c.Route.Rules {
			if pred(r) {
				return i
			}
		}
		return -1
	}
	sniff := idx(func(r map[string]any) bool { return r["action"] == "sniff" })
	hijack := idx(func(r map[string]any) bool { return r["action"] == "hijack-dns" })
	firstPrivate := idx(func(r map[string]any) bool { return r["ip_is_private"] == true && r["outbound"] == "direct" })
	firstProc := idx(func(r map[string]any) bool { return r["process_name"] != nil })
	lastRetry := -1
	for i, r := range c.Route.Rules {
		if r["inbound"] != nil && r["action"] != "sniff" {
			lastRetry = i
		}
	}
	obs := idx(func(r map[string]any) bool { return r["outbound"] == "observer" })
	if !(lastRetry < sniff && sniff < hijack && hijack < firstProc && hijack < firstPrivate && obs == len(c.Route.Rules)-1) {
		t.Fatalf("rule order: lastRetry=%d sniff=%d hijack=%d proc=%d private=%d observer=%d of %d", lastRetry, sniff, hijack, firstProc, firstPrivate, obs, len(c.Route.Rules))
	}
	// A retry inbound must never be able to reach the observer (loop): its rules
	// all terminate in reject / engine outbound / direct before the catch-all.
	for _, r := range c.Route.Rules {
		if in, ok := r["inbound"].([]any); ok && r["outbound"] == "observer" {
			t.Fatalf("retry inbound %v routed to the observer: loop", in)
		}
	}
}

// singbox.dohServers and netx.CleanServers must agree, or the daemon's own
// lookups and sing-box's would use different resolvers.
func TestArea2_DoHListNormalisationAgreesWithDaemonClient(t *testing.T) {
	tokens := []string{"1.1.1.1", " 1.1.1.1", "1.1.1.1 ", "1.0.0.1", "", "  ", "\t9.9.9.9\t", "dns.google", "DNS.GOOGLE", "8.8.8.8"}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 300; i++ {
		var in []string
		for j := rng.Intn(6); j > 0; j-- {
			in = append(in, tokens[rng.Intn(len(tokens))])
		}
		dir := t.TempDir()
		cfg, err := singbox.Build(singbox.Options{Engines: area2Engines(t, dir, "tlsrec"), ObserverPort: 1, RuleDir: dir, TestPort: 2, DoH: in})
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			DNS struct{ Servers []map[string]any } `json:"dns"`
		}
		_ = json.Unmarshal(cfg, &c)
		var got []string
		for _, s := range c.DNS.Servers {
			got = append(got, s["server"].(string))
		}
		if want := netx.CleanServers(in); !slices.Equal(got, want) {
			t.Fatalf("input %q: sing-box uses %q, daemon client uses %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Live resolver race with three resolvers.

type a2mode string

const (
	a2OK       a2mode = "ok"
	a2Stall    a2mode = "stall"
	a2Servfail a2mode = "servfail"
	a2Refused  a2mode = "refused"
	a2NX       a2mode = "nx"
)

func a2Resolver(t *testing.T, ip string, mode a2mode) int {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw []byte
		if r.Method == http.MethodGet {
			raw, _ = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		} else {
			raw, _ = io.ReadAll(r.Body)
		}
		var m dnsmessage.Message
		if err := m.Unpack(raw); err != nil || len(m.Questions) == 0 {
			w.WriteHeader(400)
			return
		}
		q := m.Questions[0]
		if mode == a2Stall {
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: m.ID, Response: true, RecursionAvailable: true, RCode: dnsmessage.RCodeSuccess},
			Questions: m.Questions,
		}
		switch mode {
		case a2Servfail:
			resp.Header.RCode = dnsmessage.RCodeServerFailure
		case a2Refused:
			resp.Header.RCode = dnsmessage.RCodeRefused
		case a2NX:
			resp.Header.RCode = dnsmessage.RCodeNameError
		default:
			if q.Type == dnsmessage.TypeA {
				resp.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1},
					Body:   &dnsmessage.AResource{A: [4]byte(net.ParseIP(ip).To4())},
				}}
			}
		}
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	srv.TLS = &tls.Config{}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	return port
}

// Real sing-box with three resolvers in every health combination that matters:
// a usable answer from any one must win quickly; if none is usable the query
// must fail rather than hang.
func TestArea2_SingBoxThreeResolverRace(t *testing.T) {
	bin := area2Bin(t)
	type tc struct {
		name    string
		modes   [3]a2mode
		want    string // IP expected, "" = NXDOMAIN, "fail" = failure expected
		maxTook time.Duration
	}
	cases := []tc{
		{"stall,stall,ok", [3]a2mode{a2Stall, a2Stall, a2OK}, "192.0.2.3", 2 * time.Second},
		{"servfail,stall,ok", [3]a2mode{a2Servfail, a2Stall, a2OK}, "192.0.2.3", 2 * time.Second},
		{"servfail,servfail,ok", [3]a2mode{a2Servfail, a2Servfail, a2OK}, "192.0.2.3", 2 * time.Second},
		{"refused,ok,stall", [3]a2mode{a2Refused, a2OK, a2Stall}, "192.0.2.2", 2 * time.Second},
		{"stall,nx,stall", [3]a2mode{a2Stall, a2NX, a2Stall}, "", 2 * time.Second},
		{"servfail,servfail,servfail", [3]a2mode{a2Servfail, a2Servfail, a2Servfail}, "fail", 8 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ports := [3]int{}
			for i, m := range c.modes {
				ports[i] = a2Resolver(t, fmt.Sprintf("192.0.2.%d", i+1), m)
			}
			dir := t.TempDir()
			cfg, err := singbox.Build(singbox.Options{
				Engines:      area2Engines(t, dir, "tlsrec"),
				ObserverPort: freePort(t), RuleDir: dir, TestPort: freePort(t), LogLevel: "debug",
				DoH: []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"},
			})
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			_ = json.Unmarshal(cfg, &m)
			servers := m["dns"].(map[string]any)["servers"].([]any)
			for i := range servers {
				s := servers[i].(map[string]any)
				s["server"], s["server_port"] = "127.0.0.1", ports[i]
				s["tls"] = map[string]any{"insecure": true}
			}
			probe := addDNSProbe(t, m)
			cfg, _ = json.MarshalIndent(m, "", "  ")
			cfgPath := filepath.Join(dir, "config.json")
			if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			cmd := exec.Command(bin, "run", "-c", cfgPath)
			cmd.Stdout, cmd.Stderr = &logs, &logs
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				if t.Failed() {
					t.Logf("sing-box log tail:\n%s", tail(logs.String(), 2500))
				}
			}()
			waitListening(t, fmt.Sprintf("127.0.0.1:%d", tcpPort(m)))
			for i := 0; i < 2; i++ {
				start := time.Now()
				ans := probeQuery(t, probe, fmt.Sprintf("h%d.race.test", i), 40*time.Second)
				took := time.Since(start)
				switch c.want {
				case "fail":
					if len(ans.Answer) != 0 || took > c.maxTook {
						t.Fatalf("query %d: %+v after %v (want a quick failure)", i, ans, took)
					}
				case "":
					if ans.Status != int(dnsmessage.RCodeNameError) || took > c.maxTook {
						t.Fatalf("query %d: %+v after %v (want NXDOMAIN)", i, ans, took)
					}
				default:
					if len(ans.Answer) != 1 || ans.Answer[0] != c.want || took > c.maxTook {
						t.Fatalf("query %d: %+v after %v (want %s)", i, ans, took, c.want)
					}
				}
			}
		})
	}
}

// startRace runs real sing-box with the configuration Build generates for
// len(modes) resolvers, each repointed at a local DoH endpoint answering the
// way its mode says, and returns the port of a plain UDP DNS listener.
func startRace(t *testing.T, modes ...a2mode) int {
	t.Helper()
	bin := area2Bin(t)
	dir := t.TempDir()
	doh := make([]string, len(modes))
	for i := range modes {
		doh[i] = fmt.Sprintf("127.0.0.%d", i+1)
	}
	cfg, err := singbox.Build(singbox.Options{
		Engines:      area2Engines(t, dir, "tlsrec"),
		ObserverPort: freePort(t), RuleDir: dir, TestPort: freePort(t), LogLevel: "warn", DoH: doh,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(cfg, &m)
	for i, s := range m["dns"].(map[string]any)["servers"].([]any) {
		s := s.(map[string]any)
		s["server"], s["server_port"] = "127.0.0.1", a2Resolver(t, fmt.Sprintf("192.0.2.%d", i+1), modes[i])
		s["tls"] = map[string]any{"insecure": true}
	}
	probe := addDNSProbe(t, m)
	cfg, _ = json.MarshalIndent(m, "", "  ")
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("sing-box log tail:\n%s", tail(logs.String(), 2500))
		}
	})
	waitListening(t, fmt.Sprintf("127.0.0.1:%d", tcpPort(m)))
	return probe
}

// The race must never lose the usable answer. sing-box 1.14.4 matches a race
// rule on a tagged response against the responses it filed when it last
// walked a rule; one that landed in between was matched as missing and its
// rules dropped, and the query fell to the first resolver: SERVFAIL for about
// one query in 450 with that resolver failing fast. A first resolver that
// fails at once makes every query take that path.
func TestArea2_SingBoxRaceKeepsTheLateAnswer(t *testing.T) {
	for _, modes := range [][]a2mode{{a2Servfail, a2OK}, {a2Servfail, a2Servfail, a2OK}, {a2Refused, a2NX}} {
		t.Run(fmt.Sprint(modes), func(t *testing.T) {
			probe := startRace(t, modes...)
			want := fmt.Sprintf("192.0.2.%d", len(modes))
			for i := 0; i < 300; i++ {
				ans := probeQuery(t, probe, fmt.Sprintf("q%d.keep.test", i), 10*time.Second)
				switch {
				case modes[len(modes)-1] == a2NX:
					if ans.Status != int(dnsmessage.RCodeNameError) {
						t.Fatalf("query %d: %+v (want NXDOMAIN)", i, ans)
					}
				case len(ans.Answer) != 1 || ans.Answer[0] != want:
					t.Fatalf("query %d: %+v (want %s)", i, ans, want)
				}
			}
		})
	}
}

// doh_servers is documented as "hosts or IPs" and config.Validate accepts
// hostnames and host:port; sing-box refuses every such configuration at start
// ("missing domain resolver for domain server address"), so the daemon would
// start sing-box, watch it die, and release with a misleading
// "did not bring the capture up in 30s".
func TestArea2Bug_ValidatedDoHServersThatSingBoxRejects(t *testing.T) {
	for _, dc := range area2DoHCases {
		if !dc.bug {
			continue
		}
		c := config.Default()
		c.DoHServers = dc.list
		if err := c.Validate(); err != nil {
			continue // rejected up front: fine
		}
		dir := t.TempDir()
		cfg, err := singbox.Build(singbox.Options{Engines: area2Engines(t, dir, "tlsrec"), ObserverPort: freePort(t), RuleDir: dir, Tun: true, DoH: dc.list})
		if err != nil {
			t.Errorf("%s: Build: %v", dc.name, err)
			continue
		}
		if err := singBoxCheck(t, cfg); err != nil {
			t.Errorf("doh_servers %q passes config.Validate but sing-box rejects it: %v", dc.list, err)
		}
	}
}
