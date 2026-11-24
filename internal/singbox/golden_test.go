//go:build !windows

package singbox

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/domain"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden configurations in testdata/")

// The whole configuration, byte for byte, for the cases users run.
//
// Every other test looks at a part: `sing-box check` accepts a configuration,
// a wire test sees one path work, the pin test names the settings sing-box
// would accept either way. A round of 147 deliberate changes to config.go
// showed what falls between them: 47 passed every test, among them the list
// rules moved in front of the rule that keeps our own processes out (a
// routing loop), the QUIC block moved behind the rules that swallow it, local
// names sent to DoH, the WARP engine routed direct, the engines' inbounds
// listening on every interface, and the Windows process names.
//
// So what Build writes is kept here as it is, for macOS and for Windows. A
// change to config.go that changes any of it fails this test and shows the
// difference; if the change is meant, run
//
//	go test ./internal/singbox/ -run TestConfigurationsAreUnchanged -update
//
// read the diff of testdata/ as the review of what every user will run, and
// commit it with the change.
func TestConfigurationsAreUnchanged(t *testing.T) {
	engines := []Engine{
		{Name: "tlsrec", Kind: TLSRecord, Port: 21081}, {Name: "ciadpi", Kind: Socks, Port: 21082},
		{Name: "tlsspoof", Kind: TLSSpoof, Port: 21083}, {Name: "tlsfrag", Kind: TLSSegment, Port: 21084},
		{Name: "warp", Kind: WireGuard, Port: 21085},
	}
	wg := &WireGuardProfile{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Addresses: []string{"172.16.0.2/32", "2606:4700:110:8a36::2/128"}, MTU: 1280, Endpoint: "engage.cloudflareclient.com", Port: 2408,
	}
	// The suffixes the daemon passes: the built-in list (it adds the user's
	// own). Four hand-picked ones stood here once, and the "fresh install"
	// case pinned a configuration no install ever ran.
	local := domain.LocalSuffixes()
	// What the daemon passes for a fresh install (daemon.startSingBox with
	// config.Default): three engines, the QUIC block, ipv4_only, the
	// gateway as the local resolver, log level fatal.
	fresh := Options{Engines: engines[:3], ObserverPort: 21080, RuleDir: "/run/autodpi", Tun: true,
		BlockQUIC: true, IPv4Only: true, LocalDNS: "192.168.1.1", LocalSuffixes: local, LogLevel: "fatal"}
	with := func(f func(o *Options)) Options {
		o := fresh
		f(&o)
		return o
	}
	cases := []struct {
		name, goos string
		o          Options
	}{
		{"macos-default", "darwin", fresh},
		{"macos-ipv6", "darwin", with(func(o *Options) { o.IPv6 = true })},
		{"windows-default", "windows", with(func(o *Options) { o.StrictRoute = true })},
		{"windows-ipv6", "windows", with(func(o *Options) { o.StrictRoute, o.IPv6 = true, true })},
		{"every-engine-with-warp", "darwin", with(func(o *Options) {
			o.Engines, o.WireGuard, o.IPv6 = engines, wg, true
			o.DoH = []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
		})},
		{"one-resolver-own-settings", "darwin", with(func(o *Options) {
			o.DoH, o.BlockQUIC, o.IPv4Only, o.LocalDNS, o.LocalSuffixes = []string{"9.9.9.9"}, false, false, "", nil
			o.SpoofSNI, o.ObservePorts, o.DirectProcs, o.LogLevel = "example.org", []int{443, 8443}, []string{"example"}, "warn"
		})},
		{"test-inbound", "darwin", with(func(o *Options) { o.Tun, o.TestPort = false, 21090 })},
		// Inputs none of the cases above varies, each of which has code of
		// its own in Build: one resolver WITH the gateway's local rules; an
		// IPv6 network with ipv4_only switched off; a single engine with the
		// QUIC block; a WARP profile that is not the usual endpoint and port
		// and has no IPv6 network under it; an IPv6 gateway.
		{"one-resolver-with-gateway", "darwin", with(func(o *Options) { o.DoH = []string{"9.9.9.9"} })},
		{"ipv6-without-ipv4-only", "darwin", with(func(o *Options) { o.IPv6, o.IPv4Only = true, false })},
		{"one-engine", "darwin", with(func(o *Options) { o.Engines = engines[1:2] })},
		{"warp-own-endpoint", "darwin", with(func(o *Options) {
			w := *wg
			w.Endpoint, w.Port, w.MTU = "162.159.192.1", 4500, 1420
			o.Engines, o.WireGuard = engines[3:], &w
		})},
		{"ipv6-gateway", "darwin", with(func(o *Options) { o.IPv6, o.LocalDNS = true, "fe80::1" })},
		{"ipv6-gateway-global", "darwin", with(func(o *Options) { o.IPv6, o.LocalDNS = true, "2a02:ff0:1::1" })},
	}
	old := goos
	t.Cleanup(func() { goos = old })
	for _, c := range cases {
		goos = c.goos
		got, err := Build(c.o)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got = append(got, '\n')
		file := filepath.Join("testdata", c.name+".json")
		if *updateGolden {
			if err := os.WriteFile(file, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s: %v (run with -update to write it)", c.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the configuration differs from %s:\n%s", c.name, file, firstDiff(want, got))
		}
	}
}

// firstDiff shows the first lines that differ, with a little before them.
func firstDiff(want, got []byte) string {
	w, g := bytes.Split(want, []byte("\n")), bytes.Split(got, []byte("\n"))
	for i := 0; i < len(w) || i < len(g); i++ {
		var a, b []byte
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if !bytes.Equal(a, b) {
			var out bytes.Buffer
			for j := max(0, i-3); j < i; j++ {
				out.WriteString("    " + string(w[j]) + "\n")
			}
			for j := i; j < min(i+6, len(w)); j++ {
				out.WriteString("  - " + string(w[j]) + "\n")
			}
			for j := i; j < min(i+6, len(g)); j++ {
				out.WriteString("  + " + string(g[j]) + "\n")
			}
			return out.String()
		}
	}
	return ""
}

// The rule-set files are what decides which sites go through an engine, and
// sing-box reads them as they are: their content is pinned as well. Sets with
// several names in particular: every other test wrote sets of one, so
// dropping the last name of a list, or matching names exactly instead of as
// suffixes, passed everything.
func TestRuleSetFilesAreUnchanged(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]struct {
		domains []string
		want    string
	}{
		"several": {[]string{"zeta.example", "alpha.example", "mid.example.org"}, `{
  "rules": [
    {
      "domain_suffix": [
        "alpha.example",
        "mid.example.org",
        "zeta.example"
      ]
    }
  ],
  "version": 3
}
`},
		"one": {[]string{"only.example"}, `{
  "rules": [
    {
      "domain_suffix": [
        "only.example"
      ]
    }
  ],
  "version": 3
}
`},
		"none": {nil, `{
  "rules": [
    {
      "domain_suffix": [
        "placeholder.invalid"
      ]
    }
  ],
  "version": 3
}
`},
	} {
		if err := WriteRuleSet(dir, name, c.domains); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(RuleSetPath(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want {
			t.Errorf("%s: the rule-set file is\n%s\nwant\n%s", name, got, c.want)
		}
		if fi, _ := os.Stat(RuleSetPath(dir, name)); fi.Mode().Perm() != 0o644 {
			t.Errorf("%s: mode %v", name, fi.Mode().Perm())
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}
