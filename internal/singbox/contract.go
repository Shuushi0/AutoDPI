package singbox

import (
	"fmt"
	"runtime"
)

// Case is one configuration Build produces.
type Case struct {
	Name   string
	Config []byte
}

// Contract writes rule-sets into dir and returns configurations that between
// them use every part of sing-box Build can ask for: each engine kind, the
// TUN and the test inbound, IPv6, the QUIC block, one, two and three raced
// resolvers, the network's own resolver and the WireGuard endpoint.
//
// sing-box is built with only what AutoDPI uses registered
// (tools/singbox/main.go). Whatever a new sing-box release renames, moves or
// stops registering shows up as one of these being refused. The tests run
// them through `sing-box check` on the build machine, the release script
// refuses to package when they did not run, and `autodpi selftest` runs them
// on the user's machine before an update replaces the installed version.
func Contract(dir string) ([]Case, error) {
	engine := func(name string, kind Kind, port int) Engine { return Engine{Name: name, Kind: kind, Port: port} }
	every := []Engine{
		engine("tlsrec", TLSRecord, 21081), engine("ciadpi", Socks, 21082), engine("tlsspoof", TLSSpoof, 21083),
		engine("tlsfrag", TLSSegment, 21084), engine("warp", WireGuard, 21085),
	}
	for _, e := range every {
		if err := WriteRuleSet(dir, e.Name, []string{"example.org"}); err != nil {
			return nil, err
		}
	}
	// Not a real key: sing-box only has to accept the shape.
	wg := &WireGuardProfile{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Addresses: []string{"172.16.0.2/32"}, MTU: 1280, Endpoint: "engage.cloudflareclient.com", Port: 2408,
	}
	base := Options{ObserverPort: 21080, RuleDir: dir}
	with := func(f func(o *Options)) Options {
		o := base
		f(&o)
		return o
	}
	cases := []struct {
		name string
		o    Options
	}{
		{"the usual capture", with(func(o *Options) {
			// What a fresh install runs: the default engines and settings
			// (ipv4_only among them), and on Windows the strict route.
			o.Engines, o.Tun, o.IPv6, o.BlockQUIC, o.IPv4Only = every[:3], true, true, true, true
			o.LocalDNS, o.LocalSuffixes = "192.168.1.1", []string{"lan", "corp"}
			o.StrictRoute = runtime.GOOS == "windows"
		})},
		{"IPv4 only, one resolver, one engine", with(func(o *Options) {
			o.Engines, o.Tun, o.IPv4Only, o.DoH = every[:1], true, true, []string{"1.1.1.1"}
			o.LogLevel = "fatal" // what the daemon runs with unless it is given -v
			o.DirectProcs, o.ObservePorts, o.SpoofSNI = []string{"example.exe"}, []int{443, 8443}, "example.org"
		})},
		{"three raced resolvers, strict route", with(func(o *Options) {
			o.Engines, o.Tun, o.StrictRoute = every[:3], true, true
			o.DoH = []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} // addresses only, as the settings require
		})},
		{"every engine kind with the WireGuard endpoint", with(func(o *Options) {
			o.Engines, o.Tun, o.IPv6, o.BlockQUIC, o.WireGuard = every, true, true, true, wg
			o.LocalDNS, o.LocalSuffixes = "10.0.0.1", []string{"home.arpa"}
		})},
		{"the test inbound instead of the TUN", with(func(o *Options) {
			o.Engines, o.TestPort = every[:3], 21090
		})},
	}
	out := make([]Case, 0, len(cases))
	for _, c := range cases {
		cfg, err := Build(c.o)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.name, err)
		}
		out = append(out, Case{Name: c.name, Config: cfg})
	}
	return out, nil
}
