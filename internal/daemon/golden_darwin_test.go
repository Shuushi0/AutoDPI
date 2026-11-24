package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/singbox"
)

// What the daemon hands to sing-box on a fresh install is the configuration
// internal/singbox pins (testdata/macos-default.json), byte for byte.
//
// The pin there covers what Build makes of its input; this covers the input.
// Without it a one-word change in startSingBox passed every test: the wrong
// folder for the rule-sets or the wrong observer port (no bypass for anyone),
// the QUIC block or the gateway dropped, the user's resolvers or server name
// ignored. A deliberate change shows up as a difference here; it is made in
// internal/singbox's golden (-update there), and this test then says whether
// the daemon really passes it.
func TestTheDaemonWritesThePinnedConfiguration(t *testing.T) {
	d, f := rig(t, Options{})
	d.engines = []singbox.Engine{
		{Name: "tlsrec", Kind: singbox.TLSRecord, Port: 21081}, {Name: "ciadpi", Kind: singbox.Socks, Port: 21082},
		{Name: "tlsspoof", Kind: singbox.TLSSpoof, Port: 21083},
	}
	d.obsPort = 21080
	f.set(func(f *fakeSys) { f.net.Gateway = "192.168.1.1" })
	pass(t, d)
	if !d.running() {
		s, det := state(d)
		t.Fatalf("the capture did not start: %s (%s)", s, det)
	}
	got, err := os.ReadFile(filepath.Join(d.p.Run, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	got = append(bytes.ReplaceAll(got, []byte(d.p.Run), []byte("/run/autodpi")), '\n')
	want, err := os.ReadFile(filepath.Join("..", "singbox", "testdata", "macos-default.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		gl, wl := bytes.Split(got, []byte("\n")), bytes.Split(want, []byte("\n"))
		for i := 0; i < len(gl) && i < len(wl); i++ {
			if !bytes.Equal(gl[i], wl[i]) {
				t.Fatalf("the daemon's configuration differs from the pinned one at line %d:\n  pinned: %s\n  daemon: %s", i+1, wl[i], gl[i])
			}
		}
		t.Fatalf("the daemon's configuration has %d lines, the pinned one %d", len(gl), len(wl))
	}
}

// And what the user set reaches sing-box: every setting the configuration
// file can change in what startSingBox passes.
func TestTheUsersSettingsReachSingBox(t *testing.T) {
	d, f := rig(t, Options{})
	d.cfg.BlockQUIC, d.cfg.IPv4Only = false, false
	d.cfg.SpoofSNI = "www.example.org"
	d.cfg.DoHServers = []string{"9.9.9.9"}
	d.cfg.LocalDomains = []string{"company.example"}
	d.engines = []singbox.Engine{{Name: "tlsspoof", Kind: singbox.TLSSpoof, Port: 21083}, {Name: "ciadpi", Kind: singbox.Socks, Port: 21082}}
	f.set(func(f *fakeSys) { f.net.Gateway = "10.0.0.1" })
	pass(t, d)
	got, err := os.ReadFile(filepath.Join(d.p.Run, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	for what, has := range map[string]bool{
		`"tls_spoof": "www.example.org"`:       true,
		`"server": "9.9.9.9"`:                  true,
		`"server": "1.1.1.1"`:                  false,
		`"company.example"`:                    true,
		`"server": "10.0.0.1"`:                 true,
		`"strategy": "ipv4_only"`:              false,
		`"action": "reject"`:                   true, // the engines' own reject of private addresses
		`"network": [` + "\n          \"udp\"": true,
	} {
		if bytes.Contains(got, []byte(what)) != has {
			t.Errorf("%s: present=%v, want %v", what, !has, has)
		}
	}
	// The QUIC block is the one reject rule with a rule_set: gone when off.
	if bytes.Contains(got, []byte(`"blocked-ciadpi"`+"\n        ],\n        \"network\"")) {
		t.Error("QUIC is blocked although block_quic is off")
	}
	// The first engine of the ladder is the first in the file.
	if i, j := bytes.Index(got, []byte(`"tlsspoof-in"`)), bytes.Index(got, []byte(`"tag": "ciadpi"`)); i < 0 || j < 0 {
		t.Errorf("an engine is missing from the configuration (tlsspoof %d, ciadpi %d)", i, j)
	}
}
