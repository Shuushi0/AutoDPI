package singbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func checkFile(bin, f string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(bin, "check", "-c", f)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err == nil && strings.TrimSpace(out.String()) != "" {
		// A deprecation warning today is a refusal one release later, and the
		// only notice there will be.
		err = errors.New("accepted, but sing-box had something to say about it")
	}
	return out.String(), err
}

// The tests take sing-box from AUTODPI_BINDIR when it is set and from bin/
// otherwise. A directory without the binary used to fall through to bin/ in
// silence: a rehearsal of a sing-box upgrade with a typo in the path then
// passed, against the old binary.
func TestMain(m *testing.M) {
	if d := os.Getenv("AUTODPI_BINDIR"); d != "" {
		name := "sing-box"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		if _, err := os.Stat(filepath.Join(d, name)); err != nil {
			fmt.Fprintf(os.Stderr, "AUTODPI_BINDIR=%s has no %s; the tests would run against another binary\n", d, name)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// ownBuild is the sing-box under test when it is AutoDPI's own build; other
// builds (the stock release binary) skip what only holds for ours.
func ownBuild(t *testing.T) (bin, version string) {
	t.Helper()
	bin = singBoxBin(t)
	out, err := exec.Command(bin, "version").Output()
	if err != nil || !strings.Contains(string(out), "Build: AutoDPI") {
		t.Skipf("not AutoDPI's own sing-box build (%v)", err)
	}
	first, _, _ := strings.Cut(string(out), "\n")
	return bin, strings.TrimSpace(strings.TrimPrefix(first, "sing-box version"))
}

// The binary is the version tools/singbox/go.mod pins, and says so. A build
// that does not carry its version ("unknown", from a plain go build) never
// turns sing-box's deprecations into errors, which is how they are noticed.
func TestTheBinaryIsThePinnedVersion(t *testing.T) {
	_, version := ownBuild(t)
	mod, err := os.ReadFile(filepath.Join("..", "..", "tools", "singbox", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	pinned := ""
	for _, line := range strings.Split(string(mod), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "github.com/sagernet/sing-box" {
			pinned = strings.TrimPrefix(f[1], "v")
		}
	}
	if pinned == "" || version != pinned {
		t.Fatalf("the binary says %q, tools/singbox/go.mod pins %q", version, pinned)
	}
}

// What is linked into the binary, by module. A sing-box release that pulls a
// protocol's library back in through some shared package registers nothing
// new, so nothing else notices; this list is how a person gets to look at it.
// After a deliberate change: go version -m bin/sing-box | awk '$1=="dep"{print $2}' | sort > tools/singbox/modules.txt
func TestTheBinaryLinksTheListedModules(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the list is the macOS build's")
	}
	bin, _ := ownBuild(t)
	out, err := exec.Command("go", "version", "-m", bin).Output()
	if err != nil {
		t.Skipf("go version -m: %v", err)
	}
	have := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "dep" {
			have[f[1]] = true
		}
	}
	listed, err := os.ReadFile(filepath.Join("..", "..", "tools", "singbox", "modules.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, m := range strings.Fields(string(listed)) {
		want[m] = true
		if !have[m] {
			t.Errorf("%s is listed but no longer linked", m)
		}
	}
	for m := range have {
		if !want[m] {
			t.Errorf("%s is linked into sing-box and not in tools/singbox/modules.txt", m)
		}
	}
}

// The contract with our own sing-box build: every configuration Contract
// names is accepted. This is what `autodpi selftest` runs on a user's machine.
func TestContractIsAccepted(t *testing.T) {
	bin := singBoxBin(t)
	dir := t.TempDir()
	cases, err := Contract(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 5 {
		t.Fatalf("only %d cases", len(cases))
	}
	for i, c := range cases {
		f := filepath.Join(dir, fmt.Sprintf("c%d.json", i))
		if err := os.WriteFile(f, c.Config, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := checkFile(bin, f); err != nil {
			t.Errorf("%s: %v\n%s", c.Name, err, out)
		}
	}
}

// Every combination of options Build takes, not only the named cases: a
// sing-box release that changes what one option needs is caught whichever
// option it is. A few hundred configurations, so not in -short runs.
func TestEveryOptionCombinationIsAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("several hundred sing-box runs")
	}
	bin := singBoxBin(t)
	dir := t.TempDir()
	all := []Engine{
		{Name: "tlsrec", Kind: TLSRecord, Port: 21081}, {Name: "ciadpi", Kind: Socks, Port: 21082},
		{Name: "tlsspoof", Kind: TLSSpoof, Port: 21083}, {Name: "tlsfrag", Kind: TLSSegment, Port: 21084},
		{Name: "warp", Kind: WireGuard, Port: 21085},
	}
	for _, e := range all {
		if err := WriteRuleSet(dir, e.Name, nil); err != nil {
			t.Fatal(err)
		}
	}
	wg := &WireGuardProfile{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Addresses: []string{"172.16.0.2/32"}, MTU: 1280, Endpoint: "engage.cloudflareclient.com", Port: 2408,
	}
	engineSets := map[string][]Engine{
		"default": all[:3], "all": all,
		"tlsrec": all[:1], "ciadpi": all[1:2], "tlsspoof": all[2:3], "tlsfrag": all[3:4], "warp": all[4:5],
	}
	resolvers := [][]string{{"1.1.1.1"}, {"1.1.1.1", "1.0.0.1"}, {"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}}
	bools := []bool{false, true}

	type job struct {
		name string
		o    Options
	}
	var jobs []job
	for setName, set := range engineSets {
		for _, tun := range bools {
			for _, v6 := range bools {
				for _, quic := range bools {
					for _, doh := range resolvers {
						for _, local := range []string{"", "192.168.1.1"} {
							for _, strict := range bools {
								// A dimension of its own. Alternating it with the
								// job number tied it to the innermost loop, and the
								// Windows default (strict route with ipv4_only) was
								// never among the combinations.
								for _, v4only := range bools {
									if !tun && (v6 || strict) {
										continue // TUN-only options
									}
									// The daemon sets these two independently: the name-only
									// strategy from the settings, the capture from the network.
									o := Options{Engines: set, ObserverPort: 21080, RuleDir: dir, WireGuard: wg,
										Tun: tun, IPv6: v6, IPv4Only: v4only, BlockQUIC: quic, DoH: doh, StrictRoute: strict}
									if !tun {
										o.TestPort = 21090
									}
									if local != "" {
										o.LocalDNS, o.LocalSuffixes = local, []string{"lan", "corp"}
									}
									jobs = append(jobs, job{fmt.Sprintf("%s tun=%v v6=%v quic=%v doh=%d local=%v strict=%v v4only=%v",
										setName, tun, v6, quic, len(doh), local != "", strict, v4only), o})
								}
							}
						}
					}
				}
			}
		}
	}
	if len(jobs) < 300 {
		t.Fatalf("only %d combinations", len(jobs))
	}
	work := make(chan int)
	var wgroup sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	// A few at a time: the other packages' tests run beside this one, and
	// some of them time their own work.
	for w := 0; w < min(4, runtime.NumCPU()); w++ {
		wgroup.Add(1)
		go func() {
			defer wgroup.Done()
			for i := range work {
				cfg, err := Build(jobs[i].o)
				msg := ""
				if err == nil {
					f := filepath.Join(dir, fmt.Sprintf("j%d.json", i))
					if err = os.WriteFile(f, cfg, 0o600); err == nil {
						msg, err = checkFile(bin, f)
					}
				}
				if err != nil {
					mu.Lock()
					if failed++; failed <= 5 {
						t.Errorf("%s: %v\n%s", jobs[i].name, err, msg)
					}
					mu.Unlock()
				}
			}
		}()
	}
	for i := range jobs {
		work <- i
	}
	close(work)
	wgroup.Wait()
	if failed > 0 {
		t.Fatalf("%d of %d combinations refused", failed, len(jobs))
	}
	t.Logf("%d combinations accepted", len(jobs))
}

// The other half of the contract: the build holds nothing but what AutoDPI
// uses. A protocol that is back in the binary brings its dependencies and
// their vulnerabilities with it, and nobody would notice.
func TestTheBuildHoldsNothingElse(t *testing.T) {
	bin, _ := ownBuild(t)
	dir := t.TempDir()
	base := func() map[string]any {
		return map[string]any{
			"inbounds":  []any{map[string]any{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 21090}},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		}
	}
	refused := func(name, wantErr string, cfg map[string]any) {
		t.Helper()
		b, _ := json.Marshal(cfg)
		f := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := checkFile(bin, f)
		if err == nil {
			t.Errorf("%s is in the build: its configuration was accepted", name)
		} else if !strings.Contains(out, wantErr) {
			t.Errorf("%s was refused, but not for being absent (%q wanted):\n%s", name, wantErr, out)
		}
	}
	if out, err := func() (string, error) {
		b, _ := json.Marshal(base())
		f := filepath.Join(dir, "base.json")
		_ = os.WriteFile(f, b, 0o600)
		return checkFile(bin, f)
	}(); err != nil {
		t.Fatalf("the base configuration itself is refused: %v\n%s", err, out)
	}
	for _, typ := range []string{"vmess", "vless", "trojan", "shadowsocks", "shadowtls", "ssh", "tor", "http", "anytls", "selector", "urltest", "block", "hysteria2", "tuic"} {
		c := base()
		c["outbounds"] = append(c["outbounds"].([]any), map[string]any{"type": typ, "tag": "x"})
		refused("outbound "+typ, "unknown outbound type", c)
	}
	for _, typ := range []string{"http", "vmess", "vless", "trojan", "shadowsocks", "naive", "redirect", "tproxy", "hysteria2"} {
		c := base()
		c["inbounds"] = append(c["inbounds"].([]any), map[string]any{"type": typ, "tag": "x"})
		refused("inbound "+typ, "unknown inbound type", c)
	}
	for _, typ := range []string{"tailscale", "openvpn", "openconnect"} {
		c := base()
		c["endpoints"] = []any{map[string]any{"type": typ, "tag": "x"}}
		refused("endpoint "+typ, "unknown endpoint type", c)
	}
	for _, typ := range []string{"quic", "h3", "dhcp", "fakeip", "tailscale", "mdns", "resolved"} {
		c := base()
		c["dns"] = map[string]any{"servers": []any{map[string]any{"type": typ, "tag": "x"}}}
		refused("DNS server "+typ, "unknown", c)
	}

	// 36 MB with everything registered, 18 MB without: well below the middle.
	if fi, err := os.Stat(bin); err != nil {
		t.Error(err)
	} else if fi.Size() > 26<<20 {
		t.Errorf("the sing-box binary is %d MB; the slim build is about 18 to 20", fi.Size()>>20)
	}
}
