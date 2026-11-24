package singbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// `sing-box check` is what the matrix, the contract and the self test on the
// user's machine all stand on. It must really create the box: were it to stop
// at decoding the file (one line less in tools/singbox/main.go), every one of
// them would go on passing while a missing part ("gVisor is not included"),
// an unreadable rule-set or a dangling tag went unnoticed. A configuration
// that decodes and cannot be created must be refused.
func TestCheckCreatesTheBox(t *testing.T) {
	bin, _ := ownBuild(t)
	dir := t.TempDir()
	cases, err := Contract(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, breakIt := range map[string]func(m map[string]any){
		"a rule-set file that is not there": func(m map[string]any) {
			sets := m["route"].(map[string]any)["rule_set"].([]any)
			sets[0].(map[string]any)["path"] = filepath.Join(dir, "missing.json")
		},
	} {
		var m map[string]any
		if err := json.Unmarshal(cases[0].Config, &m); err != nil {
			t.Fatal(err)
		}
		breakIt(m)
		b, _ := json.Marshal(m)
		f := filepath.Join(dir, "broken.json")
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err == nil {
			t.Errorf("sing-box check accepted %s: it no longer creates what it checks\n%s", name, out)
		}
	}
}

// A deprecated option is how sing-box announces what the next version will
// refuse, and checkFile turns any such word into a failure. That only works
// while the build still prints them (the deprecation manager in
// tools/singbox/main.go): one that is silent would let every warning through.
func TestDeprecationsAreReported(t *testing.T) {
	bin, _ := ownBuild(t)
	f := filepath.Join(t.TempDir(), "deprecated.json")
	// independent_cache is deprecated in sing-box 1.14. When a later version
	// removes it this test fails on the refusal, and wants another option
	// that the version still accepts and warns about.
	cfg := `{"dns":{"servers":[{"type":"https","tag":"doh","server":"1.1.1.1"}],"independent_cache":true,"final":"doh"},
"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":21099}],
"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","default_domain_resolver":"doh"}}`
	if err := os.WriteFile(f, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil {
		t.Fatalf("the sample with a deprecated option is refused outright; pick another deprecated option: %v\n%s", err, out)
	}
	if !bytes.Contains(bytes.ToLower(out), []byte("deprecated")) {
		t.Fatalf("sing-box accepted a deprecated option without a word: its warnings no longer reach the tests\n%q", out)
	}
}

// The binary is built from the module tools/singbox/go.mod names, itself and
// nothing in its place. The version it prints is a label the build script
// passes in; a `replace` line left in go.mod from a debugging session builds
// someone's local copy under that same label, and every other test is content.
func TestTheBinaryIsBuiltFromThePinnedModules(t *testing.T) {
	bin, _ := ownBuild(t)
	mod, err := os.ReadFile(filepath.Join("..", "..", "tools", "singbox", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	pinned := ""
	for _, line := range strings.Split(string(mod), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "replace" {
			t.Errorf("tools/singbox/go.mod has a replace line: %s", strings.TrimSpace(line))
		}
		if len(f) >= 2 && f[0] == "github.com/sagernet/sing-box" {
			pinned = f[1]
		}
	}
	out, err := exec.Command("go", "version", "-m", bin).Output()
	if err != nil {
		t.Fatalf("go version -m: %v", err)
	}
	linked := ""
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "=>" {
			t.Errorf("a module in the binary was replaced: %s", strings.TrimSpace(line))
		}
		if len(f) >= 3 && f[0] == "dep" && f[1] == "github.com/sagernet/sing-box" {
			linked = f[2]
		}
	}
	if pinned == "" || linked != pinned {
		t.Errorf("the binary links sing-box %q, tools/singbox/go.mod pins %q", linked, pinned)
	}
}

// The TUN's "mixed" stack needs gVisor in the build. `sing-box check` accepts
// a TUN configuration without it (only the WireGuard endpoint refuses), so a
// build that lost the tag would pass the contract for everyone who does not
// use WARP and fail when the capture starts.
func TestTheBuildHasGVisor(t *testing.T) {
	bin, _ := ownBuild(t)
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	tags := ""
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "Tags:"); ok {
			tags = strings.TrimSpace(v)
		}
	}
	if !strings.Contains(","+tags+",", ",with_gvisor,") {
		t.Fatalf("the build's tags are %q: with_gvisor is missing", tags)
	}
}

// The binary under test is the build this tree pins, bit for bit
// (tools/singbox/expected.sha256, which the build script checks as well).
func TestTheBinaryIsThePinnedBuild(t *testing.T) {
	bin, _ := ownBuild(t)
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("the pinned hashes are the release's: darwin/arm64 and windows/amd64")
	}
	if os.Getenv("SB_NOPIN") != "" {
		t.Skip("SB_NOPIN is set")
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprintf("%x", sha256.Sum256(b))
	pinned, err := os.ReadFile(filepath.Join("..", "..", "tools", "singbox", "expected.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(pinned), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == "darwin-arm64" {
			if f[0] != got {
				t.Fatalf("bin/sing-box is %s, tools/singbox/expected.sha256 pins %s", got, f[0])
			}
			return
		}
	}
	t.Fatal("tools/singbox/expected.sha256 has no line for darwin-arm64")
}
