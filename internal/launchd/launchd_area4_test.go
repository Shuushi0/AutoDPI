//go:build !windows

package launchd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/paths"
)

func lint(t *testing.T, plist []byte) error {
	t.Helper()
	if _, err := os.Stat("/usr/bin/plutil"); err != nil {
		t.Skip("no plutil")
	}
	f := filepath.Join(t.TempDir(), "x.plist")
	if err := os.WriteFile(f, plist, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/usr/bin/plutil", "-lint", f).CombinedOutput()
	if err != nil {
		t.Logf("plutil: %s", strings.TrimSpace(string(out)))
	}
	return err
}

func TestArea4_RenderIsAValidPlistForTheRealPaths(t *testing.T) {
	for _, bin := range []string{
		paths.Default().Installed,
		"/Library/Application Support/AutoDPI/autodpi",
		"/tmp/with space/it's/autodpi",
		"/tmp/ünïcode/autodpi",
	} {
		b, err := Render(bin)
		if err != nil {
			t.Fatal(err)
		}
		if err := lint(t, b); err != nil {
			t.Errorf("Render(%q) is not a valid plist: %v", bin, err)
		}
		if !strings.Contains(string(b), "<string>"+bin+"</string>") {
			t.Errorf("binary path not present verbatim for %q", bin)
		}
	}
}

// BUG (low): Render uses text/template, so XML metacharacters in the binary path
// are written raw. With AUTODPI_HOME (a dev override that Install honours,
// p.Installed = $AUTODPI_HOME/autodpi) a path containing & or < produces
// a plist launchd refuses, and Install only finds out at `launchctl bootstrap`
// after it has already copied the binary and removed the old plist.
func TestArea4_RenderEscapesXMLInBinaryPath(t *testing.T) {
	for _, bin := range []string{"/tmp/a&b/autodpi", "/tmp/a<b>/autodpi", `/tmp/"q"/autodpi`} {
		b, err := Render(bin)
		if err != nil {
			t.Fatal(err)
		}
		if err := lint(t, b); err != nil {
			t.Errorf("Render(%q) yields an invalid plist: %v", bin, err)
		}
	}
}

func TestArea4_RenderContents(t *testing.T) {
	b, _ := Render("/x/autodpi")
	s := string(b)
	// KeepAlive+RunAtLoad+ThrottleInterval: crash loop must be throttled
	for _, want := range []string{"<key>ThrottleInterval</key>\n\t<integer>10</integer>", DaemonLog, CrashLog, "<string>--log-file</string>"} {
		if !strings.Contains(s, want) {
			t.Errorf("plist lacks %q", want)
		}
	}
	if strings.Count(s, "<string>/x/autodpi</string>") != 1 {
		t.Error("binary should appear exactly once (ProgramArguments[0])")
	}
	// ProgramArguments order matters: binary, daemon, --log-file, path
	i := strings.Index(s, "<string>/x/autodpi</string>")
	j := strings.Index(s, "<string>daemon</string>")
	k := strings.Index(s, "<string>--log-file</string>")
	if !(i < j && j < k) {
		t.Errorf("argument order wrong: %d %d %d", i, j, k)
	}
	if strings.Contains(s, "UserName") {
		t.Error("daemon must run as root (no UserName key)")
	}
}

// As a normal user Install/Uninstall must return ErrNotRoot before touching anything.
func TestArea4_InstallUninstallNonRootAreNoOps(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("must not run as root")
	}
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "state.json")
	os.WriteFile(sentinel, []byte("keep"), 0o600)
	os.MkdirAll(filepath.Join(dir, "bin"), 0o755)
	p := paths.Set{Support: dir, Bin: filepath.Join(dir, "bin"), Run: filepath.Join(dir, "run"), State: sentinel,
		Config: filepath.Join(dir, "config.json"), DNSSaved: filepath.Join(dir, "dns-saved.json"),
		Sock: filepath.Join(dir, "s"), Installed: filepath.Join(dir, "autodpi")}
	self, _ := os.Executable()
	if err := Install(p, self); err != ErrNotRoot {
		t.Errorf("Install: %v", err)
	}
	if err := Uninstall(p, true); err != ErrNotRoot {
		t.Errorf("Uninstall: %v", err)
	}
	if _, err := os.Stat(p.Installed); err == nil {
		t.Error("Install copied the binary without root")
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" {
		t.Errorf("Uninstall --purge as non-root removed data: %v", err)
	}
}

// Read-only query of the real job: Print must not panic or hang, and
// reports "" or launchctl's own text.
func TestArea4_PrintIsReadOnlyAndSane(t *testing.T) {
	out := Print()
	if out != "" && !strings.HasPrefix(out, "system/"+paths.Label) {
		t.Errorf("unexpected launchctl print output: %.80q", out)
	}
}

// Documented hazard (no root needed to see it): Uninstall's purge deletes
// p.Support wholesale, and Default() lets AUTODPI_HOME point p.Support at any
// directory, while the plist/symlink/label it also removes are the *system* ones.
// This only records the coupling; the destructive call is not made.
func TestArea4_PurgeTargetIsWhateverAUTODPIHOMEsays(t *testing.T) {
	t.Setenv("AUTODPI_HOME", "/tmp/anything-at-all")
	p := paths.Default()
	if p.Support != "/tmp/anything-at-all" || p.System {
		t.Fatalf("%+v", p)
	}
	if paths.Plist == "" || !strings.HasPrefix(paths.Plist, "/Library/LaunchDaemons/") {
		t.Fatal("system plist path changed")
	}
	t.Log("`sudo AUTODPI_HOME=X autodpi uninstall --purge` would RemoveAll(X) and also boot out/remove the SYSTEM job and plist")
}
