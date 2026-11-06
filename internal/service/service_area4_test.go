//go:build !windows

package service

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/paths"
)

// BUG (low, wrong output): Describe keeps overwriting `state` for every line
// that starts with "state =" in `launchctl print`, so the nested
// "resource coalition"/"jetsam coalition" blocks (state = active) win over the
// job's own top-level "state = running". `autodpi doctor` then shows
// "launchd görevi  state = active" for a running daemon.
// Read-only: only runs `launchctl print system/<label>`; skipped if not installed.
func TestArea4_DescribeReportsTheJobsOwnState(t *testing.T) {
	out, err := exec.Command("/bin/launchctl", "print", "system/"+paths.Label).CombinedOutput()
	if err != nil {
		t.Skip("service not installed; nothing to compare with")
	}
	var want string
	for _, ln := range strings.Split(string(out), "\n") {
		// the job's own state line is indented by exactly one tab
		if v, ok := strings.CutPrefix(ln, "\tstate ="); ok {
			want = strings.TrimSpace(v)
			break
		}
	}
	if want == "" {
		t.Skip("no top-level state line in launchctl output")
	}
	if got := Describe(); got != stateText(want) {
		t.Errorf("Describe() = %q, launchctl says %q", got, want)
	}
}

func TestArea4_Constants(t *testing.T) {
	if !strings.Contains(InstallHint(), "sudo") || Kind() == "" {
		t.Error("hint/kind empty")
	}
	if LogPath(paths.Set{}) != "/var/log/autodpi.log" {
		t.Errorf("log path %q", LogPath(paths.Set{}))
	}
}

func TestJobStateIsTheTopLevelOne(t *testing.T) {
	out := "system/com.autodpi.daemon = {\n\tactive count = 1\n\tstate = running\n\n\tresource coalition = {\n\t\tID = 1\n\t\tstate = active\n\t}\n\tjetsam coalition = {\n\t\tstate = active\n\t}\n}"
	if got := jobState(out); got != "running" {
		t.Errorf("jobState = %q", got)
	}
	if got := jobState("system/x = {\n\t\tstate = active\n}"); got != "" {
		t.Errorf("nested-only output gave %q", got)
	}
	if got := stateText("running"); got != "durum = çalışıyor" {
		t.Errorf("stateText = %q", got)
	}
}

// Only the installed launchd job may restart itself: Terminal passes
// XPC_SERVICE_NAME=0 to whatever it starts, a plain shell nothing at all, and
// a daemon started by hand that exits for a restart stays down.
func TestSupervisedOnlyAsTheJob(t *testing.T) {
	for v, want := range map[string]bool{"": false, "0": false, "application.com.apple.Terminal.1": false, paths.Label: true} {
		t.Setenv("XPC_SERVICE_NAME", v)
		if got := Supervised(); got != want {
			t.Errorf("XPC_SERVICE_NAME=%q: Supervised() = %v", v, got)
		}
	}
}
