//go:build !windows

package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/store"
)

func TestMaintClearLogs(t *testing.T) {
	dir := t.TempDir()
	log, old := filepath.Join(dir, "d.log"), filepath.Join(dir, "d.log.1")
	for _, f := range []string{log, old} {
		if err := os.WriteFile(f, []byte("0123456789"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := rig(t, Options{LogFiles: []string{log, old, filepath.Join(dir, "missing")}})
	d.note("x", "y", "")
	m, err := call(t, d, ipc.Request{Cmd: "maint", Action: "clear-logs"})
	if err != nil {
		t.Fatal(err)
	}
	if m["freed_bytes"] != float64(20) {
		t.Fatalf("freed = %v", m["freed_bytes"])
	}
	for _, f := range []string{log, old} {
		if fi, _ := os.Stat(f); fi == nil || fi.Size() != 0 {
			t.Fatalf("%s not emptied", f)
		}
	}
	if len(d.journal) != 0 {
		t.Fatal("journal kept")
	}
}

func TestMaintResetListKeepsManual(t *testing.T) {
	d, f := rig(t, Options{})
	key := f.net.Key
	if key == "" {
		t.Skip("rig has no network key")
	}
	d.st.Touch(key, "")
	d.st.Add(key, store.Entry{Domain: "auto.example.net", Source: store.SourceAuto})
	d.st.Add(key, store.Entry{Domain: "mine.example.net", Source: store.SourceManual})
	m, err := call(t, d, ipc.Request{Cmd: "maint", Action: "reset-list"})
	if err != nil {
		t.Fatal(err)
	}
	if m["removed"] != float64(1) {
		t.Fatalf("removed = %v", m["removed"])
	}
	if l := d.st.List(key); len(l) != 1 || l[0].Domain != "mine.example.net" {
		t.Fatalf("list = %v", l)
	}
}

func TestMaintRefusals(t *testing.T) {
	d, _ := rig(t, Options{})
	if _, err := call(t, d, ipc.Request{Cmd: "maint", Action: "nope"}); err == nil {
		t.Fatal("unknown action accepted")
	}
	if _, err := call(t, d, ipc.Request{Cmd: "maint", Action: "restart"}); err == nil {
		t.Fatal("restart with no service manager to start it again accepted")
	}
}

// shutdown must end Run with a clean exit (launchd leaves it down); restart
// must not (launchd starts it again).
func TestMaintShutdownAndRestart(t *testing.T) {
	for _, tc := range []struct {
		action  string
		restart bool
	}{{"shutdown", false}, {"restart", true}} {
		d, _ := rig(t, Options{Supervised: true})
		stopped := make(chan struct{})
		d.stop = func() { close(stopped) }
		if _, err := call(t, d, ipc.Request{Cmd: "maint", Action: tc.action}); err != nil {
			t.Fatalf("%s: %v", tc.action, err)
		}
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: Run not stopped", tc.action)
		}
		if d.restart.Load() != tc.restart {
			t.Fatalf("%s: restart = %v", tc.action, d.restart.Load())
		}
	}
}
