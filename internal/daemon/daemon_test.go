package daemon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/paths"
)

func TestReleaseBacksOff(t *testing.T) {
	d := New(config.Default(), paths.Set{}, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	var waits []time.Duration
	for i := 0; i < 8; i++ {
		t0 := time.Now()
		d.release("test", StateStandby)
		waits = append(waits, d.retryAt.Sub(t0).Round(time.Second))
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 16 * time.Minute, 16 * time.Minute}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits %v, want %v", waits, want)
		}
	}
	if d.state != StateStandby {
		t.Fatalf("state %q", d.state)
	}
}

func TestSummarize(t *testing.T) {
	got := summarize(map[string]string{
		"tlsrec": "ok 101ms",
		"direct": "read tcp 10.0.0.2:5->1.2.3.4:443: read: connection reset by peer (63ms)",
		"ciadpi": "read tcp 127.0.0.1:1->127.0.0.1:2: i/o timeout (6004ms)",
	})
	want := "direct reset 63ms, ciadpi timeout 6004ms, tlsrec ok 101ms"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// A daemon that cannot serve its control socket shuts down at once; it must
// say so with an error (exit status) rather than return as if asked to stop.
// NoTun keeps the system resolver out of it; tlsrec alone spawns nothing.
func TestRunFailsWhenControlSocketFails(t *testing.T) {
	bin, _ := filepath.Abs("../../bin")
	if _, err := os.Stat(filepath.Join(bin, "sing-box")); err != nil {
		t.Skip("helper binaries not available")
	}
	t.Setenv("AUTODPI_BINDIR", bin)
	dir := t.TempDir()
	p := paths.Set{Support: dir, Run: filepath.Join(dir, "run"), State: filepath.Join(dir, "state.json"),
		DNSSaved: filepath.Join(dir, "dns-saved.json"),
		Sock:     filepath.Join(dir, strings.Repeat("s", 120)+".sock")} // over the 104-byte sun_path limit
	cfg := config.Default()
	cfg.Engines = []string{"tlsrec"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := New(cfg, p, "", slog.New(slog.NewTextHandler(io.Discard, nil))).Run(ctx, Options{NoTun: true})
	if ctx.Err() != nil {
		t.Fatal("Run kept going without a control socket")
	}
	if err == nil {
		t.Fatal("Run returned nil although the control socket could not be served")
	}
}

func TestHelperLogDropsChatterUnlessVerbose(t *testing.T) {
	var buf strings.Builder
	quietD := New(config.Default(), paths.Set{}, "", slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	quietD.helperLog().Info("recv: Connection reset by peer", "proc", "ciadpi")
	quietD.helperLog().Warn("exited", "proc", "ciadpi")
	if strings.Contains(buf.String(), "reset by peer") || !strings.Contains(buf.String(), "exited") {
		t.Fatalf("non-verbose helper log: %q", buf.String())
	}
	buf.Reset()
	loud := New(config.Default(), paths.Set{}, "", slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	loud.helperLog().Info("recv: Connection reset by peer", "proc", "ciadpi")
	if !strings.Contains(buf.String(), "reset by peer") {
		t.Fatalf("verbose helper log dropped output: %q", buf.String())
	}
}

// A full judged map keeps the sites that wait on a second look; it drops the
// expired and the strike-free ones first.
func TestPruneJudgedKeepsPendingStrikes(t *testing.T) {
	now := time.Now()
	m := map[string]*judgment{}
	for i := 0; i < maxJudged; i++ {
		m[fmt.Sprintf("old%d", i)] = &judgment{at: now.Add(-2 * strikeTTL)}
	}
	m["pending"] = &judgment{at: now.Add(-judgeEvery), strikes: 1}
	pruneJudged(m, now)
	if m["pending"] == nil || len(m) != 1 {
		t.Fatalf("kept %d entries, pending=%v", len(m), m["pending"] != nil)
	}

	m = map[string]*judgment{"pending": {at: now.Add(-judgeEvery), strikes: 1}}
	for i := 0; i < maxJudged; i++ {
		m[fmt.Sprintf("quiet%d", i)] = &judgment{at: now.Add(-judgeEvery)}
	}
	pruneJudged(m, now)
	if m["pending"] == nil || len(m) != 1 {
		t.Fatalf("strike-free entries should go first: kept %d", len(m))
	}
}
