package ipc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
)

func sock(t *testing.T) string {
	// unix socket paths are length-limited; t.TempDir() can be too long on
	// macOS. Windows has no /tmp: its temp folder is short enough.
	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = ""
	}
	d, err := os.MkdirTemp(base, "ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "s")
}

func TestRoundTrip(t *testing.T) {
	path := sock(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, path, func(_ context.Context, r Request) (any, error) {
		switch r.Cmd {
		case "echo":
			return map[string]string{"domain": r.Domain}, nil
		case "boom":
			panic("kaput")
		}
		return nil, errors.New("unknown " + r.Cmd)
	})
	for i := 0; i < 50 && func() bool { _, err := os.Stat(path); return err != nil }(); i++ {
		time.Sleep(20 * time.Millisecond)
	}

	var out map[string]string
	if err := Call(path, Request{Cmd: "echo", Domain: "discord.com"}, &out, time.Second); err != nil || out["domain"] != "discord.com" {
		t.Fatalf("echo: %v %v", err, out)
	}
	if err := Call(path, Request{Cmd: "nope"}, nil, time.Second); err == nil || err.Error() != "unknown nope" {
		t.Fatalf("error not propagated: %v", err)
	}
	if err := Call(path, Request{Cmd: "boom"}, nil, time.Second); err == nil {
		t.Fatal("panic must become an error, not kill the daemon")
	}
	// The daemon survived the panic.
	if err := Call(path, Request{Cmd: "echo"}, &out, time.Second); err != nil {
		t.Fatalf("daemon died after handler panic: %v", err)
	}
}

func TestSecondDaemonRefused(t *testing.T) {
	path := sock(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, path, func(context.Context, Request) (any, error) { return nil, nil })
	for i := 0; i < 50 && func() bool { _, err := os.Stat(path); return err != nil }(); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if err := Serve(context.Background(), path, nil); err == nil {
		t.Fatal("second Serve must refuse while the first is alive")
	}
}

func TestNoDaemon(t *testing.T) {
	if err := Call(sock(t), Request{Cmd: "status"}, nil, time.Second); err == nil {
		t.Fatal("expected error")
	}
}

// The daemon answers in the language the request names; a client that names
// none gets the daemon's own.
func TestRequestLanguage(t *testing.T) {
	if got := (Request{Lang: "tr"}).T("tr", "en"); got != "tr" {
		t.Errorf("tr: %q", got)
	}
	if got := (Request{Lang: "en"}).T("tr", "en"); got != "en" {
		t.Errorf("en: %q", got)
	}
	if got := (Request{}).T("tr", "en"); got != i18n.T("tr", "en") {
		t.Errorf("none: %q", got)
	}
}
