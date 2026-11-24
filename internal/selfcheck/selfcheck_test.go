//go:build !windows

package selfcheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// devBin is the directory of the helper binaries the tests use, "" when they
// are not built.
func devBin(t *testing.T) string {
	t.Helper()
	dir, _ := filepath.Abs(filepath.Join("..", "..", "bin"))
	for _, n := range []string{"sing-box", "ciadpi"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Skip("helper binaries not available")
		}
	}
	return dir
}

func TestTheBuiltHelpersPass(t *testing.T) {
	t.Setenv("AUTODPI_BINDIR", devBin(t))
	var out bytes.Buffer
	dir := filepath.Join(t.TempDir(), "check")
	if err := Run(context.Background(), dir, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if n := strings.Count(out.String(), "ok  configuration: "); n < 5 {
		t.Fatalf("only %d configurations were checked:\n%s", n, out.String())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the work directory was left behind: %v", err)
	}
}

// fakeBins is a helper directory whose sing-box is the given shell script.
func fakeBins(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sing-box"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ciadpi"), []byte("#!/bin/sh\necho 17.3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// What this exists for: a sing-box built without something the daemon's
// configuration asks for. It starts and answers "version", and only refuses
// when it is given the configuration.
func TestASingBoxThatRefusesAConfigurationFails(t *testing.T) {
	t.Setenv("AUTODPI_BINDIR", fakeBins(t, `case "$1" in
version) echo "sing-box version 9.9.9" ;;
*) echo "FATAL[0000] decode config at $3: inbounds[0]: unknown inbound type: tun" >&2; exit 1 ;;
esac`))
	var out bytes.Buffer
	err := Run(context.Background(), filepath.Join(t.TempDir(), "check"), &out)
	if !errors.Is(err, ErrBroken) || !strings.Contains(err.Error(), "refuses the configuration") || !strings.Contains(err.Error(), "unknown inbound type: tun") {
		t.Fatalf("err = %v\n%s", err, out.String())
	}
}

func TestASingBoxThatDoesNotStartFails(t *testing.T) {
	t.Setenv("AUTODPI_BINDIR", fakeBins(t, `echo "dyld: Library not loaded" >&2; exit 126`))
	err := Run(context.Background(), filepath.Join(t.TempDir(), "check"), &bytes.Buffer{})
	if !errors.Is(err, ErrBroken) || !strings.Contains(err.Error(), "sing-box does not start") {
		t.Fatalf("err = %v", err)
	}
}

func TestMissingHelpersFail(t *testing.T) {
	t.Setenv("AUTODPI_BINDIR", t.TempDir())
	err := Run(context.Background(), filepath.Join(t.TempDir(), "check"), &bytes.Buffer{})
	if err == nil {
		t.Fatal("passed without any helper program")
	}
	if errors.Is(err, ErrBroken) {
		t.Fatalf("helpers that could not be put in place are called a verdict: %v", err)
	}
}

// A helper that gives no answer in time (antivirus scanning a program it has
// never seen) has not shown that it does not work.
func TestAHelperThatDoesNotAnswerInTimeIsNoVerdict(t *testing.T) {
	old := perCommand
	perCommand = 300 * time.Millisecond
	t.Cleanup(func() { perCommand = old })
	t.Setenv("AUTODPI_BINDIR", fakeBins(t, `exec sleep 30`))
	start := time.Now()
	err := Run(context.Background(), filepath.Join(t.TempDir(), "check"), &bytes.Buffer{})
	if err == nil || errors.Is(err, ErrBroken) || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("waited %v for a helper with a %v limit", time.Since(start), perCommand)
	}
}

// Nor has one that cannot be started at all (quarantined, not executable).
func TestAHelperThatCannotBeStartedIsNoVerdict(t *testing.T) {
	dir := fakeBins(t, `echo unused`)
	if err := os.Chmod(filepath.Join(dir, "sing-box"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTODPI_BINDIR", dir)
	err := Run(context.Background(), filepath.Join(t.TempDir(), "check"), &bytes.Buffer{})
	if err == nil || errors.Is(err, ErrBroken) {
		t.Fatalf("err = %v", err)
	}
}

func TestSweepRemovesOnlyOldLeftovers(t *testing.T) {
	base := t.TempDir()
	old, fresh, other := filepath.Join(base, Prefix+"111"), filepath.Join(base, Prefix+"222"), filepath.Join(base, "bin")
	for _, d := range []string{old, fresh, other} {
		if err := os.MkdirAll(filepath.Join(d, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	Sweep(base, 10*time.Minute)
	for dir, want := range map[string]bool{old: false, fresh: true, other: true} {
		if _, err := os.Stat(dir); (err == nil) != want {
			t.Errorf("%s: present=%v, want %v", filepath.Base(dir), err == nil, want)
		}
	}
	Sweep(base, 0)
	if _, err := os.Stat(fresh); err == nil {
		t.Error("Sweep(0) left a work directory")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("Sweep removed a directory that is not its own")
	}
}

// A sing-box whose check accepts everything (one that only decodes the file,
// or a stand-in that always says yes) used to pass the whole self test. The
// last step gives it a configuration that cannot work, and it has to refuse.
func TestASingBoxThatAcceptsEverythingFails(t *testing.T) {
	t.Setenv("AUTODPI_BINDIR", fakeBins(t, `case "$1" in
version) echo "sing-box version 9.9.9" ;;
*) exit 0 ;;
esac`))
	var out bytes.Buffer
	err := Run(context.Background(), filepath.Join(t.TempDir(), "check"), &out)
	if !errors.Is(err, ErrBroken) || !strings.Contains(err.Error(), "has to refuse") {
		t.Fatalf("err = %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "ok  configuration:") {
		t.Fatalf("the ordinary configurations were not checked first:\n%s", out.String())
	}
}
