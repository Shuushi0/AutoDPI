package embedded

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestEnsureWritesAndReplaces(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "tool")
	if err := ensure(dst, content("v1"), sum("v1")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dst)
	if err != nil || (checkPerm && fi.Mode().Perm() != 0o755) {
		t.Fatalf("stat: %v %v", fi, err)
	}
	// Same content: untouched.
	before := fi.ModTime()
	if err := ensure(dst, content("v1"), sum("v1")); err != nil {
		t.Fatal(err)
	}
	if fi2, _ := os.Stat(dst); !fi2.ModTime().Equal(before) {
		t.Fatal("identical content must not be rewritten")
	}
	// Tampered or outdated: replaced.
	_ = os.WriteFile(dst, []byte("evil"), 0o755)
	if err := ensure(dst, content("v1"), sum("v1")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "v1" {
		t.Fatalf("content = %q", b)
	}
	if !checkPerm {
		return // Windows: no mode bits to repair
	}
	// Loosened permissions are repaired.
	_ = os.Chmod(dst, 0o777)
	_ = ensure(dst, content("v1"), sum("v1"))
	if fi3, _ := os.Stat(dst); fi3.Mode().Perm() != 0o755 {
		t.Fatalf("perm = %v", fi3.Mode().Perm())
	}
}

func TestDevBins(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AUTODPI_BINDIR", dir)
	if _, err := devBins(); err == nil {
		t.Fatal("expected error when binaries are absent")
	}
	for _, n := range []string{SingBox, Ciadpi} {
		_ = os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o755)
	}
	b, err := devBins()
	if err != nil || filepath.Base(b.SingBox) != SingBox || filepath.Base(b.Ciadpi) != Ciadpi {
		t.Fatalf("%+v %v", b, err)
	}
}

func content(s string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
}

// openCounter records whether the payload was opened at all.
type openCounter struct{ n int }

func (c *openCounter) open(s string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { c.n++; return content(s)() }
}

// The point of build-time hashes: a file that is already right is recognised
// from the on-disk bytes alone, without ever opening the embedded payload.
func TestEnsureDoesNotTouchPayloadWhenCurrent(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "tool")
	var c openCounter
	if err := ensure(dst, c.open("v1"), sum("v1")); err != nil || c.n != 1 {
		t.Fatalf("first extract: err=%v opens=%d", err, c.n)
	}
	if err := ensure(dst, c.open("v1"), sum("v1")); err != nil || c.n != 1 {
		t.Fatalf("current file: err=%v opens=%d (payload must stay unopened)", err, c.n)
	}
	_ = os.WriteFile(dst, []byte("evil"), 0o755)
	if err := ensure(dst, c.open("v1"), sum("v1")); err != nil || c.n != 2 {
		t.Fatalf("tampered file: err=%v opens=%d", err, c.n)
	}
}

// A payload that differs from the constant recorded at build time is refused,
// and a file already on disk is left alone.
func TestEnsureRejectsPayloadMismatch(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "tool")
	_ = os.WriteFile(dst, []byte("old"), 0o755)
	err := ensure(dst, content("v2"), sum("something else"))
	if err == nil {
		t.Fatal("mismatching payload was installed")
	}
	if b, _ := os.ReadFile(dst); string(b) != "old" {
		t.Fatalf("dst replaced: %q", b)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("temporary file left behind: %v", ents)
	}
}

func TestEnsureOpenError(t *testing.T) {
	boom := errors.New("boom")
	err := ensure(filepath.Join(t.TempDir(), "tool"), func() (io.ReadCloser, error) { return nil, boom }, sum("x"))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}
