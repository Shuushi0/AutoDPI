// Package embedded carries the helper binaries (sing-box, ciadpi) inside the
// autodpi executable and puts them where they can be executed.
package embedded

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Shuushi0/AutoDPI/internal/sysx"
)

// SingBox and Ciadpi are the helpers' file names: plain on macOS, with .exe
// on Windows (helpers_windows.go).
const (
	SingBox = "sing-box" + exeSuffix
	Ciadpi  = "ciadpi" + exeSuffix
)

// execPerm is checked and repaired on extracted helpers. Windows has no
// mode bits beyond read-only (the install directory's DACL protects them),
// so the check is skipped there.
const execPerm = 0o755

var checkPerm = runtime.GOOS != "windows"

// Bins are the executable paths the daemon runs.
type Bins struct {
	SingBox string
	Ciadpi  string
}

// payload is implemented by the build-tag specific files: with -tags embedbins
// it reads the go:embed data, otherwise it reports that nothing is embedded.
func payload(name string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return openPayload(name) }
}

// payloadHashes maps each embedded helper's file name to the SHA-256 of the
// bytes go:embed carries. scripts/build.sh and scripts/build-windows.sh write
// it into a generated Go file (payload_hashes_gen.go, see
// scripts/gen-payload-hashes.sh) from the very files they are about to embed,
// so the daemon never has to read the embedded copy (tens of MB of the
// executable, all of it paged into RSS) just to learn what it should be.
// Release builds without the generated file do not compile.

var errNotEmbedded = errors.New("helper binaries are not embedded in this build")

// Embedded reports whether this executable carries the helper binaries.
func Embedded() bool {
	f, err := openPayload(SingBox)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// UserDir is where a non-root run (lab, doctor) extracts the helpers when it
// cannot write the root-owned install directory.
func UserDir(dir string) string {
	if sysx.IsRoot() {
		return dir
	}
	if c, err := os.UserCacheDir(); err == nil {
		return filepath.Join(c, "AutoDPI", "bin")
	}
	return filepath.Join(os.TempDir(), "autodpi-bin")
}

// Paths names the helpers Prepare extracts into dir, without touching them
// (the daemon ends leftovers from a previous run before replacing files a
// running process would keep locked on Windows).
func Paths(dir string) Bins {
	return Bins{SingBox: filepath.Join(dir, SingBox), Ciadpi: filepath.Join(dir, Ciadpi)}
}

// Prepare returns runnable helper binaries. For a release build it extracts
// them into dir (only rewriting a file whose hash differs from the build-time
// constant); for a development build it points at AUTODPI_BINDIR or ./bin
// instead.
func Prepare(dir string) (Bins, error) {
	if !Embedded() {
		return devBins()
	}
	// Elevated on Windows, SecureDir creates the directory itself with the
	// right owner and DACL in one step; creating it first would leave it owned
	// by whatever default owner the token has.
	if runtime.GOOS != "windows" || !sysx.IsRoot() {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Bins{}, err
		}
	}
	if sysx.IsRoot() {
		// Windows: an elevated process executes these, and the application
		// directory comes first in the DLL search order, so nobody else may
		// write here. (No-op on macOS.)
		if err := sysx.SecureDir(dir); err != nil {
			return Bins{}, fmt.Errorf("lock down %s: %w", dir, err)
		}
	}
	var out Bins
	for _, name := range []string{SingBox, Ciadpi} {
		dst := filepath.Join(dir, name)
		want, ok := payloadHashes[name]
		if !ok {
			return Bins{}, fmt.Errorf("extract %s: no build-time hash recorded", name)
		}
		if err := ensure(dst, payload(name), want); err != nil {
			return Bins{}, fmt.Errorf("extract %s: %w", name, err)
		}
		if name == SingBox {
			out.SingBox = dst
		} else {
			out.Ciadpi = dst
		}
	}
	return out, nil
}

func devBins() (Bins, error) {
	dir := os.Getenv("AUTODPI_BINDIR")
	if dir == "" {
		dir = "bin"
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Bins{}, err
	}
	b := Bins{SingBox: filepath.Join(abs, SingBox), Ciadpi: filepath.Join(abs, Ciadpi)}
	for _, p := range []string{b.SingBox, b.Ciadpi} {
		if _, err := os.Stat(p); err != nil {
			return Bins{}, fmt.Errorf("%w; set AUTODPI_BINDIR (looked for %s)", errNotEmbedded, p)
		}
	}
	return b, nil
}

// hashOf streams r through SHA-256.
func hashOf(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fileHash hashes the file at path, streaming it from disk.
func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return hashOf(f)
}

// ensure makes dst a 0755 copy of what open yields, whose SHA-256 is want (a
// build-time constant). Only the file on disk is read to decide: the embedded
// payload is opened, and so paged in, just when dst has to be (re)written, and
// then it is hashed on the way out, so a payload that does not match want is
// never installed. Everything is streamed: the helpers are large.
func ensure(dst string, open func() (io.ReadCloser, error), want string) error {
	if have, err := fileHash(dst); err == nil && have == want {
		if fi, err := os.Stat(dst); !checkPerm || (err == nil && fi.Mode().Perm() == execPerm) {
			return nil
		}
		return os.Chmod(dst, execPerm)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".extract-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	src, err := open()
	if err != nil {
		tmp.Close()
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(tmp, h), src)
	src.Close()
	if err != nil {
		tmp.Close()
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		tmp.Close()
		return fmt.Errorf("embedded payload hash %s does not match the build-time hash %s", got, want)
	}
	if err := tmp.Chmod(execPerm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if sysx.IsRoot() {
		if err := sysx.OwnByRoot(tmp.Name()); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), dst)
}
