// Package update finds a newer release on GitHub, downloads and verifies it,
// and swaps it in. The daemon drives it (it runs as root or SYSTEM, so no
// prompt is needed); the apps only show what it reports.
//
// Trust: a release carries SHA256SUMS and SHA256SUMS.sig, an ed25519
// signature of SHA256SUMS made with the release key (PublicKey). An archive
// is used only when the signature verifies and its hash is in SHA256SUMS, so
// whoever controls the GitHub account cannot push code without the key.
package update

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is where releases are published.
const Repo = "Shuushi0/AutoDPI"

// API is the release list; tests point it at a local server.
var API = "https://api.github.com/repos/" + Repo + "/releases?per_page=20"

const (
	sumsName = "SHA256SUMS"
	sigName  = "SHA256SUMS.sig"

	maxList    = 4 << 20   // the release list
	maxSums    = 64 << 10  // SHA256SUMS
	maxSig     = 4 << 10   // its signature
	maxArchive = 300 << 20 // one archive
)

// ErrNotModified is Check's answer when the list has not changed since etag.
var ErrNotModified = errors.New("release list not modified")

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Size int64  `json:"size"`
}

// Release is a newer version that has everything an update needs.
type Release struct {
	Version   string    `json:"version"` // "0.1.1", no leading v
	URL       string    `json:"url"`     // the release page
	Notes     string    `json:"notes,omitempty"`
	Published time.Time `json:"published"`
	Archive   Asset     `json:"archive"`
	Sums      Asset     `json:"sums"`
	Sig       Asset     `json:"sig"`
}

// Platform is the archive name prefix for this OS and architecture, "" where
// no archive is published.
func Platform() string { return platform(runtime.GOOS, runtime.GOARCH) }

func platform(goos, arch string) string {
	switch goos + "/" + arch {
	case "darwin/arm64":
		return "autodpi-macos-arm64-"
	case "windows/amd64":
		return "autodpi-windows-amd64-"
	}
	return ""
}

type ghRelease struct {
	Tag       string    `json:"tag_name"`
	Draft     bool      `json:"draft"`
	Body      string    `json:"body"`
	URL       string    `json:"html_url"`
	Published time.Time `json:"published_at"`
	Assets    []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// Check returns the newest release above current that has an archive for this
// platform, SHA256SUMS and its signature; nil when there is none. Pre-releases
// count: every release so far is one. etag is the previous answer's ETag;
// the new one is returned.
func Check(ctx context.Context, c *http.Client, current, etag string) (*Release, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", API, nil)
	if err != nil {
		return nil, etag, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "AutoDPI/"+current)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, etag, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, ErrNotModified
	}
	if resp.StatusCode != http.StatusOK {
		return nil, etag, fmt.Errorf("GitHub: %s", resp.Status)
	}
	var list []ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxList)).Decode(&list); err != nil {
		return nil, etag, fmt.Errorf("GitHub: %w", err)
	}
	return pick(list, current, Platform()), resp.Header.Get("ETag"), nil
}

func pick(list []ghRelease, current, prefix string) *Release {
	if prefix == "" {
		return nil
	}
	var best *Release
	for _, r := range list {
		v := strings.TrimPrefix(r.Tag, "v")
		if r.Draft || !Valid(v) || Compare(v, current) <= 0 || (best != nil && Compare(v, best.Version) <= 0) {
			continue
		}
		rel := &Release{Version: v, URL: r.URL, Notes: r.Body, Published: r.Published}
		for _, a := range r.Assets {
			as := Asset{Name: a.Name, URL: a.URL, Size: a.Size}
			switch a.Name {
			case prefix + v + ".zip":
				rel.Archive = as
			case sumsName:
				rel.Sums = as
			case sigName:
				rel.Sig = as
			}
		}
		if rel.Archive.URL != "" && rel.Sums.URL != "" && rel.Sig.URL != "" {
			best = rel
		}
	}
	return best
}

// Valid reports whether v is MAJOR.MINOR.PATCH with an optional -suffix.
func Valid(v string) bool {
	_, _, ok := parse(v)
	return ok
}

func parse(v string) (nums [3]int, pre string, ok bool) {
	v, pre, _ = strings.Cut(v, "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nums, "", false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || (len(p) > 1 && p[0] == '0') {
			return nums, "", false
		}
		nums[i] = n
	}
	return nums, pre, true
}

// Compare orders two versions: -1, 0 or 1. A version with a -suffix comes
// before the same version without one; two suffixes compare as text. An
// invalid version comes before every valid one.
func Compare(a, b string) int {
	na, pa, oka := parse(a)
	nb, pb, okb := parse(b)
	switch {
	case !oka && !okb:
		return 0
	case !oka:
		return -1
	case !okb:
		return 1
	}
	for i := range na {
		if na[i] != nb[i] {
			if na[i] < nb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	case pa < pb:
		return -1
	}
	return 1
}

// Staged is a verified release unpacked in Dir: the autodpi binary at its
// root, beside the other files of the archive (AutoDPI.app, autodpi-tray.exe).
type Staged struct {
	Version string `json:"version"`
	Dir     string `json:"dir"`
}

// Fetch downloads rel into dir (emptied first), verifies it and unpacks it.
func Fetch(ctx context.Context, c *http.Client, rel *Release, dir string) (Staged, error) {
	if err := os.RemoveAll(dir); err != nil {
		return Staged{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Staged{}, err
	}
	sums, err := get(ctx, c, rel.Sums.URL, maxSums)
	if err != nil {
		return Staged{}, err
	}
	sig, err := get(ctx, c, rel.Sig.URL, maxSig)
	if err != nil {
		return Staged{}, err
	}
	if err := Verify(sums, sig, PublicKey); err != nil {
		return Staged{}, err
	}
	want, err := sumFor(sums, rel.Archive.Name)
	if err != nil {
		return Staged{}, err
	}
	zipPath := filepath.Join(dir, rel.Archive.Name)
	if err := download(ctx, c, rel.Archive.URL, zipPath, want); err != nil {
		return Staged{}, err
	}
	stage := filepath.Join(dir, "stage")
	if err := unzip(zipPath, stage, strings.TrimSuffix(rel.Archive.Name, ".zip")); err != nil {
		return Staged{}, err
	}
	_ = os.Remove(zipPath)
	return Staged{Version: rel.Version, Dir: stage}, nil
}

func get(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	resp, err := open(ctx, c, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", path.Base(url), limit)
	}
	return b, nil
}

func open(ctx context.Context, c *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AutoDPI")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", path.Base(url), resp.Status)
	}
	return resp, nil
}

// Verify checks sig (the base64 text of an ed25519 signature) over sums.
func Verify(sums, sig []byte, pub ed25519.PublicKey) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("SHA256SUMS.sig is not a signature")
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, sums, raw) {
		return errors.New("SHA256SUMS signature does not verify")
	}
	return nil
}

// Sign is Verify's counterpart, for the release script.
func Sign(sums []byte, key ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, sums)) + "\n")
}

// sumFor finds name's hash in a `shasum -a 256` listing.
func sumFor(sums []byte, name string) ([]byte, error) {
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			h, err := hex.DecodeString(f[0])
			if err == nil && len(h) == sha256.Size {
				return h, nil
			}
		}
	}
	return nil, fmt.Errorf("%s is not in SHA256SUMS", name)
}

func download(ctx context.Context, c *http.Client, url, dst string, want []byte) error {
	resp, err := open(ctx, c, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArchive+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxArchive {
		return fmt.Errorf("%s: larger than %d bytes", filepath.Base(dst), int64(maxArchive))
	}
	if got := h.Sum(nil); string(got) != string(want) {
		return fmt.Errorf("%s: SHA-256 does not match SHA256SUMS", filepath.Base(dst))
	}
	return nil
}

// unzip extracts the archive's top folder root into dst: regular files and
// directories only, nothing that would land outside dst.
func unzip(src, dst, root string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	found := false
	for _, f := range zr.File {
		rel, ok := strings.CutPrefix(f.Name, root+"/")
		if !ok || rel == "" {
			continue
		}
		clean := path.Clean(rel)
		if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, `\`) {
			return fmt.Errorf("archive entry %q leaves its folder", f.Name)
		}
		out := filepath.Join(dst, filepath.FromSlash(clean))
		mode := f.Mode()
		switch {
		case mode.IsDir():
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
			continue
		case !mode.IsRegular():
			return fmt.Errorf("archive entry %q is not a regular file", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		perm := os.FileMode(0o644)
		if mode&0o111 != 0 {
			perm = 0o755
		}
		if err := extract(f, out, perm); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return fmt.Errorf("archive has no %s folder", root)
	}
	return nil
}

func extract(f *zip.File, out string, perm os.FileMode) error {
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	w, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, io.LimitReader(r, maxArchive)); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}
