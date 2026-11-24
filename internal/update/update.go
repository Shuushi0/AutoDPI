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
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
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

// ErrVerify marks a download that arrived and is not what the release key
// signed: asking again gets the same bytes, unlike a connection that broke.
var ErrVerify = errors.New("the download does not match the release's signature")

// stallMax is how long a download may go without a single byte arriving. A
// slow line is waited for as long as it keeps delivering; a variable so that
// tests need not wait.
var stallMax = 60 * time.Second

// HTTPSOnly is a CheckRedirect that refuses to leave https: the release list
// and the files come from https addresses, and a redirect to plain http would
// hand the request to whoever sits on the line. (The archive would still fail
// its signature; the list and the notes have none.)
func HTTPSOnly(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refused a redirect from https to %s", req.URL.Scheme)
	}
	return nil
}

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
		rel := &Release{Version: v, URL: pageURL(r.URL, r.Tag), Notes: r.Body, Published: r.Published}
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

// pageURL is the release page the apps open in the browser: the one GitHub
// names when it is an https address on github.com, and otherwise the page of
// tag in Repo. The address goes to ShellExecute and window.open, which would
// run a file path or a script URL just as readily.
func pageURL(raw, tag string) string {
	if u, err := url.Parse(raw); err == nil && u.Scheme == "https" && u.Host == "github.com" && u.User == nil {
		return u.String()
	}
	return "https://github.com/" + Repo + "/releases/tag/" + tag
}

// Valid reports whether v is MAJOR.MINOR.PATCH with an optional -suffix: plain
// digits without leading zeros, and a suffix of letters, digits, dots and
// hyphens. One version has one spelling, and none holds a character that
// means something in a file name or a URL.
func Valid(v string) bool {
	_, _, ok := parse(v)
	return ok
}

func parse(v string) (nums [3]int, pre string, ok bool) {
	v, pre, dash := strings.Cut(v, "-")
	if dash && !validSuffix(pre) {
		return nums, "", false
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nums, "", false
	}
	for i, p := range parts {
		if p == "" || len(p) > 9 || (len(p) > 1 && p[0] == '0') || strings.Trim(p, "0123456789") != "" {
			return nums, "", false
		}
		nums[i], _ = strconv.Atoi(p)
	}
	return nums, pre, true
}

func validSuffix(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
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
	}
	return natural(pa, pb)
}

// natural orders two suffixes with their runs of digits read as numbers:
// rc9 before rc10, beta.2 before beta.11. As plain text "rc10" came before
// "rc9", and the tenth candidate would never have been offered to anyone on
// the ninth.
func natural(a, b string) int {
	for a != "" && b != "" {
		da, db := digits(a), digits(b)
		if da > 0 && db > 0 {
			na, nb := strings.TrimLeft(a[:da], "0"), strings.TrimLeft(b[:db], "0")
			if len(na) != len(nb) {
				if len(na) < len(nb) {
					return -1
				}
				return 1
			}
			if c := strings.Compare(na, nb); c != 0 {
				return c
			}
			a, b = a[da:], b[db:]
			continue
		}
		if a[0] != b[0] {
			if a[0] < b[0] {
				return -1
			}
			return 1
		}
		a, b = a[1:], b[1:]
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	}
	return 1
}

// digits is the length of the run of digits s starts with.
func digits(s string) int {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return n
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
		return Staged{}, fmt.Errorf("%w: %v", ErrVerify, err)
	}
	want, err := sumFor(sums, rel.Archive.Name)
	if err != nil {
		return Staged{}, fmt.Errorf("%w: %v", ErrVerify, err)
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
	// No limit on the whole download, only on standing still: a limit of ten
	// minutes could never be met on a slow line, and the same megabytes were
	// fetched again every hour.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stalled atomic.Bool
	stall := time.AfterFunc(stallMax, func() { stalled.Store(true); cancel() })
	defer stall.Stop()
	resp, err := open(ctx, c, url)
	if err != nil {
		if stalled.Load() {
			err = fmt.Errorf("%s: no answer for %s", path.Base(url), stallMax)
		}
		return err
	}
	defer resp.Body.Close()
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	h := sha256.New()
	body := progress{resp.Body, func() { stall.Reset(stallMax) }}
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, maxArchive+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		if stalled.Load() {
			err = fmt.Errorf("%s: the download stood still for %s", filepath.Base(dst), stallMax)
		}
		return err
	}
	if n > maxArchive {
		return fmt.Errorf("%w: %s is larger than %d bytes", ErrVerify, filepath.Base(dst), int64(maxArchive))
	}
	if got := h.Sum(nil); string(got) != string(want) {
		return fmt.Errorf("%w: the SHA-256 of %s is not the one in SHA256SUMS", ErrVerify, filepath.Base(dst))
	}
	return nil
}

// progress calls moved whenever bytes arrive.
type progress struct {
	io.Reader
	moved func()
}

func (p progress) Read(b []byte) (int, error) {
	n, err := p.Reader.Read(b)
	if n > 0 {
		p.moved()
	}
	return n, err
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
