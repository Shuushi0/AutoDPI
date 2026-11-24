package update

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/paths"
)

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.1.1", "0.1.0", 1}, {"0.1.0", "0.1.0", 0}, {"0.2.0", "0.10.0", -1},
		{"1.0.0", "0.99.99", 1}, {"0.1.1-rc1", "0.1.1", -1}, {"0.1.1-rc2", "0.1.1-rc1", 1},
		{"dev", "0.1.0", -1}, {"0.1", "0.0.1", -1}, {"01.0.0", "0.0.1", -1},
	} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// One version, one spelling: a second way to write 0.1.1 would compare equal
// to it while naming another archive. And nothing in a version may mean
// something in a file name or an address.
func TestValidRefusesOtherSpellings(t *testing.T) {
	for _, v := range []string{"0.1.1", "10.20.30", "0.1.1-rc1", "0.1.0-gsb3", "1.0.0-a.b-c"} {
		if !Valid(v) {
			t.Errorf("Valid(%q) = false", v)
		}
	}
	for _, v := range []string{"", "0.1", "0.1.1.1", "+0.1.1", "0.+1.1", "0.1.1-", "0.1.1- ", "0.1.1-a b", "0.1.1-../x", "0.1.1-a/b",
		`0.1.1-a\b`, "0.1.1-a\n", " 0.1.1", "0.1.1 ", "0.01.1", "0.1.-1", "0.1.1-é", "1234567890.0.0", "0.1.1-" + strings.Repeat("a", 65)} {
		if Valid(v) {
			t.Errorf("Valid(%q) = true", v)
		}
	}
}

// The page address goes to ShellExecute and window.open: only GitHub's own
// https address passes, anything else becomes the tag's page in Repo.
func TestPickKeepsOnlyAGitHubPage(t *testing.T) {
	const p = "autodpi-macos-arm64-"
	own := "https://github.com/" + Repo + "/releases/tag/v0.2.0"
	for raw, want := range map[string]string{
		"https://github.com/Shuushi0/AutoDPI/releases/tag/v0.2.0": "https://github.com/Shuushi0/AutoDPI/releases/tag/v0.2.0",
		"http://github.com/x":                 own,
		"https://github.com.evil.example/x":   own,
		"https://user@github.com/x":           own,
		"javascript:alert(1)":                 own,
		`C:\Windows\System32\calc.exe`:        own,
		`\\host\share\x.exe`:                  own,
		"file:///Applications/Calculator.app": own,
		"":                                    own,
	} {
		r := rel("v0.2.0", false, p+"0.2.0.zip", "SHA256SUMS", "SHA256SUMS.sig")
		r.URL = raw
		got := pick([]ghRelease{r}, "0.1.0", p)
		if got == nil || got.URL != want {
			t.Errorf("page %q -> %+v, want %q", raw, got, want)
		}
	}
}

func rel(tag string, draft bool, names ...string) ghRelease {
	r := ghRelease{Tag: tag, Draft: draft, URL: "https://example/" + tag}
	for _, n := range names {
		r.Assets = append(r.Assets, struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		}{n, "https://example/" + tag + "/" + n, 1})
	}
	return r
}

func TestPickTakesTheNewestCompleteRelease(t *testing.T) {
	const p = "autodpi-macos-arm64-"
	full := func(v string) []string { return []string{p + v + ".zip", "SHA256SUMS", "SHA256SUMS.sig"} }
	list := []ghRelease{
		rel("v0.3.0", true, full("0.3.0")...),                                                   // draft
		rel("v0.2.1", false, p+"0.2.1.zip", "SHA256SUMS"),                                       // unsigned
		rel("v0.2.0", false, full("0.2.0")...),                                                  // the one
		rel("v0.1.5", false, full("0.1.5")...),                                                  // older
		rel("v0.4.0", false, "autodpi-windows-amd64-0.4.0.zip", "SHA256SUMS", "SHA256SUMS.sig"), // other platform
	}
	got := pick(list, "0.1.0", p)
	if got == nil || got.Version != "0.2.0" || got.Archive.Name != p+"0.2.0.zip" {
		t.Fatalf("pick = %+v, want 0.2.0", got)
	}
	if got := pick(list, "0.2.0", p); got != nil {
		t.Fatalf("nothing is newer than 0.2.0, got %+v", got)
	}
	if got := pick(list, "0.1.0", ""); got != nil {
		t.Fatal("a platform without archives gets no release")
	}
}

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sums := []byte("abc  file.zip\n")
	sig := Sign(sums, priv)
	if err := Verify(sums, sig, pub); err != nil {
		t.Fatal(err)
	}
	if Verify([]byte("abd  file.zip\n"), sig, pub) == nil {
		t.Fatal("a changed SHA256SUMS verified")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if Verify(sums, sig, other) == nil {
		t.Fatal("another key verified")
	}
	if Verify(sums, []byte("not base64"), pub) == nil {
		t.Fatal("garbage verified")
	}
}

type zipFile struct {
	name string
	body string
	mode os.FileMode
}

func makeZip(t *testing.T, files ...zipFile) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate}
		h.SetMode(f.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(f.body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// serve publishes one release whose SHA256SUMS is signed with key.
func serve(t *testing.T, archive []byte, key ed25519.PrivateKey, tamper bool) (*httptest.Server, *Release) {
	const name = "autodpi-macos-arm64-0.2.0.zip"
	h := sha256.Sum256(archive)
	sums := []byte(hex.EncodeToString(h[:]) + "  " + name + "\n")
	sig := Sign(sums, key)
	if tamper {
		archive = append(append([]byte(nil), archive...), 0)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/a.zip", func(w http.ResponseWriter, _ *http.Request) { w.Write(archive) })
	mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) { w.Write(sums) })
	mux.HandleFunc("/sig", func(w http.ResponseWriter, _ *http.Request) { w.Write(sig) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &Release{Version: "0.2.0",
		Archive: Asset{Name: name, URL: srv.URL + "/a.zip"},
		Sums:    Asset{Name: "SHA256SUMS", URL: srv.URL + "/sums"},
		Sig:     Asset{Name: "SHA256SUMS.sig", URL: srv.URL + "/sig"}}
}

func withKey(t *testing.T) ed25519.PrivateKey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	old := PublicKey
	PublicKey = pub
	t.Cleanup(func() { PublicKey = old })
	return priv
}

func TestFetchVerifiesAndUnpacks(t *testing.T) {
	key := withKey(t)
	archive := makeZip(t,
		zipFile{"autodpi-macos-arm64-0.2.0/", "", os.ModeDir | 0o755},
		zipFile{"autodpi-macos-arm64-0.2.0/autodpi", "bin", 0o755},
		zipFile{"autodpi-macos-arm64-0.2.0/AutoDPI.app/Contents/Info.plist", "plist", 0o644})
	srv, r := serve(t, archive, key, false)
	st, err := Fetch(context.Background(), srv.Client(), r, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(st.Dir, "autodpi"))
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm()&0o100 == 0) {
		t.Fatalf("autodpi not unpacked as an executable: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(st.Dir, "AutoDPI.app", "Contents", "Info.plist")); string(b) != "plist" {
		t.Fatal("the app bundle was not unpacked")
	}
}

func TestFetchRefusesAChangedArchive(t *testing.T) {
	key := withKey(t)
	archive := makeZip(t, zipFile{"autodpi-macos-arm64-0.2.0/autodpi", "bin", 0o755})
	srv, r := serve(t, archive, key, true)
	if _, err := Fetch(context.Background(), srv.Client(), r, t.TempDir()); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("err = %v, want a hash mismatch", err)
	}
}

func TestFetchRefusesAnotherKey(t *testing.T) {
	withKey(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	archive := makeZip(t, zipFile{"autodpi-macos-arm64-0.2.0/autodpi", "bin", 0o755})
	srv, r := serve(t, archive, other, false)
	if _, err := Fetch(context.Background(), srv.Client(), r, t.TempDir()); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("err = %v, want a signature error", err)
	}
}

func TestUnzipStaysInItsFolder(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []zipFile{
		{"root/../evil", "x", 0o644},
		{"root/link", "target", os.ModeSymlink | 0o777},
	} {
		src := filepath.Join(dir, "a.zip")
		os.WriteFile(src, makeZip(t, f), 0o644)
		if err := unzip(src, filepath.Join(dir, "out"), "root"); err == nil {
			t.Errorf("%s was extracted", f.name)
		}
	}
}

func TestCheckReadsTheListAndHonoursETag(t *testing.T) {
	list := []ghRelease{rel("v9.0.0", false, Platform()+"9.0.0.zip", "SHA256SUMS", "SHA256SUMS.sig")}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"e1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"e1"`)
		json.NewEncoder(w).Encode(list)
	}))
	defer srv.Close()
	old := API
	API = srv.URL
	defer func() { API = old }()
	got, etag, err := Check(context.Background(), srv.Client(), "0.1.0", "")
	if Platform() == "" {
		if err != nil || got != nil {
			t.Fatalf("unsupported platform: %v %v", got, err)
		}
		return
	}
	if err != nil || got == nil || got.Version != "9.0.0" || etag != `"e1"` {
		t.Fatalf("Check = %+v %q %v", got, etag, err)
	}
	if _, _, err := Check(context.Background(), srv.Client(), "0.1.0", etag); err != ErrNotModified {
		t.Fatalf("err = %v, want ErrNotModified", err)
	}
}

// fakeInstall is an install root with an "installed" binary, and a staged
// release whose binary is a script that answers `version`.
func fakeInstall(t *testing.T, version string) (paths.Set, Staged) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake binary is a shell script")
	}
	root := t.TempDir()
	p := paths.Set{Support: root, Installed: filepath.Join(root, "autodpi")}
	os.WriteFile(p.Installed, []byte("old"), 0o755)
	old := AppPath
	AppPath = filepath.Join(root, "Applications", "AutoDPI.app")
	t.Cleanup(func() { AppPath = old })
	os.MkdirAll(filepath.Join(AppPath, "Contents"), 0o755)
	os.WriteFile(filepath.Join(AppPath, "Contents", "v"), []byte("old"), 0o644)

	stage := filepath.Join(root, "update", "stage")
	os.MkdirAll(filepath.Join(stage, "AutoDPI.app", "Contents"), 0o755)
	os.WriteFile(filepath.Join(stage, "autodpi"), []byte("#!/bin/sh\necho 'autodpi "+version+" (test)'\n"), 0o755)
	os.WriteFile(filepath.Join(stage, "AutoDPI.app", "Contents", "v"), []byte("new"), 0o644)
	return p, Staged{Version: "0.2.0", Dir: stage}
}

func read(t *testing.T, p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

func TestApplyCommit(t *testing.T) {
	p, st := fakeInstall(t, "0.2.0")
	var s State
	if err := Apply(p, st, "0.1.0", &s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, p.Installed), "0.2.0") || read(t, filepath.Join(AppPath, "Contents", "v")) != "new" {
		t.Fatal("the new files are not in place")
	}
	if s.Pending == nil || s.Pending.To != "0.2.0" {
		t.Fatalf("pending = %+v", s.Pending)
	}
	if a := Resume(p, "0.2.0", &s); a != Confirm {
		t.Fatalf("Resume = %v, want Confirm", a)
	}
	Commit(p, &s)
	if s.Last == nil || !s.Last.OK || s.Pending != nil {
		t.Fatalf("after commit: %+v", s)
	}
	if _, err := os.Stat(oldPath(p.Installed)); err == nil {
		t.Fatal("the old binary is still there after the commit")
	}
}

func TestApplyRefusesABinaryOfAnotherVersion(t *testing.T) {
	p, st := fakeInstall(t, "0.1.9")
	var s State
	if err := Apply(p, st, "0.1.0", &s); err == nil {
		t.Fatal("applied a binary that says it is 0.1.9")
	}
	if read(t, p.Installed) != "old" || s.Pending != nil {
		t.Fatal("a refused update changed something")
	}
}

func TestRepeatedStartsRollBack(t *testing.T) {
	p, st := fakeInstall(t, "0.2.0")
	var s State
	if err := Apply(p, st, "0.1.0", &s); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxStarts; i++ {
		if a := Resume(p, "0.2.0", &s); a != Confirm {
			t.Fatalf("start %d: %v", i+1, a)
		}
	}
	if a := Resume(p, "0.2.0", &s); a != RolledBack {
		t.Fatalf("start %d: %v, want RolledBack", MaxStarts+1, a)
	}
	if read(t, p.Installed) != "old" || read(t, filepath.Join(AppPath, "Contents", "v")) != "old" {
		t.Fatal("the old files are not back")
	}
	if s.Failed != "0.2.0" || s.Last == nil || s.Last.OK {
		t.Fatalf("state after rollback: %+v", s)
	}
	// The old version starts next: nothing pending, nothing to do.
	if a := Resume(p, "0.1.0", &s); a != Nothing {
		t.Fatalf("old version's start: %v", a)
	}
}

func TestStateRoundTrip(t *testing.T) {
	f := filepath.Join(t.TempDir(), "update.json")
	s := State{ETag: "x", Skipped: "0.2.0", Latest: &Release{Version: "0.2.0"}}
	if err := s.Save(f); err != nil {
		t.Fatal(err)
	}
	if got := LoadState(f); got.ETag != "x" || got.Skipped != "0.2.0" || got.Latest.Version != "0.2.0" {
		t.Fatalf("loaded %+v", got)
	}
}

// A new version that starts and names itself correctly, but whose own checks
// fail on this machine (its sing-box refuses the configuration, say), is not
// installed, and the caller can tell that trying again is pointless.
func TestApplyRefusesAVersionThatFailsItsSelfTest(t *testing.T) {
	p, st := fakeInstall(t, "0.2.0")
	os.WriteFile(filepath.Join(st.Dir, "autodpi"), []byte(`#!/bin/sh
case "$1" in
version) echo 'autodpi 0.2.0 (test)' ;;
selftest) echo 'ok  sing-box version 1.14.4'; echo 'error: sing-box refuses the configuration for the usual capture: unknown inbound type: tun' >&2; exit 3 ;;
esac
`), 0o755)
	var s State
	err := Apply(p, st, "0.1.0", &s)
	if !errors.Is(err, ErrSelfTest) || !strings.Contains(err.Error(), "unknown inbound type: tun") {
		t.Fatalf("err = %v, want the self test's reason", err)
	}
	if read(t, p.Installed) != "old" || s.Pending != nil {
		t.Fatal("a refused update changed something")
	}
	if _, err := os.Stat(oldPath(p.Installed)); !os.IsNotExist(err) {
		t.Fatal("a refused update left files behind")
	}
}

func TestApplyCallsAWrongVersionASelfTestFailure(t *testing.T) {
	p, st := fakeInstall(t, "0.1.9")
	if err := Apply(p, st, "0.1.0", &State{}); !errors.Is(err, ErrSelfTest) {
		t.Fatalf("err = %v", err)
	}
}

// A self test that could not be carried out is not a verdict on the release:
// only the exit code it reserves for one is. Otherwise a full disk or an
// antivirus scan would bar a good version for good.
func TestASelfTestThatCouldNotRunIsNoVerdict(t *testing.T) {
	p, st := fakeInstall(t, "0.2.0")
	os.WriteFile(filepath.Join(st.Dir, "autodpi"), []byte(`#!/bin/sh
case "$1" in
version) echo 'autodpi 0.2.0 (test)' ;;
selftest) echo 'error: extract sing-box: no space left on device' >&2; exit 1 ;;
esac
`), 0o755)
	var s State
	err := Apply(p, st, "0.1.0", &s)
	if err == nil || errors.Is(err, ErrSelfTest) || !strings.Contains(err.Error(), "no space left") {
		t.Fatalf("err = %v, want a plain error with the reason", err)
	}
	if read(t, p.Installed) != "old" || s.Pending != nil {
		t.Fatal("a failed check changed something")
	}
}

func TestProbeSaysWhenTheDownloadIsGone(t *testing.T) {
	p, st := fakeInstall(t, "0.2.0")
	os.RemoveAll(st.Dir)
	if err := Probe(context.Background(), p, st); !errors.Is(err, ErrGone) || errors.Is(err, ErrSelfTest) {
		t.Fatalf("err = %v", err)
	}
}

// Rollback runs inside the version it removes. On Windows that program can be
// renamed but neither deleted nor overwritten, so the new files are moved
// aside, never removed first; what was moved aside goes with the next cleanup.
func TestRollbackMovesTheNewFilesAsideAndPutsTheOldBack(t *testing.T) {
	p, st := fakeInstall(t, "0.2.0")
	var s State
	if err := Apply(p, st, "0.1.0", &s); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(p, &s, "did not work"); err != nil {
		t.Fatal(err)
	}
	if read(t, p.Installed) != "old" || read(t, filepath.Join(AppPath, "Contents", "v")) != "old" {
		t.Fatal("the old files are not back")
	}
	if s.Pending != nil || s.Failed != "0.2.0" || s.Last == nil || s.Last.OK || s.Last.Error != "did not work" {
		t.Fatalf("state: %+v last=%+v", s, s.Last)
	}
	for _, leftover := range []string{oldPath(p.Installed), failedPath(p.Installed), oldPath(AppPath), failedPath(AppPath)} {
		if _, err := os.Stat(leftover); !os.IsNotExist(err) {
			t.Errorf("%s is left behind", leftover)
		}
	}
	// What a running program on Windows leaves aside goes at the next start.
	os.WriteFile(failedPath(p.Installed), []byte("new"), 0o755)
	if a := Resume(p, "0.1.0", &s); a != Nothing {
		t.Fatalf("Resume = %v", a)
	}
	if _, err := os.Stat(failedPath(p.Installed)); !os.IsNotExist(err) {
		t.Fatal("the file a rollback moved aside survives the next start's cleanup")
	}
}

// With the previous program gone there is nothing to go back to. That is an
// error, and the state must not claim a rollback.
func TestRollbackWithoutThePreviousProgramChangesNothing(t *testing.T) {
	p, st := fakeInstall(t, "0.2.0")
	var s State
	if err := Apply(p, st, "0.1.0", &s); err != nil {
		t.Fatal(err)
	}
	os.Remove(oldPath(p.Installed))
	if err := Rollback(p, &s, "did not work"); err == nil {
		t.Fatal("rolled back to a program that is not there")
	}
	if s.Pending == nil || s.Failed != "" || !strings.Contains(read(t, p.Installed), "0.2.0") {
		t.Fatalf("state or files changed: pending=%+v failed=%q", s.Pending, s.Failed)
	}
	// The start that would roll back keeps the version running instead of
	// trying, and failing, at every start from then on.
	s.Pending.Starts = MaxStarts
	if a := Resume(p, "0.2.0", &s); a != Confirm || s.Pending == nil || s.Pending.Starts != MaxStarts {
		t.Fatalf("Resume = %v, pending = %+v", a, s.Pending)
	}
	if s.Last == nil || !strings.Contains(s.Last.Error, "could not go back") {
		t.Fatalf("the failed rollback is not recorded: %+v", s.Last)
	}
}

func TestStateKeepsInstallTries(t *testing.T) {
	f := filepath.Join(t.TempDir(), "update.json")
	s := State{Tries: &Tries{Version: "0.2.0", N: 2}}
	if err := s.Save(f); err != nil {
		t.Fatal(err)
	}
	if got := LoadState(f); got.Tries == nil || *got.Tries != *s.Tries {
		t.Fatalf("tries = %+v", got.Tries)
	}
}

// On Windows a tray app that never restarted after the last update still runs
// from the file kept aside then, which cannot be removed. A new update must
// not fail for that: what cannot be removed is renamed out of the way.
func TestSwapGetsPastALeftoverThatCannotBeRemoved(t *testing.T) {
	p, st := fakeInstall(t, "0.2.0")
	// A directory with something in it stands in for a file that will not go
	// away at the first try: os.Rename onto it fails as it does on a running
	// image, os.RemoveAll is what normally clears it. Make RemoveAll fail.
	stuck := oldPath(p.Installed)
	if err := os.MkdirAll(filepath.Join(stuck, "held"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stuck, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m, _ := filepath.Glob(stuck + "*")
		for _, f := range m {
			os.Chmod(f, 0o755)
		}
	})
	var s State
	if err := Apply(p, st, "0.1.0", &s); err != nil {
		t.Fatalf("the update failed over a leftover it could not remove: %v", err)
	}
	if !strings.Contains(read(t, p.Installed), "0.2.0") || read(t, oldPath(p.Installed)) != "old" {
		t.Fatal("the files are not swapped")
	}
	if m, _ := filepath.Glob(stuck + "-*"); len(m) != 1 {
		t.Fatalf("the leftover was not moved aside: %v", m)
	}
}
