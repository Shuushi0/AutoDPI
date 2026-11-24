//go:build !windows

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/update"
)

// Tester: the new build's own observer is broken. DoH answers (the network
// is fine), the observer self-test through 127.0.0.1 fails: that is the
// build, not the network. The daemon stays in standby, the update is never
// confirmed, never rolled back, and a clean stop forgives the start, so
// MaxStarts is never reached either.
func TestABuildWhoseObserverIsBrokenIsNeverTakenBack(t *testing.T) {
	d, f := pendingRig(t)
	f.set(func(f *fakeSys) {
		f.healthErr = errors.New("observer self-test: socks 127.0.0.1:1080: connection refused")
	})
	for i := 0; i < 3; i++ {
		pass(t, d)
	}
	s, det := state(d)
	t.Logf("state %s (%s), proof %d", s, det, d.captureProof())
	// 10x confirmDoubt: at real speed that is over three hours
	confirm(t, d, 10*confirmDoubt)
	st := pendingState(d)
	if st.Pending != nil || st.Failed == "" || !d.restart.Load() {
		t.Errorf("the build that cannot engage is not taken back: pending=%+v failed=%q restart=%v", st.Pending, st.Failed, d.restart.Load())
	}
}

// Tester: the user presses "Install now" while a scheduled check holds the
// work lock (or the timer's download / the confirmation's look). The answer
// was already "installing"; nothing installs and the banner shows "busy".
func TestInstallNowWhileACheckRuns(t *testing.T) {
	d := installRig(t)
	stagedBinary(t, d, goodBinary)
	d.upd.work.Lock() // a check is running (up to 30 s on a slow network)
	if _, err := d.upd.request(context.Background(), ipc.Request{Cmd: "update", Action: "install"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	d.upd.work.Unlock()
	for i := 0; i < 100 && !d.restart.Load(); i++ { // the staged copy's own checks run first
		time.Sleep(100 * time.Millisecond)
	}
	st := d.upd.status()
	t.Logf("after Install now: phase=%q error=%q kind=%q restart=%v", st.Phase, st.Error, st.ErrorKind, d.restart.Load())
	if !d.restart.Load() {
		t.Errorf("the install the user asked for was dropped; the page shows error %q", st.Error)
	}
}

// Tester: a release whose archive does not match its signed SHA256SUMS (an
// asset re-uploaded after signing, or a CDN that serves a cut-short body with
// 200). Every hour the whole archive is downloaded again; nothing ever gives
// up on it, unlike an install (MaxTries).
func TestADownloadThatNeverVerifiesIsFetchedForever(t *testing.T) {
	d := installRig(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	old := update.PublicKey
	update.PublicKey = pub
	t.Cleanup(func() { update.PublicKey = old })
	archive := bytes.Repeat([]byte{1}, 20<<20) // ~ the real zip
	name := update.Platform() + "99.0.0.zip"
	sums := []byte(strings.Repeat("0", 64) + "  " + name + "\n") // does not match
	var served atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/a.zip", func(w http.ResponseWriter, _ *http.Request) { n, _ := w.Write(archive); served.Add(int64(n)) })
	mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) { w.Write(sums) })
	mux.HandleFunc("/sig", func(w http.ResponseWriter, _ *http.Request) { w.Write(update.Sign(sums, priv)) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	d.upd.http = srv.Client()
	d.upd.mu.Lock()
	d.upd.staged = nil
	d.upd.st.Latest = &update.Release{Version: "99.0.0",
		Archive: update.Asset{Name: name, URL: srv.URL + "/a.zip"},
		Sums:    update.Asset{Name: "SHA256SUMS", URL: srv.URL + "/sums"},
		Sig:     update.Asset{Name: "SHA256SUMS.sig", URL: srv.URL + "/sig"}}
	d.upd.mu.Unlock()
	for hour := 0; hour < 24; hour++ { // the user asks again and again
		if !wanted(d) {
			if hour != update.MaxTries {
				t.Fatalf("gave up after %d downloads, want %d", hour, update.MaxTries)
			}
			break
		}
		d.upd.fetch(context.Background(), false)
	}
	st := d.upd.status()
	t.Logf("after 24 hourly tries: %d MB downloaded, failed=%v tries=%+v error=%q", served.Load()>>20, st.Failed, d.upd.st.Tries, st.Error)
	if !st.Failed && wanted(d) {
		t.Errorf("a download that can never verify is fetched again every hour without end: %d MB a day", served.Load()>>20)
	}
}

// Tester: the new build deadlocks (d.mu held for good) with sing-box failing.
// launchd/SCM see a live process; the confirmation needs d.mu for its look, so
// it never decides, and nothing else can take the build back.
func TestAHungBuildIsNeverTakenBack(t *testing.T) {
	d, f := pendingRig(t)
	old := proofWait
	proofWait = 20 * time.Millisecond
	t.Cleanup(func() { proofWait = old })
	f.set(func(f *fakeSys) { f.tun = false })
	d.upd.mu.Lock()
	d.upd.broken = confirmWithin - confirmTick // one look from a rollback
	d.upd.mu.Unlock()
	d.mu.Lock() // the hang
	done := make(chan struct{})
	go func() { confirm(t, d, 2*time.Second); close(done) }()
	time.Sleep(time.Second) // 200 looks at test speed
	st := pendingState(d)
	d.mu.Unlock()
	<-done
	if st.Pending != nil && st.Failed == "" {
		t.Errorf("a hung build is neither rolled back nor restarted: the confirmation blocks on the daemon's lock")
	}
}

// Tester: an update installed while the clock was ahead (or a clock that was
// set back afterwards). pendingMax is measured on the wall clock from the
// saved time, so the "no longer holds a newer one back" rule never fires.
func TestAPendingUpdateFromAClockThatWasAhead(t *testing.T) {
	d, _ := pendingRig(t)
	stagedBinary(t, d, goodBinary)
	d.upd.mu.Lock()
	d.upd.st.Pending.At = time.Now().Add(30 * 24 * time.Hour)
	d.upd.mu.Unlock()
	if !wanted(d) {
		t.Errorf("a newer release is held back for a month by an unconfirmed update whose time is in the future (pending=%v)", d.upd.status().Pending)
	}
}
