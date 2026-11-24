//go:build !windows

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/update"
)

// pendingRig is a daemon that has just been updated from 0.0.9 and has yet to
// confirm itself: the new program is in place ("new"), the previous one is
// kept beside it ("old"). The confirmation runs at test speed.
func pendingRig(t *testing.T) (*Daemon, *fakeSys) {
	t.Helper()
	a, w, dd, tk, fb := confirmAfter, confirmWithin, confirmDoubt, confirmTick, forgiveBelow
	confirmAfter, confirmWithin, confirmDoubt, confirmTick, forgiveBelow =
		40*time.Millisecond, 80*time.Millisecond, 240*time.Millisecond, 5*time.Millisecond, 40*time.Millisecond
	app := update.AppPath
	update.AppPath = filepath.Join(t.TempDir(), "AutoDPI.app")
	t.Cleanup(func() {
		confirmAfter, confirmWithin, confirmDoubt, confirmTick, forgiveBelow = a, w, dd, tk, fb
		update.AppPath = app
	})

	d, f := rig(t, Options{Supervised: true})
	d.stop = func() {}
	d.p.Installed = filepath.Join(d.p.Support, "autodpi")
	mustWrite(t, d.p.Installed, "new")
	mustWrite(t, previous(d), "old")
	d.upd = newUpdater(d)
	d.upd.st.Pending = &update.Pending{From: "0.0.9", To: Version, At: time.Now(), Starts: 1}
	d.upd.save()
	return d, f
}

// previous is where an update keeps the program it replaced.
func previous(d *Daemon) string { return filepath.Join(d.p.Support, ".autodpi.old") }

func mustWrite(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o755); err != nil {
		t.Fatal(err)
	}
}

func fileText(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

// confirm runs the confirmation until it has decided, or for wait.
func confirm(t *testing.T, d *Daemon, wait time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	d.upd.confirmLoop(ctx)
}

func pendingState(d *Daemon) update.State {
	d.upd.mu.Lock()
	defer d.upd.mu.Unlock()
	return d.upd.st
}

func wantProof(t *testing.T, d *Daemon, want proof) {
	t.Helper()
	if got := d.captureProof(); got != want {
		s, det := state(d)
		t.Fatalf("proof %d in state %s (%s), want %d", got, s, det, want)
	}
}

// The case this is for: the new version's sing-box cannot start. The daemon is
// alive and, between attempts, only waiting, with the internet working. That
// used to confirm the update after half a minute; it must go back to the old
// one, and the old program must really be back.
func TestUpdateWithACaptureThatNeverComesUpIsRolledBack(t *testing.T) {
	d, f := pendingRig(t)
	f.set(func(f *fakeSys) { f.tun = false })
	pass(t, d)
	wantState(t, d, StateStarting)
	d.sbStarted = time.Now().Add(-31 * time.Second)
	pass(t, d)
	wantState(t, d, StateError, "retry in")
	wantProof(t, d, proofBroken)
	pass(t, d)
	wantState(t, d, StateError, "next attempt in")
	wantProof(t, d, proofBroken)

	confirm(t, d, 3*time.Second)
	st := pendingState(d)
	if st.Pending != nil || st.Failed != Version || st.Last == nil || st.Last.OK || !strings.Contains(st.Last.Error, "capture") {
		t.Fatalf("not rolled back: pending=%+v failed=%q last=%+v", st.Pending, st.Failed, st.Last)
	}
	if got := fileText(d.p.Installed); got != "old" {
		t.Fatalf("the installed program is %q after the rollback, want the previous one", got)
	}
	if !d.restart.Load() {
		t.Fatal("no restart into the old version")
	}
	// The verdict outlives the restart: this version is not installed again.
	if again := newUpdater(d); again.st.Failed != Version {
		t.Fatalf("the failed version was forgotten: %+v", again.st)
	}
}

// When the previous program cannot be put back, the update is not called
// rolled back: this version runs on, and saying otherwise would send the user
// looking for a problem in the wrong version.
func TestARollbackThatCannotHappenIsNotReported(t *testing.T) {
	d, f := pendingRig(t)
	if err := os.Remove(previous(d)); err != nil {
		t.Fatal(err)
	}
	f.set(func(f *fakeSys) { f.tun = false })
	pass(t, d)
	d.sbStarted = time.Now().Add(-31 * time.Second)
	pass(t, d)
	confirm(t, d, 3*time.Second)
	st := pendingState(d)
	if st.Pending == nil || st.Failed != "" || d.restart.Load() {
		t.Fatalf("reported a rollback that did not happen: pending=%+v failed=%q restart=%v", st.Pending, st.Failed, d.restart.Load())
	}
	if got := fileText(d.p.Installed); got != "new" {
		t.Fatalf("installed program is %q", got)
	}
}

func TestUpdateIsConfirmedOnceTheCaptureHasWorkedForAWhile(t *testing.T) {
	d, f := pendingRig(t)
	wantProof(t, d, proofDoubtful) // "starting", before anything ran
	engage(t, d, f)
	wantState(t, d, StateActive)
	wantProof(t, d, proofWorking)

	// Not at first sight: a build that falls over under its first traffic
	// must still have something to go back to.
	confirm(t, d, confirmAfter/3)
	if st := pendingState(d); st.Pending == nil {
		t.Fatal("confirmed before the capture had worked for confirmAfter")
	}
	if fileText(previous(d)) != "old" {
		t.Fatal("the previous program was removed before the update was confirmed")
	}

	// A download that was fetched meanwhile lives in the folder Commit removes.
	d.upd.mu.Lock()
	d.upd.staged, d.upd.phase = &update.Staged{Version: "99.0.0", Dir: filepath.Join(d.p.Support, "update", "stage")}, phaseReady
	d.upd.mu.Unlock()

	confirm(t, d, 3*time.Second)
	st := pendingState(d)
	if st.Pending != nil || st.Failed != "" || st.Last == nil || !st.Last.OK {
		t.Fatalf("not confirmed: %+v last=%+v", st, st.Last)
	}
	if d.restart.Load() {
		t.Fatal("a confirmed update restarted the daemon")
	}
	if _, err := os.Stat(previous(d)); !os.IsNotExist(err) {
		t.Fatal("the previous program is still there after the confirmation")
	}
	d.upd.mu.Lock()
	staged, phase := d.upd.staged, d.upd.phase
	d.upd.mu.Unlock()
	if staged != nil || phase != "" {
		t.Fatalf("still points at a download whose folder is gone: staged=%+v phase=%q", staged, phase)
	}
}

// Paused, offline, another tunnel, another DPI tool, a failing plumbing check,
// or the network going away while sing-box is still being verified: none of
// them says anything about the new version. It is neither confirmed nor rolled
// back, however long that lasts, and a clean stop in that time is not a failed
// start.
func TestUpdateWaitsWhileNothingCanBeSaid(t *testing.T) {
	for name, block := range map[string]func(t *testing.T, d *Daemon, f *fakeSys){
		"paused":   func(t *testing.T, d *Daemon, f *fakeSys) { _ = d.st.SetPaused(true) },
		"offline":  func(t *testing.T, d *Daemon, f *fakeSys) { f.set(func(f *fakeSys) { f.net.Online = false }) },
		"tunnel":   func(t *testing.T, d *Daemon, f *fakeSys) { f.set(func(f *fakeSys) { f.foreign = "utun9" }) },
		"dpi tool": func(t *testing.T, d *Daemon, f *fakeSys) { f.set(func(f *fakeSys) { f.tool = "GoodbyeDPI" }) },
		"plumbing": func(t *testing.T, d *Daemon, f *fakeSys) {
			f.set(func(f *fakeSys) { f.healthErr = context.DeadlineExceeded })
		},
		"network lost while verifying": func(t *testing.T, d *Daemon, f *fakeSys) {
			f.set(func(f *fakeSys) { f.capErr = errors.New("TLS through the capture: timeout") })
			pass(t, d)
			pass(t, d)
			wantState(t, d, StateStarting, "verifying")
			wantProof(t, d, proofDoubtful)
			f.set(func(f *fakeSys) { f.net.Online = false }) // the lid closes, the Wi-Fi drops
		},
	} {
		t.Run(name, func(t *testing.T) {
			d, f := pendingRig(t)
			block(t, d, f)
			pass(t, d)
			pass(t, d)
			wantProof(t, d, proofNone)
			confirm(t, d, 2*confirmDoubt)
			st := pendingState(d)
			if st.Pending == nil || st.Failed != "" || d.restart.Load() {
				t.Fatalf("decided without evidence: pending=%+v failed=%q last=%+v", st.Pending, st.Failed, st.Last)
			}
			d.upd.forgiveStart()
			if n := pendingState(d).Pending.Starts; n != 0 {
				t.Fatalf("starts = %d after a clean stop that failed at nothing, want 0", n)
			}
		})
	}
}

// sing-box runs, the network is there, and nothing passes: a build whose
// capture carries no traffic looks like that, and so does a bad line. It is
// given four times as long as a sing-box that does not start at all.
func TestACaptureThatRunsButNeverVerifiesGetsLonger(t *testing.T) {
	d, f := pendingRig(t)
	f.set(func(f *fakeSys) { f.capErr = errors.New("TLS through the capture: timeout") })
	pass(t, d)
	pass(t, d)
	wantState(t, d, StateStarting, "verifying")
	wantProof(t, d, proofDoubtful)

	confirm(t, d, 2*confirmWithin)
	if st := pendingState(d); st.Pending == nil {
		t.Fatalf("rolled back after %v of a merely unverified capture; that is the limit for a sing-box that does not start", 2*confirmWithin)
	}
	confirm(t, d, 3*time.Second)
	if st := pendingState(d); st.Pending != nil || st.Failed != Version {
		t.Fatalf("never rolled back: %+v", st)
	}
}

// The wait after a fail-open (the network's checks failed with the capture up)
// is doubt, not proof against the build; the wait after sing-box failed is.
func TestWhichWaitsCountAgainstTheBuild(t *testing.T) {
	d, f := pendingRig(t)
	f.set(func(f *fakeSys) { f.capErr = errors.New("DoH: timeout") })
	pass(t, d)
	d.release("fail-open: checks failing for 1m30s: DoH: timeout", StateStandby)
	pass(t, d)
	wantState(t, d, StateStandby, "next attempt in")
	wantProof(t, d, proofDoubtful)

	d.retryAt = time.Now().Add(-time.Second)
	f.set(func(f *fakeSys) { f.tun = false })
	pass(t, d)
	d.sbStarted = time.Now().Add(-31 * time.Second)
	pass(t, d)
	pass(t, d)
	wantState(t, d, StateError, "next attempt in")
	wantProof(t, d, proofBroken)
}

// A run that kept failing counts towards update.MaxStarts even when it is
// stopped cleanly before the verdict: a machine that is only ever on for a
// short while must still get rid of a broken version.
func TestFailingRunStillCountsAsAStart(t *testing.T) {
	d, _ := pendingRig(t)
	d.upd.mu.Lock()
	d.upd.broken = forgiveBelow
	d.upd.mu.Unlock()
	d.upd.forgiveStart()
	if n := pendingState(d).Pending.Starts; n != 1 {
		t.Fatalf("starts = %d after a failing run, want it to still count (1)", n)
	}
}

// stagedBinary puts a downloaded version in place whose commands answer as
// the script says.
func stagedBinary(t *testing.T, d *Daemon, script string) {
	t.Helper()
	dir := filepath.Join(d.p.Support, "update", "stage")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "autodpi"), "#!/bin/sh\n"+script+"\n")
	d.upd.mu.Lock()
	d.upd.staged, d.upd.phase = &update.Staged{Version: "99.0.0", Dir: dir}, phaseReady
	d.upd.st.Latest = &update.Release{Version: "99.0.0"}
	d.upd.mu.Unlock()
}

const goodBinary = `case "$1" in
version) echo "autodpi 99.0.0 (test)" ;;
selftest) echo "self test passed" ;;
esac`

// installRig is a daemon with nothing pending and a program to replace.
func installRig(t *testing.T) *Daemon {
	t.Helper()
	d, _ := pendingRig(t)
	d.upd.st.Pending = nil
	d.upd.save()
	return d
}

// The loop's question before it downloads or installs by itself.
func wanted(d *Daemon) bool {
	d.upd.mu.Lock()
	defer d.upd.mu.Unlock()
	r := d.upd.newer()
	held := d.upd.st.Pending != nil && !olderThan(d.upd.st.Pending.At, pendingMax)
	return r != nil && r.Version != d.upd.st.Skipped && r.Version != d.upd.st.Failed && !held
}

// A version whose own self test says it cannot work here used to be thrown
// away and downloaded again at the next look, forever. It is marked as failed
// and left alone, and the installed version keeps running.
func TestAVersionThatFailsItsSelfTestIsNotDownloadedAgain(t *testing.T) {
	d := installRig(t)
	stagedBinary(t, d, `case "$1" in
version) echo "autodpi 99.0.0 (test)" ;;
*) echo "error: sing-box refuses the configuration for the usual capture" >&2; exit 3 ;;
esac`)
	err := d.upd.install(context.Background(), false)
	if !errors.Is(err, update.ErrSelfTest) {
		t.Fatalf("install: %v", err)
	}
	st := d.upd.status()
	if !st.Failed || st.Latest != "99.0.0" || !strings.Contains(st.Error, "refuses the configuration") {
		t.Fatalf("status after a failed self test: %+v", st)
	}
	if d.upd.staged != nil || d.restart.Load() || fileText(d.p.Installed) != "new" {
		t.Fatal("the refused version is still staged, the daemon restarted, or the program changed")
	}
	if wanted(d) {
		t.Fatal("the failed version would be downloaded again")
	}
	if again := newUpdater(d); again.st.Failed != "99.0.0" {
		t.Fatal("the verdict did not survive a restart")
	}
}

// A self test that could not run (antivirus holding the new files, a full
// disk) says nothing against the release. The same download is used for the
// next try, three times in all, and only then given up.
func TestASelfTestThatCouldNotRunIsTriedAgainWithTheSameDownload(t *testing.T) {
	d := installRig(t)
	stagedBinary(t, d, `case "$1" in
version) echo "autodpi 99.0.0 (test)" ;;
*) echo "error: extract sing-box: no space left on device" >&2; exit 1 ;;
esac`)
	for try := 1; try < update.MaxTries; try++ {
		err := d.upd.install(context.Background(), false)
		if err == nil || errors.Is(err, update.ErrSelfTest) {
			t.Fatalf("try %d: %v", try, err)
		}
		d.upd.mu.Lock()
		staged, failed, phase := d.upd.staged, d.upd.st.Failed, d.upd.phase
		d.upd.mu.Unlock()
		if staged == nil || failed != "" || phase != phaseReady {
			t.Fatalf("try %d: staged=%v failed=%q phase=%q; want the download kept for the next try", try, staged, failed, phase)
		}
		if !strings.Contains(d.upd.status().Error, "no space left") {
			t.Fatalf("try %d: the reason is not shown: %+v", try, d.upd.status())
		}
	}
	if err := d.upd.install(context.Background(), false); err == nil {
		t.Fatal("the last try passed")
	}
	if st := d.upd.status(); !st.Failed || wanted(d) {
		t.Fatalf("after %d tries the version is still wanted: %+v", update.MaxTries, st)
	}
}

// A download that has gone missing is fetched again, and is no verdict.
func TestAMissingDownloadIsFetchedAgain(t *testing.T) {
	d := installRig(t)
	stagedBinary(t, d, goodBinary)
	if err := os.RemoveAll(filepath.Join(d.p.Support, "update")); err != nil {
		t.Fatal(err)
	}
	err := d.upd.install(context.Background(), false)
	if !errors.Is(err, update.ErrGone) || errors.Is(err, update.ErrSelfTest) {
		t.Fatalf("install: %v", err)
	}
	if d.upd.staged != nil || d.upd.st.Failed != "" {
		t.Fatalf("staged=%v failed=%q; want a fresh download next time and no verdict", d.upd.staged, d.upd.st.Failed)
	}
}

// While one update waits for its verdict the service does not put another on
// top of it by itself, and says why. The user's own "install now" does go
// ahead: a newer release may be the cure for what keeps this one unconfirmed.
func TestInstallingOverAnUnconfirmedUpdate(t *testing.T) {
	d, _ := pendingRig(t)
	stagedBinary(t, d, goodBinary)
	if wanted(d) {
		t.Fatal("a newer release is wanted while the last update is minutes old and unconfirmed")
	}
	err := d.upd.install(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "still being confirmed") || !strings.Contains(d.upd.status().Error, "still being confirmed") {
		t.Fatalf("install by itself: err=%v status=%+v", err, d.upd.status())
	}
	if d.restart.Load() || pendingState(d).Pending.To != Version || d.upd.staged == nil {
		t.Fatal("a refused install changed something")
	}

	if err := d.upd.install(context.Background(), true); err != nil {
		t.Fatalf("install the user asked for: %v", err)
	}
	st := pendingState(d)
	if st.Pending == nil || st.Pending.To != "99.0.0" || !d.restart.Load() {
		t.Fatalf("after the asked install: pending=%+v restart=%v", st.Pending, d.restart.Load())
	}
	if !strings.Contains(fileText(d.p.Installed), "99.0.0") {
		t.Fatal("the new version is not in place")
	}
	// What is kept to go back to is the last version that WAS confirmed, not
	// the unconfirmed one this went over: that one may be the broken build
	// the user is trying to get away from.
	if st.Pending.From != "0.0.9" || fileText(previous(d)) != "old" {
		t.Fatalf("the version to go back to is %q (file %q), want the last confirmed one", st.Pending.From, fileText(previous(d)))
	}
	if err := update.Rollback(d.p, &d.upd.st, "did not work either"); err != nil || fileText(d.p.Installed) != "old" {
		t.Fatalf("a rollback after that does not land on the last confirmed version: %v, installed %q", err, fileText(d.p.Installed))
	}
}

// An update that has stayed unconfirmed for days (a machine that is always
// paused, or always behind a VPN) no longer holds newer releases back.
func TestAnOldUnconfirmedUpdateGivesWay(t *testing.T) {
	d, _ := pendingRig(t)
	stagedBinary(t, d, goodBinary)
	d.upd.mu.Lock()
	d.upd.st.Pending.At = time.Now().Add(-pendingMax - time.Hour)
	d.upd.mu.Unlock()
	if !wanted(d) {
		t.Fatal("a newer release is still held back")
	}
	if err := d.upd.install(context.Background(), false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if p := pendingState(d).Pending; p == nil || p.To != "99.0.0" {
		t.Fatalf("pending = %+v", p)
	}
}

// Any other failure to install (a file in use, a missing directory) is tried
// again later and keeps the version that was pending as it was.
func TestAnInstallThatFailsToSwapKeepsEverything(t *testing.T) {
	d, _ := pendingRig(t)
	stagedBinary(t, d, goodBinary)
	d.p.Installed = filepath.Join(d.p.Support, "missing-dir", "autodpi") // nothing to move aside
	err := d.upd.install(context.Background(), true)
	if err == nil || errors.Is(err, update.ErrSelfTest) {
		t.Fatalf("install: %v", err)
	}
	st := pendingState(d)
	if st.Pending == nil || st.Pending.To != Version || st.Failed != "" || d.restart.Load() {
		t.Fatalf("pending=%+v failed=%q restart=%v", st.Pending, st.Failed, d.restart.Load())
	}
}

// A capture that was verified and now fails its checks, on the way to a
// fail-open, is not "working": that is what a build that breaks under traffic
// looks like, and time spent like that must not get it confirmed.
func TestFailingChecksAreNotWorkingTime(t *testing.T) {
	d, f := pendingRig(t)
	engage(t, d, f)
	wantProof(t, d, proofWorking)
	f.set(func(f *fakeSys) { f.capErr = errors.New("TLS through the capture: reset"); f.healthErr = f.capErr })
	pass(t, d)
	if s, _ := state(d); s != StateActive {
		t.Skipf("released at the first failed check (state %s): nothing to tell apart", s)
	}
	wantProof(t, d, proofDoubtful)
}

// An install replaces the pending update while the confirmation is waiting
// for its turn. What it then looks at is no longer its update: it must not
// take the new one back (or keep it) on the old one's record.
func TestConfirmationLeavesAReplacedUpdateAlone(t *testing.T) {
	d, _ := pendingRig(t)
	mine := pendingState(d).Pending
	d.upd.mu.Lock()
	d.upd.broken = confirmWithin // one step from a rollback
	d.upd.st.Pending = &update.Pending{From: Version, To: "99.0.0", At: time.Now()}
	d.upd.mu.Unlock()
	if !d.upd.judge(context.Background(), mine, confirmTick) {
		t.Fatal("kept judging an update that is no longer the pending one")
	}
	st := pendingState(d)
	if st.Pending == nil || st.Pending.To != "99.0.0" || st.Failed != "" || d.restart.Load() {
		t.Fatalf("the replacing update was decided on the old one's record: pending=%+v failed=%q", st.Pending, st.Failed)
	}
}

// Nor while an install is under way: its download is in the folder a commit
// removes.
func TestConfirmationWaitsForARunningInstall(t *testing.T) {
	d, f := pendingRig(t)
	engage(t, d, f)
	d.upd.mu.Lock()
	d.upd.worked = confirmAfter
	d.upd.mu.Unlock()
	d.upd.work.Lock() // an install is probing
	confirm(t, d, 10*confirmTick)
	if pendingState(d).Pending == nil {
		t.Fatal("committed (and removed the download folder) while an install was running")
	}
	d.upd.work.Unlock()
	confirm(t, d, 3*time.Second)
	if pendingState(d).Pending != nil {
		t.Fatal("never committed once the install was over")
	}
}

// The service is told to stop while a downloaded version is checking itself.
// The stop wins: no try is counted against the release, and nothing is
// swapped in or restarted into.
func TestAStopDuringTheSelfTestIsNotAFailedInstall(t *testing.T) {
	d := installRig(t)
	stagedBinary(t, d, `case "$1" in
version) echo "autodpi 99.0.0 (test)" ;;
selftest) sleep 30 ;;
esac`)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	err := d.upd.install(ctx, false)
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("install: %v after %v", err, time.Since(start))
	}
	st := pendingState(d)
	if st.Tries != nil || st.Failed != "" || st.Pending != nil || d.restart.Load() || fileText(d.p.Installed) != "new" {
		t.Fatalf("a stop was treated as a failed install: tries=%+v failed=%q pending=%+v restart=%v", st.Tries, st.Failed, st.Pending, d.restart.Load())
	}
	if d.upd.staged == nil {
		t.Fatal("the download was thrown away")
	}
}

// A newer release that is known, wanted, downloaded and verified is still not
// installed by the service itself, however quiet the connection is: installing
// is the user's to ask for (the Update button).
func TestNothingIsInstalledWithoutBeingAskedFor(t *testing.T) {
	d := installRig(t)
	stagedBinary(t, d, goodBinary)
	d.upd.mu.Lock()
	d.upd.st.Checked = time.Now() // no look at GitHub from this test
	d.upd.mu.Unlock()
	if !wanted(d) || !d.upd.supported() {
		t.Fatalf("the rig has nothing to install: wanted=%v supported=%v", wanted(d), d.upd.supported())
	}
	before := fileText(d.p.Installed)
	first, tick := updateFirstLook, updateTick
	updateFirstLook, updateTick = 10*time.Millisecond, 10*time.Millisecond
	defer func() { updateFirstLook, updateTick = first, tick }()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	d.upd.loop(ctx) // dozens of looks
	if st := pendingState(d); d.restart.Load() || fileText(d.p.Installed) != before || st.Pending != nil {
		t.Fatalf("the service installed an update by itself: restart=%v installed=%q pending=%+v", d.restart.Load(), fileText(d.p.Installed), st.Pending)
	}
	if st := d.upd.status(); st.Latest != "99.0.0" || st.Phase != phaseReady {
		t.Fatalf("the release is no longer on offer: %+v", st)
	}
	// Asked for, it goes in.
	if err := d.upd.install(context.Background(), true); err != nil {
		t.Fatalf("install when asked: %v", err)
	}
	if !d.restart.Load() || fileText(d.p.Installed) == before {
		t.Fatalf("the update the user asked for was not installed: restart=%v", d.restart.Load())
	}
}

// The setting an earlier version had ("auto_update") is taken out of the
// config file, but not while an update waits to be confirmed: taken back, the
// version before must find the file as it left it.
func TestTheRetiredSettingGoesOnceTheVersionIsHereToStay(t *testing.T) {
	d, _ := pendingRig(t)
	d.p.Config = filepath.Join(d.p.Support, "config.json")
	mustWrite(t, d.p.Config, `{"auto_update": false, "hedge_ms": 900}`)
	if d.upd.st.Pending == nil {
		t.Fatal("the rig has nothing pending")
	}
	d.upd.tidyConfig()
	if !strings.Contains(fileText(d.p.Config), "auto_update") {
		t.Fatalf("the file was changed while the update was unconfirmed:\n%s", fileText(d.p.Config))
	}
	d.upd.st.Pending = nil
	d.upd.tidyConfig()
	if s := fileText(d.p.Config); strings.Contains(s, "auto_update") || !strings.Contains(s, `"hedge_ms": 900`) {
		t.Fatalf("after the version was confirmed:\n%s", s)
	}
}
