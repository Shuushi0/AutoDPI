package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/update"
)

// The updater: the daemon looks for a newer release and announces it. When
// the user asks for it (the Update button, `autodpi update install`), it
// downloads and verifies the release, swaps it in and restarts into it;
// nothing is installed without being asked for. The new daemon confirms
// itself once it runs well (confirmLoop); one that keeps stopping or never
// gets going is replaced by the old one again.

// Update phases, as status reports them.
const (
	phaseChecking    = "checking"
	phaseDownloading = "downloading"
	phaseReady       = "ready" // downloaded and verified, waiting to be installed
	phaseInstalling  = "installing"
)

var (
	updateFirstLook = 90 * time.Second // after start: let the capture settle first
	updateTick      = 30 * time.Second
)

// An update is confirmed by the capture working, not by the daemon being
// alive: see confirmLoop. Variables so that tests need not wait.
var (
	confirmAfter  = 10 * time.Minute // the capture has worked this long: the update stays
	confirmWithin = 5 * time.Minute  // sing-box itself has failed this long: back to the old version
	confirmDoubt  = 20 * time.Minute // sing-box runs but nothing passes, this long: back as well
	confirmTick   = 5 * time.Second  // how often the fresh update is looked at
	forgiveBelow  = 30 * time.Second // a run that failed for less than this does not count as a failed start
	pendingMax    = 72 * time.Hour   // an update unconfirmed this long no longer holds a newer one back
	proofWait     = 10 * time.Second // the daemon does not say how its capture is for this long: it hangs
	fetchMax      = 3 * time.Hour    // one download, however slow the line
)

// olderThan reports whether t is at least d ago by the wall clock. A time
// that lies ahead (written while the clock was wrong, or before it was set
// back) counts as long ago: otherwise it would hold whatever waits on it for
// as long as the clock was off, which can be years.
func olderThan(t time.Time, d time.Duration) bool {
	age := wallSince(t)
	return age < 0 || age >= d
}

// UpdateStatus is the update part of Status.
type UpdateStatus struct {
	Current string    `json:"current"`
	Latest  string    `json:"latest,omitempty"` // a newer release, "" when this is the newest
	URL     string    `json:"url,omitempty"`    // its release page
	Notes   string    `json:"notes,omitempty"`
	Phase   string    `json:"phase,omitempty"`
	Hours   int       `json:"hours"` // update_check_hours
	Checked time.Time `json:"checked"`
	Error   string    `json:"error,omitempty"`
	// ErrorKind says what Error is about: "check" (looking for a release),
	// "download" or "install". A failed look says nothing about a download
	// that is ready, and must not be shown as its reason.
	ErrorKind string `json:"error_kind,omitempty"`
	Skipped   bool   `json:"skipped,omitempty"` // the user skipped Latest
	Failed    bool   `json:"failed,omitempty"`  // Latest was installed and rolled back
	// RolledBack: Failed because it was installed and taken back; otherwise it
	// never got as far as being installed (its self test, or three tries).
	RolledBack bool `json:"rolled_back,omitempty"`
	// Pending: the last update is still being confirmed, and holds Latest back.
	Pending   bool           `json:"pending,omitempty"`
	Supported bool           `json:"supported"` // this install can update itself
	Last      *update.Result `json:"last,omitempty"`
}

type updater struct {
	d    *Daemon
	file string
	http *http.Client

	work sync.Mutex // one check, download or install at a time

	mu      sync.Mutex
	st      update.State
	phase   string
	err     string
	staged  *update.Staged
	errKind string      // what err is about: check, download or install
	asking  atomic.Bool // a look at the capture has not come back yet (proof)
	// While an update is pending, how long this run's capture has worked, has
	// failed for a reason that is sing-box's, and has failed for one that may
	// be the network's (see captureProof).
	worked, broken, doubted time.Duration
}

func newUpdater(d *Daemon) *updater {
	u := &updater{d: d, file: update.StateFile(d.p)}
	u.st = update.LoadState(u.file)
	// No limit on a whole request: each caller sets its own (30s for the
	// list; a download is limited by standing still, see update.Fetch).
	u.http = &http.Client{CheckRedirect: update.HTTPSOnly, Transport: &http.Transport{
		DialContext:           u.dial,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     true,
	}}
	return u
}

// dial reaches GitHub the way the daemon reaches everything: names through
// its own DoH, sockets on the physical interface, never through the capture.
func (u *updater) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := u.d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error = fmt.Errorf("no address for %s", host)
	for _, ip := range ips {
		c, err := u.d.dial.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// settings reads how often to look for a release afresh: the page saves it
// without a restart.
func (u *updater) settings() (hours int) {
	// The language is the third setting the page saves without a restart:
	// what the service itself words (the audit's findings) follows it from
	// here on.
	i18n.Reload()
	c, err := config.Load(u.d.p.Config)
	if err != nil && c.Engines == nil {
		c = config.Default()
	}
	return c.UpdateCheckHours
}

func (u *updater) supported() bool { return update.Platform() != "" && u.d.opt.Supervised }

func (u *updater) save() error {
	err := u.st.Save(u.file)
	if err != nil {
		u.d.log.Warn("update state", "err", err)
	}
	return err
}

func (u *updater) status() UpdateStatus {
	hours := u.settings()
	u.mu.Lock()
	defer u.mu.Unlock()
	s := UpdateStatus{Current: Version, Phase: u.phase, Hours: hours, Checked: u.st.Checked,
		Error: brief(u.err, 240), Supported: u.supported(), Last: u.st.Last}
	if u.err != "" {
		s.ErrorKind = u.errKind
	}
	if r := u.newer(); r != nil {
		s.Latest, s.URL, s.Notes = r.Version, r.URL, brief(r.Notes, 4000)
		s.Skipped = r.Version == u.st.Skipped
		s.Failed = r.Version == u.st.Failed
		s.RolledBack = s.Failed && u.st.Last != nil && u.st.Last.To == r.Version && !u.st.Last.OK
		s.Pending = u.st.Pending != nil && !olderThan(u.st.Pending.At, pendingMax)
	}
	return s
}

// brief cuts s to most characters: these travel with every status answer and
// are shown in a banner 372 pixels wide.
func brief(s string, most int) string {
	if r := []rune(s); len(r) > most {
		return string(r[:most-1]) + "…"
	}
	return s
}

// newer is the known release above this version, nil if none. Callers hold mu.
func (u *updater) newer() *update.Release {
	if r := u.st.Latest; r != nil && update.Compare(r.Version, Version) > 0 {
		return r
	}
	return nil
}

// resume settles an update in flight before the daemon starts working. It
// reports whether the daemon must restart at once (the old version is back).
func (u *updater) resume() bool {
	switch update.Resume(u.d.p, Version, &u.st) {
	case update.RolledBack:
		u.save()
		u.d.log.Warn("update rolled back", "version", Version, "why", u.st.Last.Error)
		return true
	case update.Confirm:
		u.save()
		u.d.log.Info("update pending confirmation", "from", u.st.Pending.From, "start", u.st.Pending.Starts)
	default:
		u.save()
		u.tidyConfig()
	}
	return false
}

// tidyConfig takes the settings this version no longer has out of the config
// file. Only once this version is here to stay (nothing waiting to be
// confirmed): an update that is taken back must find the file as the
// version before left it.
func (u *updater) tidyConfig() {
	if u.st.Pending != nil {
		return
	}
	if did, err := config.Tidy(u.d.p.Config); err != nil {
		u.d.log.Warn("config", "err", err)
	} else if did {
		u.d.log.Info("config: removed the settings this version no longer has")
	}
}

// proof is what the capture says about the build at one moment.
type proof int

const (
	proofNone     proof = iota // nothing can be said
	proofWorking               // the capture is verified and running
	proofBroken                // sing-box does not start, or its capture does not come up
	proofDoubtful              // sing-box runs, the network is there, and nothing passes through
)

// captureProof reads the capture's state as evidence about this build.
//
// Working: the capture is active. Broken: an error state, or the wait after
// one; that is sing-box failing to start or to bring the capture up. Doubtful:
// the capture is up but unverified, or was released because its checks kept
// failing: a build whose sing-box carries no traffic looks like this, and so
// does a network that is merely bad. None: paused, offline, another tunnel or
// DPI tool in the way, or the plumbing check that comes before any attempt
// failing; none of it is the build's doing (or can be told to be).
func (d *Daemon) captureProof() proof {
	online := d.sys.network == nil || d.sys.network().Online
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.opt.NoTun && d.opt.TestPort == 0:
		return proofWorking // no capture in this run: the daemon being up is all there is
	case d.state == StateActive && d.badAt.IsZero():
		return proofWorking
	case d.state == StateActive:
		// Verified once and now failing its checks, on the way to a
		// fail-open: a build that breaks under traffic looks like this, and it
		// must not be counted towards being kept.
		return proofDoubtful
	case !online:
		return proofNone
	case d.state == StateError || d.backoffHard:
		return proofBroken
	case d.state == StateStarting || d.backingOff:
		return proofDoubtful
	case d.state == StateStandby && d.selfBroken:
		// Never engaging because its own observer does not relay, with the
		// resolvers answering: nothing else would ever take such a build
		// back, since it does not crash and never gets as far as sing-box.
		return proofDoubtful
	}
	return proofNone
}

// confirmLoop decides about a fresh update from what its capture does, not
// from the daemon being alive: a sing-box that cannot start leaves the daemon
// running, the internet working and no site unblocked.
//
// The update stays once the capture has worked for confirmAfter in all; only
// then are the previous files removed, so a build that falls over under its
// first traffic can still be undone. It goes back to the previous version
// after confirmWithin of sing-box itself failing, or confirmDoubt of failing
// in a way a bad network could also explain. Time in which nothing can be
// said counts for nothing; the update stays pending.
func (u *updater) confirmLoop(ctx context.Context) {
	u.mu.Lock()
	p := u.st.Pending
	u.mu.Unlock()
	if p == nil {
		return
	}
	t := time.NewTicker(confirmTick)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		step := min(now.Sub(last), 2*confirmTick) // a sleeping machine did nothing in between
		last = now
		// Not while an install is under way: it may be putting another
		// version in this one's place, and its download lives in the folder
		// a decision here would remove.
		if !u.work.TryLock() {
			continue
		}
		decided := u.judge(ctx, p, step)
		u.work.Unlock()
		if decided {
			return
		}
	}
}

// judge is one look at the pending update p: it reports whether the matter
// is settled (kept, taken back, or no longer this loop's to decide).
func (u *updater) judge(ctx context.Context, p *update.Pending, step time.Duration) bool {
	kind := u.proof()
	u.mu.Lock()
	if u.st.Pending != p || ctx.Err() != nil {
		// Another update took its place, or the daemon is stopping.
		u.mu.Unlock()
		return true
	}
	switch kind {
	case proofWorking:
		u.worked += step
	case proofBroken:
		u.broken += step
	case proofDoubtful:
		u.doubted += step
	}
	keep := u.worked >= confirmAfter
	undo := !keep && (u.broken >= confirmWithin || u.broken+u.doubted >= confirmDoubt)
	if keep {
		// The record first, the kept copies after it (Commit): were the copies
		// removed and the record then not saved, a pending update would be on
		// disk with nothing behind it. Not saved: nothing is removed, and the
		// next look tries again.
		if err := update.Commit(u.d.p, &u.st); err != nil {
			u.d.log.Warn("update state", "err", err)
			keep = false
		} else {
			u.dropStaged()
			u.tidyConfig()
		}
	}
	u.mu.Unlock()

	switch {
	case keep:
		u.d.note("update", Version, "updated from "+p.From)
		return true
	case undo:
		// Without waiting for the daemon's lock: a build that hangs holds it.
		state, detail := "no answer", "the service stopped answering"
		if u.d.mu.TryLock() {
			state, detail = u.d.state, u.d.detail
			u.d.mu.Unlock()
		}
		u.mu.Lock()
		err := update.Rollback(u.d.p, &u.st, fmt.Sprintf("the new version's capture did not work (%s: %s)", state, detail))
		if err == nil {
			u.dropStaged()
		}
		u.save()
		u.mu.Unlock()
		// The journal takes the daemon's lock, which a build that hangs holds
		// for good: nothing here may wait for it, or the files would be back
		// and this process would run on, with the work lock held as well.
		if err != nil {
			// Still this version, and saying otherwise would be a lie. The
			// next start tries again (update.Resume).
			u.d.log.Warn("update: could not go back", "to", p.From, "err", err)
			go u.d.note("update", Version, "could not go back to "+p.From+": "+err.Error())
			return true
		}
		u.d.log.Warn("update rolled back", "from", Version, "to", p.From)
		u.d.restartSelf()
		go u.d.note("update", Version, "rolled back to "+p.From)
		return true
	}
	return false
}

// proof is captureProof with a limit. A build that hangs (a lock held for
// good) never answers, launchd and the service manager see a live process,
// and nothing else would ever take it back: no answer counts as broken.
func (u *updater) proof() proof {
	if !u.asking.CompareAndSwap(false, true) {
		return proofBroken // the last look still has not come back
	}
	res := make(chan proof, 1)
	go func() {
		res <- u.d.captureProof()
		u.asking.Store(false)
	}()
	select {
	case k := <-res:
		return k
	case <-time.After(proofWait):
		return proofBroken
	}
}

// dropStaged forgets a download: Commit and Rollback remove the folder it is
// in. Callers hold u.mu.
func (u *updater) dropStaged() {
	u.staged = nil
	if u.phase == phaseReady {
		u.phase = ""
	}
}

// forgiveStart takes back this run's count towards update.MaxStarts when the
// daemon stops in an orderly way without having failed: a machine that is
// paused or offline may be shut down, and its service restarted, any number of
// times before the update gets its chance. A crash never gets here, and a run
// that kept failing still counts.
func (u *updater) forgiveStart() {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.st.Pending == nil || u.st.Pending.Starts == 0 || u.broken+u.doubted >= forgiveBelow {
		return
	}
	u.st.Pending.Starts--
	u.save()
}

// loop checks on schedule. It installs nothing: that is the user's to ask
// for (request).
func (u *updater) loop(ctx context.Context) {
	if update.Platform() == "" {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(updateFirstLook):
	}
	t := time.NewTicker(updateTick)
	defer t.Stop()
	for {
		// A file an update moved aside and could not replace (something held
		// it) goes back as soon as it lets itself be moved.
		update.Heal(u.d.p)
		hours := u.settings()
		u.mu.Lock()
		due := hours > 0 && olderThan(u.st.Checked, time.Duration(hours)*time.Hour)
		u.mu.Unlock()
		if due {
			u.check(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (u *updater) setPhase(p, err string) {
	u.mu.Lock()
	u.phase, u.err, u.errKind = p, err, ""
	u.mu.Unlock()
}

// check asks GitHub once. It returns false when another job is running.
func (u *updater) check(ctx context.Context) bool {
	if !u.work.TryLock() {
		return false
	}
	defer u.work.Unlock()
	u.setPhase(phaseChecking, "")
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	u.mu.Lock()
	etag := u.st.ETag
	if u.st.By != Version {
		// The saved answer was to another version's question: after going
		// back to an older one by hand, "nothing has changed" hid the very
		// release that had been running.
		etag = ""
	}
	u.mu.Unlock()
	rel, etag, err := update.Check(ctx, u.http, Version, etag)

	u.mu.Lock()
	defer u.mu.Unlock()
	u.phase = ""
	u.st.Checked = time.Now()
	switch {
	case errors.Is(err, update.ErrNotModified):
	case err != nil:
		u.err, u.errKind = err.Error(), "check"
	default:
		u.st.ETag, u.st.Latest, u.st.By = etag, rel, Version
	}
	u.save()
	if err != nil && !errors.Is(err, update.ErrNotModified) {
		u.d.logOnly("update", "", "check: "+err.Error())
	}
	return true
}

// lock takes the work lock: at once or not at all, or, with wait, whenever
// the job that holds it is done. It reports whether it is held.
func (u *updater) lock(wait bool) bool {
	if wait {
		u.work.Lock()
		return true
	}
	return u.work.TryLock()
}

// fetch downloads and verifies the newer release. With wait it does so after
// whatever job is running; otherwise it returns false when one is.
func (u *updater) fetch(ctx context.Context, wait bool) bool {
	if !u.lock(wait) {
		return false
	}
	defer u.work.Unlock()
	u.mu.Lock()
	r := u.newer()
	if r != nil && u.staged != nil && u.staged.Version == r.Version {
		r = nil // the job waited for has fetched it
	}
	u.mu.Unlock()
	if r == nil {
		return true
	}
	u.setPhase(phaseDownloading, "")
	ctx, cancel := context.WithTimeout(ctx, fetchMax)
	defer cancel()
	st, err := update.Fetch(ctx, u.http, r, update.WorkDir(u.d.p))
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil {
		// A download is only made when the user asks for the update, so a
		// failed one is tried again when they ask again. One that arrives
		// and is not what was signed is given up after update.MaxTries, like
		// an install that keeps failing.
		u.phase, u.err, u.errKind = "", err.Error(), "download"
		if errors.Is(err, update.ErrVerify) {
			if u.st.Fetches == nil || u.st.Fetches.Version != r.Version {
				u.st.Fetches = &update.Tries{Version: r.Version}
			}
			if u.st.Fetches.N++; u.st.Fetches.N >= update.MaxTries {
				u.st.Failed, u.st.Fetches = r.Version, nil
			}
			u.save()
		}
		u.d.logOnly("update", r.Version, "download: "+err.Error())
		return true
	}
	if u.st.Fetches != nil {
		u.st.Fetches = nil
		u.save()
	}
	u.phase, u.staged = phaseReady, &st
	u.d.logOnly("update", r.Version, "downloaded and verified")
	return true
}

// install checks the staged release on this machine, swaps it in and restarts
// into it. asked: the user pressed the button, which also goes ahead over an
// update that is still unconfirmed.
func (u *updater) install(ctx context.Context, asked bool) error {
	// The user's "install now" waits for a check or a look that is under
	// way: it has already been answered with "installing".
	if !u.lock(asked) {
		return errBusy
	}
	defer u.work.Unlock()
	u.mu.Lock()
	if u.staged == nil {
		u.mu.Unlock()
		return errNothingStaged
	}
	st := *u.staged
	if p := u.st.Pending; p != nil && !asked && !olderThan(p.At, pendingMax) {
		const why = "the last update is still being confirmed"
		u.err, u.errKind = why, "install"
		u.mu.Unlock()
		return errors.New(why)
	}
	before := u.phase
	u.phase = phaseInstalling
	u.mu.Unlock()

	// Outside the lock: the release's self test can take minutes on a slow
	// machine, and every status request waits for u.mu.
	err := update.Probe(ctx, u.d.p, st)

	u.mu.Lock()
	defer u.mu.Unlock()
	if ctx.Err() != nil {
		// The service is being stopped. That is not this release failing,
		// and a stop must not turn into a restart into another version.
		u.phase = before
		return ctx.Err()
	}
	if err == nil {
		// Over an unconfirmed update Swap keeps the last confirmed version
		// as what to go back to.
		err = update.Swap(u.d.p, st, Version, &u.st)
	}
	if errors.Is(err, update.ErrHalfSwapped) {
		// Some of the new files are in and could not be taken out again.
		// Which version this is now is settled by a start (update.Resume),
		// with the record as Swap left it.
		u.phase, u.err, u.errKind = before, err.Error(), "install"
		u.save()
		if !update.Heal(u.d.p) {
			// Nothing at the program's own path, and no copy could be put
			// there yet (something still holds the files). A restart now
			// would have nothing to start: this process runs on, and the
			// next look tries again (update.Heal in loop).
			u.d.note("update", Version, "install interrupted and the program is not at its place yet; trying again shortly: "+err.Error())
			return err
		}
		u.d.note("update", Version, "install interrupted, restarting to settle it: "+err.Error())
		u.d.restartSelf()
		return err
	}
	if err != nil {
		// Never straight back to downloading: the same archive would fail the
		// same way, again and again. A verdict against the release ends it. A
		// failure that may pass (a full disk, a file in use, a self test that
		// antivirus kept from finishing) keeps the download: the user's next
		// try uses it, update.MaxTries times in all.
		if u.st.Tries == nil || u.st.Tries.Version != st.Version {
			u.st.Tries = &update.Tries{Version: st.Version}
		}
		u.st.Tries.N++
		u.phase, u.err, u.errKind = before, err.Error(), "install"
		if errors.Is(err, update.ErrSelfTest) || u.st.Tries.N >= update.MaxTries {
			u.st.Failed, u.st.Tries = st.Version, nil
			u.dropStaged()
		} else if errors.Is(err, update.ErrGone) {
			u.dropStaged() // the download itself is missing: fetch it again next time
		}
		u.save()
		u.d.note("update", Version, "install failed: "+err.Error())
		return err
	}
	u.st.Tries = nil
	u.save()
	u.d.note("update", st.Version, "installing, restarting")
	u.d.restartSelf()
	return nil
}

var (
	errBusy          = errors.New("another update step is under way")
	errNothingStaged = errors.New("nothing downloaded")
)

// request answers the "update" command: check, install or skip.
func (u *updater) request(ctx context.Context, r ipc.Request) (any, error) {
	switch r.Action {
	case "check":
		if update.Platform() == "" {
			return nil, errors.New(r.T("bu sistem için güncelleme yayınlanmıyor", "no updates are published for this system"))
		}
		u.check(ctx) // when busy, the running job's result is what status shows
	case "install":
		if !u.supported() {
			return nil, errors.New(r.T("bu kurulum kendini güncelleyemiyor (servis olarak çalışmıyor); yeni sürümü elle kurun",
				"this install cannot update itself (it does not run as a service); install the new version by hand"))
		}
		u.mu.Lock()
		rel := u.newer()
		u.mu.Unlock()
		if rel == nil {
			return nil, errors.New(r.T("yeni sürüm yok", "there is no newer version"))
		}
		go func() {
			ctx := u.d.runCtx
			if ctx == nil {
				ctx = context.Background()
			}
			u.mu.Lock()
			ready := u.staged != nil && u.staged.Version == rel.Version
			u.mu.Unlock()
			if !ready {
				u.fetch(ctx, true)
			}
			err := u.install(ctx, true)
			if errors.Is(err, errNothingStaged) {
				// The download was there and is gone: the last update was
				// confirmed in between, and that clears the folder.
				u.fetch(ctx, true)
				err = u.install(ctx, true)
			}
			if err != nil {
				// The command has already answered "installing": the reason
				// it did not must be somewhere to be found.
				u.mu.Lock()
				if u.err == "" {
					u.err, u.errKind = err.Error(), "install"
				}
				u.mu.Unlock()
				u.d.logOnly("update", rel.Version, "install: "+err.Error())
			}
		}()
	case "skip":
		u.mu.Lock()
		if rel := u.newer(); rel != nil {
			u.st.Skipped = rel.Version
			u.save()
		}
		u.mu.Unlock()
	default:
		return nil, fmt.Errorf(r.T("bilinmeyen güncelleme eylemi %q", "unknown update action %q"), r.Action)
	}
	return u.status(), nil
}

// restartSelf ends Run with ErrRestart, as `maint restart` does.
func (d *Daemon) restartSelf() {
	d.restart.Store(true)
	d.stopSoon()
}
