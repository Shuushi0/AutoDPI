package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/update"
)

// The updater: the daemon looks for a newer release, downloads and verifies
// it, and with auto_update swaps it in at a quiet moment and restarts into
// it. The new daemon confirms itself once it runs well (confirmLoop); one
// that keeps stopping or never gets going is replaced by the old one again.

// Update phases, as status reports them.
const (
	phaseChecking    = "checking"
	phaseDownloading = "downloading"
	phaseReady       = "ready" // downloaded and verified, waiting to be installed
	phaseInstalling  = "installing"
)

const (
	updateFirstLook = 90 * time.Second // after start: let the capture settle first
	updateTick      = 30 * time.Second
	quietFor        = time.Minute    // no new connection this long: install now
	installAnyway   = 24 * time.Hour // ready this long: install even if never quiet
	confirmWithin   = 5 * time.Minute
	retryFetch      = time.Hour
)

// UpdateStatus is the update part of Status.
type UpdateStatus struct {
	Current   string         `json:"current"`
	Latest    string         `json:"latest,omitempty"` // a newer release, "" when this is the newest
	URL       string         `json:"url,omitempty"`    // its release page
	Notes     string         `json:"notes,omitempty"`
	Phase     string         `json:"phase,omitempty"`
	Auto      bool           `json:"auto"`
	Hours     int            `json:"hours"` // update_check_hours
	Checked   time.Time      `json:"checked"`
	Error     string         `json:"error,omitempty"`
	Skipped   bool           `json:"skipped,omitempty"` // the user skipped Latest
	Failed    bool           `json:"failed,omitempty"`  // Latest was installed and rolled back
	Supported bool           `json:"supported"`         // this install can update itself
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
	readyAt time.Time
	failAt  time.Time // the last download failed: the next waits retryFetch
}

func newUpdater(d *Daemon) *updater {
	u := &updater{d: d, file: update.StateFile(d.p)}
	u.st = update.LoadState(u.file)
	u.http = &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{
		DialContext:         u.dial,
		TLSHandshakeTimeout: 15 * time.Second,
		ForceAttemptHTTP2:   true,
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

// settings reads the two update keys afresh: the page saves them without a
// restart.
func (u *updater) settings() (auto bool, hours int) {
	c, err := config.Load(u.d.p.Config)
	if err != nil && c.Engines == nil {
		c = config.Default()
	}
	return c.AutoUpdate, c.UpdateCheckHours
}

func (u *updater) supported() bool { return update.Platform() != "" && u.d.opt.Supervised }

func (u *updater) save() {
	if err := u.st.Save(u.file); err != nil {
		u.d.log.Warn("update state", "err", err)
	}
}

func (u *updater) status() UpdateStatus {
	auto, hours := u.settings()
	u.mu.Lock()
	defer u.mu.Unlock()
	s := UpdateStatus{Current: Version, Phase: u.phase, Auto: auto, Hours: hours, Checked: u.st.Checked,
		Error: u.err, Supported: u.supported(), Last: u.st.Last}
	if r := u.newer(); r != nil {
		s.Latest, s.URL, s.Notes = r.Version, r.URL, r.Notes
		s.Skipped = r.Version == u.st.Skipped
		s.Failed = r.Version == u.st.Failed
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
	}
	return false
}

// confirmLoop confirms a fresh update once the daemon has come up, and goes
// back to the old version if it does not within confirmWithin.
func (u *updater) confirmLoop(ctx context.Context) {
	u.mu.Lock()
	p := u.st.Pending
	u.mu.Unlock()
	if p == nil {
		return
	}
	deadline := time.Now().Add(confirmWithin)
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		u.d.mu.Lock()
		state := u.d.state
		u.d.mu.Unlock()
		if state != StateStarting && state != StateError {
			u.mu.Lock()
			update.Commit(u.d.p, &u.st)
			u.save()
			u.mu.Unlock()
			u.d.note("update", Version, "updated from "+p.From)
			return
		}
		if time.Now().After(deadline) {
			u.mu.Lock()
			update.Rollback(u.d.p, &u.st, "the new version did not start working within 5 minutes ("+state+")")
			u.save()
			u.mu.Unlock()
			u.d.note("update", Version, "rolled back to "+p.From)
			u.d.restartSelf()
			return
		}
	}
}

// loop checks on schedule and, with auto_update, installs.
func (u *updater) loop(ctx context.Context) {
	if update.Platform() == "" {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(updateFirstLook):
	}
	var lastFlows int64 = -1
	var quietSince time.Time
	t := time.NewTicker(updateTick)
	defer t.Stop()
	for {
		auto, hours := u.settings()
		u.mu.Lock()
		due := hours > 0 && time.Since(u.st.Checked) >= time.Duration(hours)*time.Hour
		u.mu.Unlock()
		if due {
			u.check(ctx)
		}
		if auto && u.supported() {
			u.mu.Lock()
			r := u.newer()
			want := r != nil && r.Version != u.st.Skipped && r.Version != u.st.Failed
			ready := u.staged != nil && r != nil && u.staged.Version == r.Version
			readyAt, failAt := u.readyAt, u.failAt
			u.mu.Unlock()
			switch {
			case want && !ready && time.Since(failAt) >= retryFetch:
				u.fetch(ctx)
			case want && ready:
				flows := u.d.sys.flows()
				if flows != lastFlows {
					lastFlows, quietSince = flows, time.Now()
				}
				if time.Since(quietSince) >= quietFor || !u.d.running() || time.Since(readyAt) >= installAnyway {
					u.install()
				}
			}
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
	u.phase, u.err = p, err
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
	u.mu.Unlock()
	rel, etag, err := update.Check(ctx, u.http, Version, etag)

	u.mu.Lock()
	defer u.mu.Unlock()
	u.phase = ""
	u.st.Checked = time.Now()
	switch {
	case errors.Is(err, update.ErrNotModified):
	case err != nil:
		u.err = err.Error()
	default:
		u.st.ETag, u.st.Latest = etag, rel
	}
	u.save()
	if err != nil && !errors.Is(err, update.ErrNotModified) {
		u.d.logOnly("update", "", "check: "+err.Error())
	}
	return true
}

// fetch downloads and verifies the newer release.
func (u *updater) fetch(ctx context.Context) bool {
	if !u.work.TryLock() {
		return false
	}
	defer u.work.Unlock()
	u.mu.Lock()
	r := u.newer()
	u.mu.Unlock()
	if r == nil {
		return true
	}
	u.setPhase(phaseDownloading, "")
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	st, err := update.Fetch(ctx, u.http, r, update.WorkDir(u.d.p))
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil {
		u.phase, u.err, u.failAt = "", err.Error(), time.Now()
		u.d.logOnly("update", r.Version, "download: "+err.Error())
		return true
	}
	u.phase, u.staged, u.readyAt = phaseReady, &st, time.Now()
	u.d.logOnly("update", r.Version, "downloaded and verified")
	return true
}

// install swaps the staged release in and restarts into it.
func (u *updater) install() error {
	if !u.work.TryLock() {
		return errBusy
	}
	defer u.work.Unlock()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.staged == nil {
		return errors.New("nothing downloaded")
	}
	u.phase = phaseInstalling
	from := Version
	if err := update.Apply(u.d.p, *u.staged, from, &u.st); err != nil {
		u.phase, u.err, u.staged = "", err.Error(), nil
		u.d.note("update", from, "install failed: "+err.Error())
		return err
	}
	u.save()
	u.d.note("update", u.staged.Version, "installing, restarting")
	u.d.restartSelf()
	return nil
}

var errBusy = errors.New("busy")

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
				u.fetch(ctx)
			}
			_ = u.install()
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
