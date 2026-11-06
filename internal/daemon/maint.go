package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/ipc"
)

// maint runs one of ipc.MaintActions.
func (d *Daemon) maint(r ipc.Request) (any, error) {
	switch r.Action {
	case "clear-logs":
		return d.clearLogs()

	case "restart":
		// launchd (KeepAlive) or the SCM (recovery actions) starts the daemon
		// again; run by hand there is nobody to do that, so refuse instead of
		// just stopping.
		if !d.opt.Supervised {
			return nil, errors.New(r.T("bu daemon elle başlatıldı, onu yeniden başlatacak bir servis yöneticisi yok", "this daemon was started by hand: no service manager would start it again"))
		}
		d.note("restart", "", "requested")
		d.restart.Store(true)
		d.stopSoon()
		return map[string]any{"restarting": true}, nil

	case "shutdown":
		// A clean exit: launchd and the SCM leave the daemon down until it is
		// started again (launchctl kickstart or sc start, the menu bar or tray
		// app's start button, or the next boot).
		d.note("shutdown", "", "requested")
		d.stopSoon()
		return map[string]any{"stopping": true}, nil

	case "flush-dns":
		if err := flushDNS(); err != nil {
			return nil, err
		}
		d.logOnly("flush-dns", "", "")
		return map[string]any{"flushed": true}, nil

	case "retest":
		if !d.running() {
			return nil, errors.New(r.T("servis şu an yakalamada değil; yeniden test için aktif olmalı", "the service is not capturing right now; it must be active to re-test"))
		}
		ctx := d.runCtx
		if ctx == nil {
			ctx = context.Background()
		}
		go d.retestAll(ctx)
		d.logOnly("retest", "", "requested")
		return map[string]any{"started": true}, nil

	case "reset-list", "reset-all-lists":
		key := d.sys.network().Key
		all := r.Action == "reset-all-lists"
		if !all && key == "" {
			return nil, errNoNetwork
		}
		n, err := d.st.ClearAuto(key, all)
		if err != nil {
			return nil, err
		}
		d.applyList()
		d.note("list-reset", key, fmt.Sprintf("%d auto entries removed (all networks: %v)", n, all))
		return map[string]any{"removed": n}, nil

	case "reconcile":
		d.kickReconcile()
		return map[string]any{"kicked": true}, nil
	}
	return nil, fmt.Errorf(r.T("bilinmeyen bakım eylemi %q (olanlar: %v)", "unknown maint action %q (have %v)"), r.Action, ipc.MaintActions)
}

// stopSoon ends Run once the reply to the current request is out.
func (d *Daemon) stopSoon() {
	go func() {
		time.Sleep(500 * time.Millisecond)
		d.stop()
	}()
}

// clearLogs empties the daemon log, its previous generation and the crash log.
// The daemon's own log file is opened for append, so truncating it in place
// is safe while it is being written.
func (d *Daemon) clearLogs() (any, error) {
	var freed int64
	var errs []error
	for _, f := range d.opt.LogFiles {
		fi, err := os.Stat(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if f != "" && fi.Mode().IsRegular() {
			if err := os.Truncate(f, 0); err != nil {
				errs = append(errs, err)
				continue
			}
			freed += fi.Size()
		}
	}
	d.mu.Lock()
	d.journal = nil
	d.mu.Unlock()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return map[string]any{"freed_bytes": freed, "files": len(d.opt.LogFiles)}, nil
}

func flushDNS() error {
	if runtime.GOOS == "windows" {
		return exec.Command("ipconfig", "/flushdns").Run()
	}
	if err := exec.Command("/usr/bin/dscacheutil", "-flushcache").Run(); err != nil {
		return fmt.Errorf("dscacheutil: %w", err)
	}
	// mDNSResponder is the cache that matters; it is not an error if it is absent.
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
	return nil
}
