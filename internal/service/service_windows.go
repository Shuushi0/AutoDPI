package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/sysdns"
	"github.com/Shuushi0/AutoDPI/internal/sysx"
)

// Kind names the service manager entry in doctor's output.
func Kind() string { return i18n.T("Windows hizmeti", "Windows service") }

// InstallHint is the command that installs the service.
func InstallHint() string {
	return i18n.T("autodpi install (yönetici terminalinde)", "autodpi install (in an administrator terminal)")
}

// ErrNotRoot is Install's and Uninstall's answer without an elevated token.
var ErrNotRoot error = notRoot{}

type notRoot struct{}

func (notRoot) Error() string {
	return i18n.T("bu işlem yönetici (Run as administrator) terminali ister", "this needs an elevated (Run as administrator) terminal")
}

// LogPath is where the installed daemon writes its log.
func LogPath(p paths.Set) string { return p.Log }

func commandLine(exe string, args ...string) string {
	s := syscall.EscapeArg(exe)
	for _, a := range args {
		s += " " + syscall.EscapeArg(a)
	}
	return s
}

// Install copies self into %ProgramData%\AutoDPI (locked down to SYSTEM
// and Administrators, like the root-owned directory on macOS), registers an
// auto-start service running as LocalSystem that the SCM restarts after a
// crash (launchd's KeepAlive), and starts it.
func Install(p paths.Set, self string) error {
	if !sysx.IsRoot() {
		return ErrNotRoot
	}
	if err := prepareRoot(p); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf(i18n.T("hizmet yöneticisine bağlanılamadı: %w", "service manager: %w"), err)
	}
	defer m.Disconnect()

	args := []string{"daemon", "--log-file", p.Log}
	s, err := m.OpenService(paths.ServiceName)
	if err == nil {
		defer s.Close()
		// The running binary is locked: stop it before replacing it.
		if err := stopAndWait(s, 30*time.Second); err != nil {
			return err
		}
	}
	if err := copyExec(self, p.Installed); err != nil {
		return fmt.Errorf(i18n.T("autodpi.exe kurulum klasörüne kopyalanamadı: %w", "install binary: %w"), err)
	}
	if s == nil {
		s, err = m.CreateService(paths.ServiceName, p.Installed, mgr.Config{
			DisplayName:  "AutoDPI",
			Description:  "Local, transparent DPI-bypass service (sing-box TUN + observer).",
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, args...)
		if err != nil {
			return fmt.Errorf(i18n.T("hizmet oluşturulamadı: %w", "create service: %w"), err)
		}
		defer s.Close()
	} else {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		cfg.BinaryPathName = commandLine(p.Installed, args...)
		cfg.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(cfg); err != nil {
			return fmt.Errorf(i18n.T("hizmet güncellenemedi: %w", "update service: %w"), err)
		}
	}
	// The installed executable is the one thing in the locked-down directory
	// ordinary users may read and run (`autodpi status` unelevated).
	if err := sysx.SecureExe(p.Installed); err != nil {
		return fmt.Errorf(i18n.T("%s izinleri ayarlanamadı: %w", "set permissions on %s: %w"), p.Installed, err)
	}
	// KeepAlive + ThrottleInterval 10: restart 10 s after any exit that is
	// not a clean stop, forever (the failure count resets after a day).
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 10 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 86400); err != nil {
		return fmt.Errorf(i18n.T("kurtarma eylemleri ayarlanamadı: %w", "recovery actions: %w"), err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf(i18n.T("çökme dışı hatalarda kurtarma ayarlanamadı: %w", "recovery on non-crash failures: %w"), err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf(i18n.T("hizmet başlatılamadı: %w", "start service: %w"), err)
	}
	return nil
}

// prepareRoot makes the install directory and the control-socket directory
// exist as plain directories that only SYSTEM and Administrators control,
// creating them atomically with their DACL and refusing anything a user
// pre-created (EnsureTrustedDir). It fails closed: the service executes what
// is in there as SYSTEM.
func prepareRoot(p paths.Set) error {
	if err := os.MkdirAll(filepath.Dir(p.Support), 0o755); err != nil {
		return err
	}
	if err := sysx.EnsureTrustedDir(p.Support); err != nil {
		return fmt.Errorf(i18n.T("%s kilitlenemedi: %w", "lock down %s: %w"), p.Support, err)
	}
	// Before the socket got its own directory it sat in the root; a stale file
	// there only gets in the way of tightening the root's DACL.
	_ = os.Remove(filepath.Join(p.Support, "ctl.sock"))
	if dir := filepath.Dir(p.Sock); !strings.EqualFold(dir, p.Support) {
		if err := sysx.EnsureCtlDir(dir); err != nil {
			return fmt.Errorf(i18n.T("kontrol soketi klasörü %s: %w", "control socket directory %s: %w"), dir, err)
		}
	}
	return nil
}

func stopAndWait(s *mgr.Service, timeout time.Duration) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf(i18n.T("hizmet durdurulamadı: %w", "stop service: %w"), err)
		}
	}
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		if st, err = s.Query(); err != nil || st.State == svc.Stopped {
			return err
		}
	}
	return fmt.Errorf(i18n.T("hizmet %s içinde durmadı", "service did not stop within %s"), timeout)
}

// Uninstall stops and deletes the service and removes what Install put
// down. With purge the learned lists go too.
func Uninstall(p paths.Set, purge bool) error {
	if !sysx.IsRoot() {
		return ErrNotRoot
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf(i18n.T("hizmet yöneticisine bağlanılamadı: %w", "service manager: %w"), err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(paths.ServiceName); err == nil {
		stopErr := stopAndWait(s, 30*time.Second)
		delErr := s.Delete()
		s.Close()
		if delErr != nil {
			return fmt.Errorf(i18n.T("hizmet silinemedi: %w", "delete service: %w"), delErr)
		}
		if stopErr != nil {
			return stopErr
		}
	}
	_ = (&sysdns.Manager{File: p.DNSSaved}).Release()
	_ = os.Remove(p.Sock)
	uninstallTray(p)
	sysx.KillOtherInstances() // hidden settings-page servers the menu started
	if purge {
		removeOrDefer(p.Installed) // may be the running CLI itself
		if err := os.RemoveAll(p.Support); err != nil {
			// Only the running CLI, renamed aside, may be left: the
			// directory goes with it at the next reboot.
			left, _ := os.ReadDir(p.Support)
			for _, e := range left {
				if !strings.HasSuffix(e.Name(), asideSuffix) {
					return err
				}
			}
			deleteAtReboot(p.Support)
		}
		return nil
	}
	removeOrDefer(p.Installed)
	_ = os.RemoveAll(p.Bin)
	_ = os.RemoveAll(p.Run)
	if dir := filepath.Dir(p.Sock); !strings.EqualFold(dir, p.Support) {
		_ = os.Remove(dir) // the socket itself went above; only an empty ctl dir goes
	}
	return nil
}

// removeOrDefer deletes path; a running executable cannot be deleted on
// Windows, so it is renamed aside and deleted at the next reboot instead.
func removeOrDefer(path string) {
	if err := os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
		return
	}
	aside := path + asideSuffix
	_ = os.Remove(aside)
	if os.Rename(path, aside) == nil {
		path = aside
	}
	deleteAtReboot(path)
}

const asideSuffix = ".delete-me"

// deleteAtReboot queues path for deletion by the session manager (an empty
// directory works too; queued entries are processed in order).
func deleteAtReboot(path string) {
	if p, err := windows.UTF16PtrFromString(path); err == nil {
		_ = windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
}

// Describe returns the service state, "" when it is not installed. It asks
// for query rights only, so it works from an unelevated shell.
func Describe() string {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return ""
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(paths.ServiceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return ""
	}
	s := &mgr.Service{Name: paths.ServiceName, Handle: h}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return i18n.T("kurulu (durum okunamadı: ", "installed (state unreadable: ") + err.Error() + ")"
	}
	return stateText(stateName(st.State))
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start pending"
	case svc.StopPending:
		return "stop pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue pending"
	case svc.PausePending:
		return "pause pending"
	case svc.Paused:
		return "paused"
	}
	return fmt.Sprintf("state %d", s)
}

// Supervised reports whether the Service Control Manager runs this process: it
// starts the service again after a non-zero exit (the recovery actions Install
// sets).
func Supervised() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// Run runs the daemon body. Started by the SCM, it reports to it and turns
// Stop/Shutdown into the end of ctx; started from a terminal it just runs.
func Run(ctx context.Context, inner func(context.Context) error) error {
	// An elevated daemon on the real install root (service or foreground)
	// first makes sure the directories are ours; the daemon's own lock-down
	// only logs a warning, this refuses to start.
	body := func(ctx context.Context) error {
		if p := paths.Default(); p.System && sysx.IsRoot() {
			if err := prepareRoot(p); err != nil {
				return err
			}
		}
		return inner(ctx)
	}
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return body(ctx)
	}
	h := &handler{parent: ctx, body: body}
	if err := svc.Run(paths.ServiceName, h); err != nil {
		return err
	}
	return h.err
}

type handler struct {
	parent context.Context
	body   func(context.Context) error
	err    error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(h.parent)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.body(ctx) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			// The daemon ended by itself: a non-zero exit makes the SCM apply
			// the recovery actions (restart in 10 s).
			h.err = err
			if err != nil {
				return false, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// The daemon gives the network back first (sing-box down, DNS
				// restored); that takes a few seconds.
				st <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				cancel()
				h.err = <-done
				return false, 0
			}
		}
	}
}

func copyExec(src, dst string) error {
	if abs, err := filepath.EvalSymlinks(src); err == nil {
		src = abs
	}
	if cur, err := filepath.EvalSymlinks(dst); err == nil && strings.EqualFold(cur, src) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := renameRetry(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// renameRetry replaces dst with src. Right after the service stopped, the old
// image may stay locked for a moment (the process object lingers, a virus
// scanner is still looking at the new file): retry the transient sharing
// errors for a few seconds instead of failing the install.
func renameRetry(src, dst string) error {
	var err error
	for i := 0; i < 25; i++ {
		if err = os.Rename(src, dst); err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return err
}
