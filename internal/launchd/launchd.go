//go:build !windows

package launchd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fsx"
	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/sysdns"
	"github.com/Shuushi0/AutoDPI/internal/update"
)

// xmlText escapes s for the text of a plist <string>: only & < > need it.
var xmlText = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace

var plistTmpl = template.Must(template.New("plist").Funcs(template.FuncMap{"xml": xmlText}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{xml .Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{xml .Binary}}</string>
		<string>daemon</string>
		<string>--log-file</string>
		<string>{{xml .Log}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ExitTimeOut</key>
	<integer>20</integer>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardErrorPath</key>
	<string>{{xml .Crash}}</string>
	<key>StandardOutPath</key>
	<string>{{xml .Crash}}</string>
	<key>SoftResourceLimits</key>
	<dict>
		<key>NumberOfFiles</key>
		<integer>16384</integer>
	</dict>
	<key>HardResourceLimits</key>
	<dict>
		<key>NumberOfFiles</key>
		<integer>16384</integer>
	</dict>
</dict>
</plist>
`))

// DaemonLog is where the daemon writes its own rotating log.
const (
	DaemonLog = "/var/log/autodpi.log"
	CrashLog  = "/var/log/autodpi.crash.log"
)

// ErrNotRoot is Install's and Uninstall's answer without root.
var ErrNotRoot error = notRoot{}

type notRoot struct{}

func (notRoot) Error() string {
	return i18n.T("bu işlem root yetkisi ister: sudo ile çalıştırın", "this needs root: run it with sudo")
}

func target() string { return "system/" + paths.Label }

func launchctl(args ...string) (string, error) {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Refresh writes the job's property list again when it is not what this
// version would write. A copy that updated itself never runs Install, so a
// change to the list (ExitTimeOut) would otherwise never reach it. launchd
// reads the file when it loads the job: this takes effect at the next boot.
func Refresh(p paths.Set) {
	if os.Geteuid() != 0 {
		return
	}
	want, err := Render(p.Installed)
	if err != nil {
		return
	}
	if have, err := os.ReadFile(paths.Plist); err != nil || bytes.Equal(have, want) {
		return // not installed as a job, or already the same
	}
	_ = writeRoot(paths.Plist, want, 0o644)
}

// Render returns the launchd property list for the installed binary.
//
// ExitTimeOut: launchd's default is 5 seconds between SIGTERM and SIGKILL,
// which a stop that has to wait for a helper does not always make (measured:
// 9.7 s with a frozen guard); killed there, the resolver was not given back
// until the next start. The daemon's own limit (shutdownMax) is below it.
func Render(binary string) ([]byte, error) {
	var b bytes.Buffer
	err := plistTmpl.Execute(&b, map[string]string{
		"Label": paths.Label, "Binary": binary, "Log": DaemonLog, "Crash": CrashLog,
	})
	return b.Bytes(), err
}

// Install copies self into the root-owned support directory, writes the plist
// and (re)starts the job. The binary must live somewhere only root can write:
// launchd runs it as root.
func Install(p paths.Set, self string) error {
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}
	if err := os.MkdirAll(p.Support, 0o755); err != nil {
		return err
	}
	if err := os.Chown(p.Support, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(p.Support, 0o755); err != nil {
		return err
	}
	// The running service goes first, and is waited for until its process
	// has ended. It used to be replaced under its own feet: an update it was
	// in the middle of could then land on the copy being installed, and at
	// its shutdown it wrote its update record back after this had cleared it.
	stopJob()
	if err := copyExec(self, p.Installed); err != nil {
		// The version that was there, running again, not a stopped service.
		if _, serr := os.Stat(paths.Plist); serr == nil {
			_, _ = launchctl("bootstrap", "system", paths.Plist)
		}
		return fmt.Errorf(i18n.T("autodpi kurulum klasörüne kopyalanamadı: %w", "install binary: %w"), err)
	}
	// Whoever installs by hand has decided which version runs: an update
	// still waiting to be confirmed must not take it back later. The daemon
	// is down here, so nothing else is writing the record.
	update.Forget(p)

	plist, err := Render(p.Installed)
	if err != nil {
		return err
	}
	if err := writeRoot(paths.Plist, plist, 0o644); err != nil {
		return fmt.Errorf(i18n.T("launchd tanımı (plist) yazılamadı: %w", "write plist: %w"), err)
	}

	// The convenience symlink: created when there is none. Whatever else sits
	// there (a file, a link to another install such as a package manager's) is
	// not ours to replace.
	if _, err := os.Lstat(paths.Link); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(paths.Link), 0o755); err == nil {
			_ = os.Symlink(p.Installed, paths.Link)
		}
	}

	// bootstrap fails with "Input/output error" while launchd is still
	// letting go of the old job, which stopJob's wait does not always see.
	// Without the service loaded nothing would start it again, not even a
	// reboot: tried a few times before giving up. Only bootstrap's own
	// success counts along the way (a job still listed may be the old one
	// on its way out); after the last try, a job that is loaded is enough.
	var out string
	var berr error
	for i := 0; i < 5; i++ {
		if out, berr = launchctl("bootstrap", "system", paths.Plist); berr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if berr != nil && Print() != "" {
		berr = nil
	}
	if berr != nil {
		err, out := berr, out
		return fmt.Errorf(i18n.T("servis launchd'ye yüklenemedi (%v: %s). Dosyalar yerinde; aynı komutu yeniden çalıştırın, olmazsa bilgisayarı yeniden başlatıp bir daha deneyin",
			"the service could not be loaded into launchd (%v: %s). The files are in place; run the same command again, and if that fails restart the computer and try once more"), err, out)
	}
	_, _ = launchctl("enable", target())
	// RunAtLoad already started it; kickstart without -k only starts a job
	// that is not running (with -k it killed the fresh instance and the
	// network blinked twice during install).
	if out, err := launchctl("kickstart", target()); err != nil {
		return fmt.Errorf(i18n.T("launchctl kickstart başarısız: %v: %s", "launchctl kickstart: %v: %s"), err, out)
	}
	return nil
}

// Uninstall stops the job and removes what Install put down. With purge the
// learned lists go too.
func Uninstall(p paths.Set, purge bool) error {
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}
	stopJob()
	// An update waiting to be confirmed ends here, with the copies it kept:
	// its record would otherwise meet the next install.
	update.Forget(p)
	// The daemon restores the resolver when it stops; this covers one that
	// died holding it.
	_ = (&sysdns.Manager{File: p.DNSSaved}).Release()
	_ = os.Remove(paths.Plist)
	if dst, err := os.Readlink(paths.Link); err == nil && dst == p.Installed {
		_ = os.Remove(paths.Link)
	}
	_ = os.Remove(p.Sock)
	if purge {
		return os.RemoveAll(p.Support)
	}
	_ = os.Remove(p.Installed)
	_ = os.RemoveAll(p.Bin)
	_ = os.RemoveAll(p.Run)
	return nil
}

// stopJob unloads the job and waits until launchd no longer lists it and its
// process has ended. bootout returns before either; the daemon gives the
// network back and saves its state on the way out, which takes seconds and,
// when something hangs, up to its own limit of a minute. One that is still
// there after that is ended.
func stopJob() {
	pid := jobPID(Print())
	_, _ = launchctl("bootout", target())
	for i := 0; i < 50 && Print() != ""; i++ {
		time.Sleep(200 * time.Millisecond)
	}
	if pid <= 1 {
		return
	}
	for i := 0; i < 350; i++ { // 70 s
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	time.Sleep(500 * time.Millisecond)
}

// jobPID picks the job's process id out of `launchctl print`: the "pid ="
// line indented by exactly one tab. 0 when the job is not running.
func jobPID(print string) int {
	for _, ln := range strings.Split(print, "\n") {
		if v, ok := strings.CutPrefix(ln, "\tpid ="); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

// Print returns launchctl's view of the job, "" when it is not loaded.
func Print() string {
	out, err := launchctl("print", target())
	if err != nil {
		return ""
	}
	return out
}

func copyExec(src, dst string) error {
	if abs, err := filepath.EvalSymlinks(src); err == nil {
		src = abs
	}
	if cur, err := filepath.EvalSymlinks(dst); err == nil && cur == src {
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
	// To disk before the rename: after a power cut the rename can be there
	// and the content not, and launchd would be starting an empty file.
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	fsx.SyncDir(filepath.Dir(dst))
	return nil
}

// writeRoot replaces path in one step: a half-written plist is a service
// launchd refuses to load at the next boot.
func writeRoot(path string, b []byte, mode os.FileMode) error {
	if err := fsx.WriteFile(path, b, mode); err != nil {
		return err
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
