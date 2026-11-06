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
	"strings"
	"text/template"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/sysdns"
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

// Render returns the launchd property list for the installed binary.
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
	if err := copyExec(self, p.Installed); err != nil {
		return fmt.Errorf(i18n.T("autodpi kurulum klasörüne kopyalanamadı: %w", "install binary: %w"), err)
	}

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

	_, _ = launchctl("bootout", target())      // replace a running instance
	for i := 0; i < 50 && Print() != ""; i++ { // bootout returns before the job is gone
		time.Sleep(200 * time.Millisecond)
	}
	if out, err := launchctl("bootstrap", "system", paths.Plist); err != nil {
		return fmt.Errorf(i18n.T("launchctl bootstrap başarısız: %v: %s", "launchctl bootstrap: %v: %s"), err, out)
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
	_, _ = launchctl("bootout", target())
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
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func writeRoot(path string, b []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, b, mode); err != nil {
		return err
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
