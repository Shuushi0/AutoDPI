//go:build !windows

package service

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/launchd"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/update"
)

// Kind names the service manager entry in doctor's output.
func Kind() string { return i18n.T("launchd görevi", "launchd job") }

// InstallHint is the command that installs the service.
func InstallHint() string { return "sudo autodpi install" }

// LogPath is where the installed daemon writes its log.
func LogPath(paths.Set) string { return launchd.DaemonLog }

func Install(p paths.Set, self string) error { return launchd.Install(p, self) }

func Uninstall(p paths.Set, purge bool) error { return launchd.Uninstall(p, purge) }

// runApp runs the commands that restart the menu bar app; tests replace it.
var runApp = func(name string, args ...string) error { return exec.Command(name, args...).Run() }

// InstallTray puts the menu bar app from next to self into /Applications. The
// running copy is closed only after the new one is in place, so a failed copy
// leaves it alone. It reports ErrTrayAbsent when there is nothing to install,
// as with `sudo autodpi install` from the installed binary.
func InstallTray(_ paths.Set, self string) error {
	src := filepath.Join(filepath.Dir(self), filepath.Base(update.AppPath))
	if _, err := os.Stat(src); err != nil || src == update.AppPath {
		return ErrTrayAbsent
	}
	if err := update.ReplaceTree(src, update.AppPath); err != nil {
		return err
	}
	if uid, user := sudoUser(); user != "" {
		update.ChownTree(update.AppPath, uid) // theirs to delete, like a dragged copy
		restartApp(uid, user)
	}
	return nil
}

// TrayInstalledText is what install says once the app is in place.
func TrayInstalledText() string {
	return i18n.T("menü çubuğu uygulaması kuruldu: ", "menu bar app installed: ") + update.AppPath
}

// TrayFailedText is install's warning when the app could not be put in place.
func TrayFailedText() string {
	return i18n.T("menü çubuğu uygulaması kurulamadı", "the menu bar app was not installed")
}

// sudoUser is the person behind sudo; "" for a plain root shell, where there
// is no way to tell whose session the app belongs in.
func sudoUser() (int, string) {
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	user := os.Getenv("SUDO_USER")
	if err != nil || uid <= 0 || user == "" {
		return 0, ""
	}
	return uid, user
}

// restartApp closes the running copy and opens the new one in the user's
// session and as the user, never as root. A failure is not worth a warning:
// the app is installed and opens from /Applications.
func restartApp(uid int, user string) {
	running := "^" + regexp.QuoteMeta(update.AppPath) + "/Contents/MacOS/"
	if runApp("/usr/bin/pkill", "-f", running) == nil {
		// open would only bring a copy that is still closing to the front.
		for range 30 {
			if runApp("/usr/bin/pgrep", "-f", running) != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	_ = runApp("/bin/launchctl", "asuser", strconv.Itoa(uid), "/usr/bin/sudo", "-u", user, "/usr/bin/open", update.AppPath)
}

// Describe returns the job's state, "" when it is not installed.
func Describe() string {
	jp := launchd.Print()
	if jp == "" {
		return ""
	}
	if st := jobState(jp); st != "" {
		return stateText(st)
	}
	return i18n.T("yüklü", "loaded")
}

// jobState picks the job's own state ("running") out of `launchctl print`:
// the line indented by exactly one tab. Nested blocks (resource and jetsam
// coalitions) have "state =" lines of their own.
func jobState(print string) string {
	for _, ln := range strings.Split(print, "\n") {
		if v, ok := strings.CutPrefix(ln, "\tstate ="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// Supervised reports whether launchd runs this process as the installed job,
// which it starts again after a non-zero exit (KeepAlive). launchd sets
// XPC_SERVICE_NAME to the job's label; a shell has it unset, Terminal sets it
// to "0".
func Supervised() bool { return os.Getenv("XPC_SERVICE_NAME") == paths.Label }

// Run runs the daemon body. launchd needs nothing special: it signals the
// process, which ends ctx.
func Run(ctx context.Context, body func(context.Context) error) error { return body(ctx) }
