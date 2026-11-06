//go:build !windows

package service

import (
	"context"
	"os"
	"strings"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/launchd"
	"github.com/Shuushi0/AutoDPI/internal/paths"
)

// Kind names the service manager entry in doctor's output.
func Kind() string { return i18n.T("launchd görevi", "launchd job") }

// InstallHint is the command that installs the service.
func InstallHint() string { return "sudo autodpi install" }

// LogPath is where the installed daemon writes its log.
func LogPath(paths.Set) string { return launchd.DaemonLog }

func Install(p paths.Set, self string) error { return launchd.Install(p, self) }

func Uninstall(p paths.Set, purge bool) error { return launchd.Uninstall(p, purge) }

// InstallTray has nothing to do on macOS: the menu bar app is an .app the
// user copies to /Applications.
func InstallTray(paths.Set, string) error { return ErrTrayAbsent }

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
