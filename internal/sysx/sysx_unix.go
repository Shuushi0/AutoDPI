//go:build !windows

package sysx

import (
	"os"
	"os/exec"
	"regexp"
)

// AdminHint is how the user gets the privileges IsRoot asks for.
func AdminHint() string { return "sudo" }

// IsRoot reports whether the process may install the service and drive a TUN.
func IsRoot() bool { return os.Geteuid() == 0 }

// SecureDir is a no-op on macOS: the install directory is chowned to root by
// the installer and created 0755 by the daemon, which runs as root.
func SecureDir(string) error { return nil }

// ShareConfig is a no-op on macOS: config.json is written 0644 (readable by
// everyone, changed by root only).
func ShareConfig(string) error { return nil }

// OwnByRoot hands path to root:wheel (only root can).
func OwnByRoot(path string) error { return os.Chown(path, 0, 0) }

// KillByPath SIGKILLs every process whose command line contains one of paths.
// It reports the paths that matched something.
func KillByPath(paths ...string) []string {
	var hit []string
	for _, p := range paths {
		if err := exec.Command("/usr/bin/pkill", "-9", "-f", regexp.QuoteMeta(p)).Run(); err == nil {
			hit = append(hit, p)
		}
	}
	return hit
}

// ProcessRunning reports whether a process whose command line matches name runs.
func ProcessRunning(name string) bool {
	out, _ := exec.Command("/usr/bin/pgrep", "-f", name).Output()
	return len(out) > 0
}

// ConflictingTool returns the name of a running DPI-bypass program that works
// on the same packets. None is known on macOS: the tools there are proxies,
// not packet rewriters.
func ConflictingTool() (string, bool) { return "", false }
