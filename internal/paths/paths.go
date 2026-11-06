// Package paths centralises every on-disk and socket location the service uses.
package paths

import (
	"os"
	"path/filepath"
)

type Set struct {
	Support   string // root-owned install root
	Bin       string // extracted helper binaries (sing-box, ciadpi)
	Run       string // generated sing-box config and rule-sets
	State     string // persistent per-network lists
	Config    string // optional user overrides
	DNSSaved  string // the user's resolver settings while the daemon holds them
	Sock      string // control socket
	Log       string
	Installed string // installed copy of the autodpi binary
	// System is set for the real install root (not AUTODPI_HOME): only
	// then may the daemon lock the directory down to administrators.
	System bool
}

// Default honours AUTODPI_HOME so tests and dev runs can live in a scratch
// directory instead of the system location.
func Default() Set {
	if home := os.Getenv("AUTODPI_HOME"); home != "" {
		return under(home, filepath.Join(home, "ctl.sock"), filepath.Join(home, "daemon.log"))
	}
	s := systemDefault()
	s.System = true
	return s
}

func under(root, sock, log string) Set {
	return Set{
		Support:   root,
		Bin:       filepath.Join(root, "bin"),
		Run:       filepath.Join(root, "run"),
		State:     filepath.Join(root, "state.json"),
		Config:    filepath.Join(root, "config.json"),
		DNSSaved:  filepath.Join(root, "dns-saved.json"),
		Sock:      sock,
		Log:       log,
		Installed: filepath.Join(root, "autodpi"+exeSuffix),
	}
}
