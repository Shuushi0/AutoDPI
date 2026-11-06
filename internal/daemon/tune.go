package daemon

import (
	"os"
	"runtime/debug"
)

// The helpers are Go programs too and, left alone, let their heaps grow to
// twice the live size before collecting. Idle machines should not pay for that.
// A GOGC/GOMEMLIMIT already present in the daemon's environment wins, so the
// numbers can still be overridden from the launchd plist.
const (
	gcPercent = 50
	memLimit  = 40 << 20 // daemon: soft limit, the GC works harder near it
)

// TuneRuntime sets the daemon's own GC pacing.
func TuneRuntime() {
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(gcPercent)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
}

// helperGoEnv is the extra environment for sing-box: the same pacing, as the
// variables its Go runtime reads at start.
func helperGoEnv() []string {
	var env []string
	if os.Getenv("GOGC") == "" {
		env = append(env, "GOGC=50")
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		env = append(env, "GOMEMLIMIT=48MiB")
	}
	return env
}
