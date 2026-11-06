//go:build !windows

package audit

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// Collect reads what decides where names resolve. Without root lsof sees only
// the user's own processes: a server of another user goes unnoticed.
func Collect(ctx context.Context) Facts {
	var f Facts
	dir := "/etc/resolver"
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				f.Errors = append(f.Errors, "resolver: "+err.Error())
				continue
			}
			if servers := parseResolverFile(string(b)); len(servers) > 0 {
				f.Policies = append(f.Policies, Policy{Names: normalizeNames([]string{e.Name()}), Servers: servers})
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		f.Errors = append(f.Errors, "resolver: "+err.Error())
	}
	// lsof exits non-zero when it finds nothing, which is the usual answer.
	if path, err := exec.LookPath("lsof"); err == nil {
		out, _ := exec.CommandContext(ctx, path, "-nP", "-iUDP:53", "-iTCP:53", "-Fpcn").Output()
		f.Listeners = parseLsof(string(out))
	}
	if b, err := os.ReadFile("/etc/hosts"); err == nil {
		f.Hosts = parseHosts(string(b))
	} else if !errors.Is(err, os.ErrNotExist) {
		f.Errors = append(f.Errors, "hosts: "+err.Error())
	}
	return f
}
