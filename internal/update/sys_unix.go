//go:build !windows

package update

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func hide(*exec.Cmd) {}

// matchOwner gives the new copy the owner of the one it replaces: an app the
// user dragged to /Applications stays theirs to delete, though root writes it.
func matchOwner(old, fresh string) {
	fi, err := os.Stat(old)
	if err != nil {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = filepath.WalkDir(fresh, func(p string, _ fs.DirEntry, err error) error {
		if err == nil {
			_ = os.Lchown(p, int(st.Uid), int(st.Gid))
		}
		return nil
	})
}
