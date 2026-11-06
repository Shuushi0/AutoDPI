//go:build !windows

package ipc

import "os"

// adminGID is macOS's "admin" group: members may drive the daemon.
const adminGID = 80

func secureSocket(path string) error {
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	_ = os.Chown(path, 0, adminGID) // best effort: only root can
	return nil
}
