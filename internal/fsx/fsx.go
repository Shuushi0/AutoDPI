// Package fsx writes files so that a power cut leaves either the old content
// or the new, never half of one or an empty file: written beside the target,
// forced to disk, renamed over it, and the directory forced to disk too.
// A rename alone is not enough; what was written and never synced can read
// back empty after the journal replays the rename.
package fsx

import (
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// WriteFile replaces path with data in one step (see the package comment).
// The temporary file has a name of its own in the same folder: with one fixed
// name, two writers (the service and an install run by hand) would write
// into the same file and one of them rename the other's half.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(perm)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	SyncDir(filepath.Dir(path))
	return nil
}

// Rename is os.Rename, retried for a second on Windows: there it fails with a
// sharing violation while another program (an antivirus scanning what was
// just written, the reader of the file being replaced) has either file open.
func Rename(from, to string) error {
	err := os.Rename(from, to)
	for i := 0; err != nil && runtime.GOOS == "windows" && i < 20; i++ {
		if _, serr := os.Lstat(from); serr != nil {
			break // nothing to move: waiting will not change that
		}
		time.Sleep(50 * time.Millisecond)
		err = os.Rename(from, to)
	}
	return err
}

// SyncFile forces a file that was written some other way to disk.
func SyncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// SyncDir forces a directory's entries (the renames in it) to disk. Best
// effort, and nothing on Windows, which has no such call for a directory.
func SyncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
