// Package logx is a size-capped log file: launchd never rotates what it
// redirects, so the daemon keeps its own.
package logx

import (
	"os"
	"sync"
)

type Rotating struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

// Open appends to path, keeping at most one previous generation (path.1).
func Open(path string, max int64) (*Rotating, error) {
	r := &Rotating{path: path, max: max}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Rotating) open() error {
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}

func (r *Rotating) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > r.max {
		r.f.Close()
		_ = os.Rename(r.path, r.path+".1")
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *Rotating) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
