package daemon

import (
	"fmt"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/domain"
	"github.com/Shuushi0/AutoDPI/internal/hoststate"
	"github.com/Shuushi0/AutoDPI/internal/observer"
)

// The "open" state: a hostname that opened
// directly three times in a row on a network is relayed by the observer in its
// light mode until a connection to it fails. It lives in memory only, one small
// bounded table per network; nothing about it is written to disk.

// maxCaches bounds how many networks' tables are kept.
const maxCaches = 32

// netCache is the table of the network the Mac is on now, as the observer's
// hot path sees it: one atomic load, no lock.
type netCache struct {
	key   string
	c     *hoststate.Cache
	since time.Time // events of flows that began earlier belong to another network
}

// cacheFor returns the table of network key, creating it.
func (d *Daemon) cacheFor(key string) *hoststate.Cache {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c := d.caches[key]; c != nil {
		return c
	}
	if d.caches == nil || len(d.caches) >= maxCaches {
		d.caches = map[string]*hoststate.Cache{}
	}
	c := hoststate.New()
	d.caches[key] = c
	return c
}

// useNetwork points the observer at network key's table.
func (d *Daemon) useNetwork(key string) {
	if key == "" {
		d.openCur.Store(nil)
		return
	}
	if cur := d.openCur.Load(); cur != nil && cur.key == key {
		return
	}
	d.openCur.Store(&netCache{key: key, c: d.cacheFor(key), since: time.Now()})
}

// dropCache forgets a network's table (a provisional key that was folded into
// the stable one).
func (d *Daemon) dropCache(key string) {
	d.mu.Lock()
	delete(d.caches, key)
	d.mu.Unlock()
}

// mode is the observer's per-flow question. sni is lower-case already.
func (d *Daemon) mode(sni string) observer.Mode {
	if cur := d.openCur.Load(); cur != nil && cur.c.Light(sni) {
		return observer.Light
	}
	return observer.Full
}

// trackOpen turns the observer's verdicts into the open state: the third
// direct connection in a row opens a name, a failed or repaired one forgets it.
// Only the exact name counts: nothing is inferred about sibling names.
func (d *Daemon) trackOpen(ev observer.Event) {
	if ev.SNI == "" {
		return
	}
	cur := d.openCur.Load()
	if cur == nil || ev.Time.Before(cur.since) {
		return
	}
	if host, ok := domain.Normalize(ev.SNI); !ok || host != ev.SNI {
		return
	}
	if net := d.sys.network(); net.Key != cur.key || !net.Online {
		return // offline, every failure looks alike
	}
	// Only the in-memory count changes: a name becoming or staying open is not
	// journalled, logged or written anywhere (a blocked connection that closes
	// it is journalled by onEvent as repaired).
	switch ev.Outcome {
	case observer.Direct:
		cur.c.Direct(ev.SNI)
	case observer.Fallback, observer.Failed:
		cur.c.Failed(ev.SNI)
	}
}

// openCount is the number of open names on the current network.
func (d *Daemon) openCount() int {
	if cur := d.openCur.Load(); cur != nil {
		return cur.c.Len()
	}
	return 0
}

func (d *Daemon) openReset() (map[string]any, error) {
	cur := d.openCur.Load()
	if cur == nil {
		return nil, errNoNetwork
	}
	n := cur.c.Reset()
	d.logOnly("open-reset", cur.key, fmt.Sprintf("%d names forgotten", n))
	return map[string]any{"removed": n, "network": cur.key}, nil
}
