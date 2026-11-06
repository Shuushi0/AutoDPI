package hoststate

import (
	"sync"
	"time"
)

// DeadKey names a destination no path could open: the server name the client
// asked for (lower-case SNI, empty when the ClientHello has none) and the ip:port
// it was sent to. A different address of the same name is a different key: one
// broken or rejecting server says nothing about its siblings.
type DeadKey struct{ Host, Dest string }

// Dead is the negative cache: destinations where the direct attempt and an
// engine that did reach the server all failed. For ttl the observer tries such a
// destination directly only, without engines, events or validation. It lives in
// memory, is bounded (two generations of at most limit entries) and forgets on
// its own. All methods are safe for concurrent use.
type Dead struct {
	ttl   time.Duration
	limit int
	now   func() time.Time // replaceable in tests

	mu        sync.RWMutex
	cur, prev map[DeadKey]time.Time // key -> expiry
}

// NewDead returns an empty cache. Entries last ttl; a limit < 1 means 1024.
func NewDead(ttl time.Duration, limit int) *Dead {
	if limit < 1 {
		limit = 1024
	}
	return &Dead{ttl: ttl, limit: limit, now: time.Now, cur: map[DeadKey]time.Time{}}
}

// Has reports whether k is remembered and not yet expired. It is the
// per-connection cost: one read lock and one or two map lookups, no allocation.
func (d *Dead) Has(k DeadKey) bool {
	d.mu.RLock()
	exp, ok := d.cur[k]
	if !ok {
		exp, ok = d.prev[k]
	}
	d.mu.RUnlock()
	return ok && d.now().Before(exp)
}

// Add remembers k for the cache's ttl, renewing an existing entry.
func (d *Dead) Add(k DeadKey) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.cur[k]; !ok && len(d.cur) >= d.limit {
		d.prev, d.cur = d.cur, make(map[DeadKey]time.Time, 64)
	}
	delete(d.prev, k)
	d.cur[k] = d.now().Add(d.ttl)
}

// Forget removes k.
func (d *Dead) Forget(k DeadKey) {
	d.mu.Lock()
	delete(d.cur, k)
	delete(d.prev, k)
	d.mu.Unlock()
}

// Len is the number of live (unexpired) entries.
func (d *Dead) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	now, n := d.now(), 0
	for _, exp := range d.cur {
		if now.Before(exp) {
			n++
		}
	}
	for k, exp := range d.prev {
		if _, dup := d.cur[k]; !dup && now.Before(exp) {
			n++
		}
	}
	return n
}

// Reset forgets everything and returns how many entries were live.
func (d *Dead) Reset() int {
	n := d.Len()
	d.mu.Lock()
	d.cur, d.prev = map[DeadKey]time.Time{}, nil
	d.mu.Unlock()
	return n
}
