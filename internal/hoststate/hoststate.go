// Package hoststate remembers, in memory only, which exact host names have
// been opening directly on one network. A name that opened directly Promote
// times in a row is "open": the observer then handles it in its light mode (one
// direct attempt, no hedging, no events) until a connection to it fails, which
// forgets it again. Nothing is persisted: after a restart each name has to
// earn the state back with three direct connections.
package hoststate

import "sync"

// Promote is how many direct connections in a row make a name open.
const Promote = 3

// Limit bounds each of the two generations; when the current one is full the
// older one is dropped. Forgetting a name only delays its promotion.
const Limit = 4096

// Cache is one network's table. All methods are safe for concurrent use.
type Cache struct {
	mu        sync.RWMutex
	cur, prev map[string]uint8 // host -> consecutive direct connections, capped at Promote
}

func New() *Cache {
	return &Cache{cur: map[string]uint8{}}
}

// Light reports whether host is open. The name must be lower-case, which an
// SNI from sni.Parse is. It takes one read lock and does one or two map
// lookups: this is the per-connection cost of an open name.
func (c *Cache) Light(host string) bool {
	c.mu.RLock()
	n, ok := c.cur[host]
	if !ok {
		n = c.prev[host]
	}
	c.mu.RUnlock()
	return n >= Promote
}

// Direct records a connection that opened directly and reports whether it just
// made host open.
func (c *Cache) Direct(host string) (promoted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.cur[host]
	if !ok {
		if n, ok = c.prev[host]; ok {
			delete(c.prev, host)
		}
	}
	if n >= Promote {
		c.put(host, n)
		return false
	}
	n++
	c.put(host, n)
	return n == Promote
}

// put stores n for host in the current generation, rotating when it is full.
func (c *Cache) put(host string, n uint8) {
	if _, ok := c.cur[host]; !ok && len(c.cur) >= Limit {
		c.prev, c.cur = c.cur, make(map[string]uint8, 64)
	}
	c.cur[host] = n
}

// Failed forgets host (a connection to it failed or needed repair) and reports
// whether it was open.
func (c *Cache) Failed(host string) (wasOpen bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wasOpen = c.cur[host] >= Promote || c.prev[host] >= Promote
	delete(c.cur, host)
	delete(c.prev, host)
	return wasOpen
}

// Len is the number of open names.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := 0
	for _, v := range c.cur {
		if v >= Promote {
			n++
		}
	}
	for h, v := range c.prev {
		if _, dup := c.cur[h]; !dup && v >= Promote {
			n++
		}
	}
	return n
}

// Reset forgets everything and returns how many names were open.
func (c *Cache) Reset() int {
	n := c.Len()
	c.mu.Lock()
	c.cur, c.prev = map[string]uint8{}, nil
	c.mu.Unlock()
	return n
}
