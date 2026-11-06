package daemon

import (
	"sync"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/netx"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
)

// Asking the system about routes means running route(8) and netstat(1), each a
// new process. The capture loop wants those answers every few seconds, but they
// only change when the routing table does. A memo keeps an answer until the
// route-change generation moves (netx.WatchRoutes) or the cache lifetime ends:
// 30s with change notifications behind it, the old 2s without.
type memo[T any] struct {
	mu  sync.Mutex
	fn  func() T
	gen uint64
	at  time.Time
	ok  bool
	v   T
}

func (m *memo[T]) get() T {
	m.mu.Lock()
	defer m.mu.Unlock()
	gen := netx.RouteGen() // read first: a change during fn() makes the stored answer stale at once
	if m.ok && m.gen == gen && time.Since(m.at) < netx.CacheTTL(2*time.Second) {
		return m.v
	}
	v := m.fn()
	m.v, m.gen, m.at, m.ok = v, gen, time.Now(), true
	return v
}

type routeRes struct {
	iface, gateway string
	err            error
}

type routeMemo struct{ m memo[routeRes] }

func newRouteCache() *routeMemo {
	return &routeMemo{memo[routeRes]{fn: func() routeRes {
		i, g, err := netx.DefaultRoute()
		return routeRes{i, g, err}
	}}}
}

func (r *routeMemo) get() (string, string, error) {
	v := r.m.get()
	return v.iface, v.gateway, v.err
}

type foreignRes struct {
	iface string
	found bool
}

type foreignMemo struct{ m memo[foreignRes] }

func newForeignCache() *foreignMemo {
	return &foreignMemo{memo[foreignRes]{fn: func() foreignRes {
		i, f := netx.ForeignTunnel(singbox.TunIP)
		return foreignRes{i, f}
	}}}
}

func (f *foreignMemo) get() (string, bool) {
	v := f.m.get()
	return v.iface, v.found
}
