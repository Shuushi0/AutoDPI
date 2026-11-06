package netx

import (
	"context"
	"sync/atomic"
	"time"
)

// Route-table change notifications let the daemon stop asking the system
// (route(8), netstat(1): each a fresh process) every few seconds whether
// anything changed. When no notification source is available (non-macOS, or
// the routing socket cannot be opened) everything behaves as before: short
// cache lifetimes and frequent polling.

var routeWatch struct {
	gen    atomic.Uint64
	active atomic.Bool
}

// RouteGen counts the route/interface changes seen so far; a cached value taken
// at the same generation is still valid.
func RouteGen() uint64 { return routeWatch.gen.Load() }

// RouteEventsActive reports whether changes are being delivered.
func RouteEventsActive() bool { return routeWatch.active.Load() }

// CacheTTL is how long a route-derived value may be reused: long while change
// notifications guard it (they invalidate through RouteGen), the short fallback
// otherwise.
func CacheTTL(fallback time.Duration) time.Duration {
	if RouteEventsActive() {
		return 30 * time.Second
	}
	return fallback
}

// WatchRoutes starts listening for route and interface changes until ctx ends.
// The returned channel receives a (coalesced) pulse per burst of changes; it is
// nil when notifications are not available.
func WatchRoutes(ctx context.Context) <-chan struct{} {
	pulses := make(chan struct{}, 1)
	if err := watchRoutes(ctx, func() {
		routeWatch.gen.Add(1)
		select {
		case pulses <- struct{}{}:
		default:
		}
	}); err != nil {
		return nil
	}
	routeWatch.active.Store(true)
	go func() {
		<-ctx.Done()
		routeWatch.active.Store(false)
	}()
	return pulses
}
