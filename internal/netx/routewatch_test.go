package netx

import (
	"context"
	"testing"
	"time"
)

func TestWatchRoutesLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := WatchRoutes(ctx)
	if ch == nil {
		t.Skip("no route notifications on this platform")
	}
	if !RouteEventsActive() || CacheTTL(time.Second) <= time.Second {
		t.Fatal("watching should lengthen cache lifetimes")
	}
	cancel()
	for i := 0; i < 100 && RouteEventsActive(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if RouteEventsActive() || CacheTTL(time.Second) != time.Second {
		t.Fatal("cache lifetimes must fall back once the watch ends")
	}
}
