//go:build !windows

package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// A captive portal, or a network that blocks the DoH servers: the plumbing
// check fails. How often does the engage loop run it (each one a DoH query
// per server and TLS handshakes) while it waits in standby?
func TestRegressStandbyHealthProbeRate(t *testing.T) {
	d, _ := rig(t, Options{})
	var calls atomic.Int32
	d.sys.healthy = func(ctx context.Context) error {
		calls.Add(1)
		select { // DoH to a blocked resolver: each attempt runs into its timeout
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
		return errors.New("DoH (all resolvers): context deadline exceeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	d.engageLoop(ctx)
	s, det := state(d)
	t.Logf("12s in standby: %d plumbing checks (%s: %s)", calls.Load(), s, det)
	if calls.Load() > 2 {
		t.Errorf("%d checks in 12s with no backoff: every pass re-probes a network that keeps failing", calls.Load())
	}
}
