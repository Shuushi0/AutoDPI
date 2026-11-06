//go:build !windows

package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// While real flows keep going through the capture, the active probe (DoH plus
// TLS handshakes) runs only every probeEvery; without traffic it runs every
// health check, and a failing probe still counts.
func TestTrafficReplacesActiveProbes(t *testing.T) {
	d, f := rig(t, Options{})
	var flows atomic.Int64
	var probes atomic.Int64
	d.sys.flows = flows.Load
	d.sys.healthy = func(context.Context) error {
		probes.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.healthErr
	}

	pass(t, d) // engage (the pre-engage check probes too)
	pass(t, d) // first check verifies the capture: always active
	if !d.verified {
		t.Fatal("capture not verified")
	}
	base := probes.Load()

	for i := 0; i < 5; i++ { // traffic flows: no probing
		flows.Add(3)
		pass(t, d)
	}
	if n := probes.Load() - base; n != 0 {
		t.Fatalf("probed %d times while traffic flowed, want none", n)
	}

	pass(t, d) // idle: nothing new carried, so probe actively again
	if n := probes.Load() - base; n != 1 {
		t.Fatalf("idle pass: %d probes, want 1", n)
	}

	d.lastProbe = time.Now().Add(-probeEvery - time.Second) // traffic, but the last probe is old
	flows.Add(1)
	pass(t, d)
	if n := probes.Load() - base; n != 2 {
		t.Fatalf("after probeEvery with traffic: %d probes, want 2", n)
	}

	// A broken path carries nothing, so failures are seen and counted.
	f.set(func(f *fakeSys) { f.healthErr = errors.New("down") })
	pass(t, d)
	if d.badChecks != 1 {
		t.Fatalf("badChecks=%d after an idle failing probe, want 1", d.badChecks)
	}
}
