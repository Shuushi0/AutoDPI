//go:build !windows

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The health check's own connections go through the observer and count as
// flows. They used to make the next pass see "traffic", skip its check and
// clear the failures, so a capture that passed nothing was released after
// seven minutes instead of a minute and a half.
func TestFailingChecksAreNotHiddenByTheirOwnFlows(t *testing.T) {
	d, f := rig(t, Options{})
	var flows int64
	d.sys.flows = func() int64 { return flows }
	healthy := d.sys.healthy
	d.sys.healthy = func(ctx context.Context) error {
		flows += 2 // the observer self-test, as the real check does
		return healthy(ctx)
	}
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.capErr = errors.New("TLS through the capture: reset") })
	for i := 1; i <= 3; i++ {
		pass(t, d)
		if d.badChecks != i {
			t.Fatalf("after %d failed checks the count is %d: a check was skipped or the failures were cleared", i, d.badChecks)
		}
	}
}

// An engine whose port changed after the capture was built (ciadpi's, taken
// by another program while it was down) is one sing-box still reaches at the
// old port: the capture is built again.
func TestCaptureIsRebuiltWhenAnEnginePortChanges(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	d.engGen.Add(1)
	pass(t, d)
	if d.running() {
		t.Fatal("the capture kept running with a stale engine port")
	}
	pass(t, d)
	if !d.running() || f.get().starts != 2 || d.sbEngGen != d.engGen.Load() {
		t.Fatalf("not rebuilt: running=%v starts=%d", d.running(), f.get().starts)
	}
}

// A link that drops for a moment again and again (weak Wi-Fi, a phone
// hotspot) with a capture that passes nothing: every return of the route
// used to clear the run of failed checks, and the capture was never given
// back. Seen as the precondition in a real log: the route going and coming
// back 6 to 20 seconds apart.
func TestRouteFlappingDoesNotDefeatFailOpen(t *testing.T) {
	d, f := rig(t, Options{})
	engage(t, d, f)
	f.set(func(f *fakeSys) { f.capErr = errors.New("TLS through the capture: reset") })
	pass(t, d) // the first failed check
	d.badSince = time.Now().Add(-failOpenAfter)
	for i := 0; i < 6 && d.running(); i++ {
		f.set(func(f *fakeSys) { f.net.Online, f.iface = false, "" }) // gone for one pass
		pass(t, d)
		f.set(func(f *fakeSys) { f.net.Online, f.iface = true, "en0" })
		pass(t, d)
	}
	if d.running() {
		t.Fatalf("the broken capture was never released (badChecks=%d)", d.badChecks)
	}
}

// A clock set back while a wait runs: the wait starts over at its own length
// instead of growing by the size of the step.
func TestAClockSetBackDoesNotStretchTheWait(t *testing.T) {
	d, f := rig(t, Options{})
	f.set(func(f *fakeSys) { f.healthErr = errors.New("DoH (all resolvers): timeout") })
	pass(t, d)
	if d.standbyFails != 1 {
		t.Fatalf("setup: standbyFails=%d", d.standbyFails)
	}
	d.standbyAt = d.standbyAt.Add(time.Hour) // as if the clock went back an hour
	pass(t, d)
	if left := wallUntil(d.standbyAt); left > standbyMost {
		t.Fatalf("the next check is %s away", left.Round(time.Second))
	}
	d.retryAt, d.retryWait = time.Now().Round(0).Add(time.Hour+30*time.Second), 30*time.Second
	f.set(func(f *fakeSys) { f.healthErr = nil })
	pass(t, d)
	if left := wallUntil(d.retryAt); left > 30*time.Second {
		t.Fatalf("the next attempt is %s away", left.Round(time.Second))
	}
}
