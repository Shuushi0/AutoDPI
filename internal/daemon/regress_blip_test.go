//go:build !windows

package daemon

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/sysdns"
)

// R4: what a default-route blip shorter than offlineRelease changes in the
// daemon. Time is scaled 1:100 (offlineRelease 600ms stands for 60s, a pass
// every 30ms for the 3s ticker).
func blipRig(t *testing.T, blip time.Duration, after func(f *fakeSys)) (d *Daemon, f *fakeSys, rep string) {
	t.Helper()
	old := offlineRelease
	offlineRelease = 600 * time.Millisecond
	t.Cleanup(func() { offlineRelease = old })

	d, f = rig(t, Options{})
	f.set(func(f *fakeSys) { f.net.Gateway, f.net.Iface = "10.34.76.132", "en0" })
	engage(t, d, f)
	gw0, starts0, calls0 := d.sbGateway, f.get().starts, f.get().dnsCalls

	f.set(func(f *fakeSys) { f.net.Online, f.iface = false, "" })
	for end := time.Now().Add(blip); time.Now().Before(end); {
		pass(t, d)
		time.Sleep(30 * time.Millisecond)
	}
	if after != nil {
		f.set(after)
	}
	f.set(func(f *fakeSys) {
		f.net.Online = true
		if f.iface == "" {
			f.iface = "en0"
		}
	})
	pass(t, d)
	pass(t, d)
	s, det := state(d)
	g := f.get()
	rep = fmt.Sprintf("blip=%v state=%s(%s) restarts=%d sbGateway %s->%s networksetup calls +%d dns=%v offlineSince.zero=%v badChecks=%d netChanged=%v",
		blip*100, s, det, g.starts-starts0, gw0, d.sbGateway, g.dnsCalls-calls0, g.dns, d.offlineSince.IsZero(), d.badChecks, d.netChanged.Load())
	t.Log(rep)
	return d, f, rep
}

func TestRegressBlipSameAttachmentChangesNothing(t *testing.T) {
	for _, blip := range []time.Duration{50 * time.Millisecond, 200 * time.Millisecond, 500 * time.Millisecond} {
		d, f, _ := blipRig(t, blip, nil)
		if f.get().starts != 1 {
			t.Errorf("blip %v restarted sing-box", blip*100)
		}
		if !slices.Equal(f.get().dns["Wi-Fi"], []string{sysdns.Capture}) {
			t.Errorf("blip %v: resolver %v", blip*100, f.get().dns)
		}
		wantState(t, d, StateActive)
	}
}

func TestRegressBlipNewGatewayRestarts(t *testing.T) {
	_, f, _ := blipRig(t, 200*time.Millisecond, func(f *fakeSys) { f.net.Gateway = "10.34.77.1" })
	if f.get().starts != 2 {
		t.Errorf("a new gateway after a blip did not rebuild the capture: starts=%d", f.get().starts)
	}
}

func TestRegressBlipNewInterfaceSameGateway(t *testing.T) {
	_, f, _ := blipRig(t, 200*time.Millisecond, func(f *fakeSys) { f.iface, f.net.Iface = "en5", "en5" })
	t.Logf("starts=%d dns=%v", f.get().starts, f.get().dns)
}

// After a blip, sing-box comes back broken in a way only the active probe
// sees (DNS through the capture dead), while some flows still pass on cached
// addresses. How long does the daemon keep saying ACTIVE?
func TestRegressBrokenAfterBlipHiddenByBusyFlows(t *testing.T) {
	d, f := rig(t, Options{})
	var n int64
	d.sys.flows = func() int64 { n += 3; return n } // traffic keeps flowing
	engage(t, d, f)
	pass(t, d) // a verified check: lastProbe = now
	f.set(func(f *fakeSys) { f.net.Online, f.iface = false, "" })
	pass(t, d)
	pass(t, d)
	f.set(func(f *fakeSys) {
		f.net.Online, f.iface = true, "en0"
		f.capErr = errors.New("DNS through the capture: i/o timeout")
	})
	checks := 0
	for i := 0; i < 9; i++ { // nine health periods (4.5 minutes of 30s checks)
		pass(t, d) // pass() lifts the 30s rate limit, as if 30s had gone by
		checks++
	}
	s, _ := state(d)
	t.Logf("after the blip: %d health periods, state=%s badChecks=%d failOpen=%v (probe suppressed until lastProbe is %v old)",
		checks, s, d.badChecks, !d.running(), probeEvery)
	if d.badChecks == 0 && s == StateActive {
		t.Errorf("capture DNS dead after the blip, yet %d checks in a row recorded nothing and the state is ACTIVE", checks)
	}
}
