//go:build !windows

package daemon

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
)

func r4fds() int { e, _ := os.ReadDir("/dev/fd"); return len(e) }

// 1000 cycles through every transition the engage loop has: start, verify,
// DNS take, fail-open, backoff wait, pause/resume, offline release, broken
// sing-box, VPN standby, IPv6 rebuild.
func TestRegressNoLeakAcross1000ReconcileCycles(t *testing.T) {
	oldOff := offlineRelease
	offlineRelease = 0
	t.Cleanup(func() { offlineRelease = oldOff })
	d, f := rig(t, Options{})
	cycle := func(i int) {
		engage(t, d, f)
		switch i % 6 {
		case 0: // fail-open
			f.set(func(f *fakeSys) { f.capErr = errors.New("down") })
			pass(t, d)
			d.badSince = time.Now().Add(-failOpenAfter - time.Second)
			pass(t, d)
			pass(t, d)
			f.set(func(f *fakeSys) { f.capErr = nil })
		case 1: // pause and resume
			_ = d.st.SetPaused(true)
			pass(t, d)
			_ = d.st.SetPaused(false)
		case 2: // offline release
			f.set(func(f *fakeSys) { f.net.Online = false })
			pass(t, d)
			pass(t, d)
			f.set(func(f *fakeSys) { f.net.Online = true })
		case 3: // a VPN comes and goes
			f.set(func(f *fakeSys) { f.foreign = "utun7" })
			pass(t, d)
			f.set(func(f *fakeSys) { f.foreign = "" })
		case 4: // IPv6 flips
			f.set(func(f *fakeSys) { f.v6 = !f.v6 })
			pass(t, d)
			pass(t, d)
		case 5: // TUN never comes up
			d.stopSingBox()
			f.set(func(f *fakeSys) { f.tun = false })
			pass(t, d)
			d.sbStarted = time.Now().Add(-31 * time.Second)
			pass(t, d)
			f.set(func(f *fakeSys) { f.tun = true })
		}
		d.retryAt, d.failOpens = time.Time{}, 0
		if !d.running() {
			pass(t, d)
		}
		d.stopSingBox()
		d.verified = false
	}
	for i := range 12 {
		cycle(i)
	}
	time.Sleep(100 * time.Millisecond)
	g0, f0 := runtime.NumGoroutine(), r4fds()
	for i := range 1000 {
		cycle(i)
	}
	time.Sleep(200 * time.Millisecond)
	g1, f1 := runtime.NumGoroutine(), r4fds()
	t.Logf("goroutines %d -> %d, fds %d -> %d, sing-box starts %d, journal %d, judged %d, flowSeen %d",
		g0, g1, f0, f1, f.get().starts, len(d.journal), len(d.judged), len(d.flowSeen))
	if g1 > g0+3 || f1 > f0+3 {
		t.Errorf("leak: goroutines %d -> %d, fds %d -> %d", g0, g1, f0, f1)
	}
}
