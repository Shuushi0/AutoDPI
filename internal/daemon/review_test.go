//go:build !windows

package daemon

import (
	"testing"
	"time"
)

// The hung build: rolled back on disk, but is the process restarted?
func TestReviewHungBuildRestarts(t *testing.T) {
	d, f := pendingRig(t)
	old := proofWait
	proofWait = 20 * time.Millisecond
	t.Cleanup(func() { proofWait = old })
	f.set(func(f *fakeSys) { f.tun = false })
	d.upd.mu.Lock()
	d.upd.broken = confirmWithin - confirmTick
	d.upd.mu.Unlock()
	d.mu.Lock() // the hang, for good
	done := make(chan struct{})
	go func() { confirm(t, d, 2*time.Second); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	st := pendingState(d)
	restarted := d.restart.Load()
	t.Logf("pending=%v failed=%q restart=%v", st.Pending, st.Failed, restarted)
	if st.Failed != "" && !restarted {
		t.Errorf("rolled back on disk, but restartSelf never ran: the hung new build keeps running")
	}
	d.mu.Unlock()
	<-done
}
