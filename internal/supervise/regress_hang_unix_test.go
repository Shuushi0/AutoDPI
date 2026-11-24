//go:build !windows

package supervise

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// The guard is wedged (stopped, or stuck writing to a daemon that does not
// read). Stop waits grace+2s, SIGKILLs the child itself, and then waits for a
// "done" that only the guard can deliver. Run's shutdown (stopSingBox) and the
// engage loop sit behind it.
func TestRegressStopReturnsWhenTheGuardIsWedged(t *testing.T) {
	p, err := Start(Spec{Name: "hang", Path: "/bin/sh", Args: []string{"-c", "exec sleep 60"}, Self: os.Args[0]})
	if err != nil {
		t.Fatal(err)
	}
	hubs.Lock()
	g := hubs.bySelf[os.Args[0]].pid
	hubs.Unlock()
	_ = syscall.Kill(g, syscall.SIGSTOP)
	t.Cleanup(func() { _ = syscall.Kill(g, syscall.SIGCONT); _ = syscall.Kill(g, syscall.SIGKILL) })
	ret := make(chan struct{})
	go func() { p.Stop(100 * time.Millisecond); close(ret) }()
	select {
	case <-ret:
		t.Log("Stop returned")
	case <-time.After(8 * time.Second):
		t.Errorf("Stop still blocked 8s after it was called with a 100ms grace (child alive: %v)", syscall.Kill(p.PID(), 0) == nil)
	}
}
