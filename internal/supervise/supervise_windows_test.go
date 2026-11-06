package supervise

import (
	"context"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// The test binary doubles as a long-running helper.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "sleeper" {
		time.Sleep(60 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStartContainsAndStops(t *testing.T) {
	p, err := Start(Spec{Name: "sleeper", Path: os.Args[0], Args: []string{"sleeper"}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PID()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var in int32
	if r, _, err := procIsProcessInJob.Call(uintptr(h), uintptr(job.h), uintptr(unsafe.Pointer(&in))); r == 0 || in == 0 {
		t.Fatalf("child not in the kill-on-close job: in=%v err=%v", in, err)
	}
	start := time.Now()
	p.Stop(3 * time.Second)
	select {
	case <-p.Done():
	default:
		t.Fatal("Stop returned before the child was reaped")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("stop took %s", time.Since(start))
	}
}

func TestKeepRestartsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ups := make(chan int, 4)
	done := make(chan struct{})
	go func() {
		Keep(ctx, Spec{Name: "sleeper", Path: os.Args[0], Args: []string{"sleeper"}}, func(p *Proc) { ups <- p.PID() })
		close(done)
	}()
	select {
	case <-ups:
	case <-time.After(10 * time.Second):
		t.Fatal("helper never came up")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Keep did not return after cancel")
	}
}
