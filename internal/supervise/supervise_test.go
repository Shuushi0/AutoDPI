//go:build !windows

package supervise

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as the autodpi executable that provides "guard".
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case GuardCmd:
			os.Exit(RunGuard(os.Args[2:]))
		case "daemon-sim":
			// Stand-in for the daemon: start two guarded children, record their
			// pids, then either exit at once (os.Args[4] == "exit") or sleep until killed.
			var out []string
			for i, c := range []string{"exec sleep 60", "exec sleep 61"} {
				p, err := Start(Spec{Name: "sim" + strconv.Itoa(i), Path: "/bin/sh", Self: os.Args[0],
					Args: []string{"-c", c}, HardKill: i == 1})
				if err != nil {
					os.Exit(3)
				}
				out = append(out, strconv.Itoa(p.PID()))
			}
			_ = os.WriteFile(os.Args[2], []byte(strings.Join(out, " ")), 0o644)
			if os.Args[3] == "exit" {
				os.Exit(0) // dies without cleaning up
			}
			time.Sleep(time.Minute)
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func waitFile(t *testing.T, path string) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			return pid
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("child never wrote its pid")
	return 0
}

func waitPids(t *testing.T, path string) []int {
	t.Helper()
	for i := 0; i < 100; i++ {
		if b, err := os.ReadFile(path); err == nil && len(strings.Fields(string(b))) == 2 {
			var pids []int
			for _, f := range strings.Fields(string(b)) {
				n, _ := strconv.Atoi(f)
				pids = append(pids, n)
			}
			return pids
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("daemon-sim never wrote its children's pids")
	return nil
}

func ppidOf(t *testing.T, pid int) int {
	t.Helper()
	out, err := exec.Command("ps", "-o", "ppid=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

func expectDead(t *testing.T, pids []int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for _, pid := range pids {
		for alive(pid) {
			if time.Now().After(deadline) {
				t.Fatalf("pid %d outlived its parent: fail-open is broken", pid)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func TestGuardKillsChildrenWhenParentExits(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pids")
	if err := exec.Command(os.Args[0], "daemon-sim", pidFile, "exit").Run(); err != nil {
		t.Fatal(err)
	}
	pids := waitPids(t, pidFile)
	t.Cleanup(func() {
		for _, p := range pids {
			_ = syscall.Kill(p, syscall.SIGKILL)
		}
	})
	expectDead(t, pids, 4*time.Second)
}

// SIGKILL gives the daemon no chance to clean up; one guard serves both
// children and takes them down within the second.
func TestOneGuardForBothChildrenSurvivesSIGKILLOfParent(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pids")
	sim := exec.Command(os.Args[0], "daemon-sim", pidFile, "sleep")
	if err := sim.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sim.Process.Kill(); _, _ = sim.Process.Wait() })
	pids := waitPids(t, pidFile)
	t.Cleanup(func() {
		for _, p := range pids {
			_ = syscall.Kill(p, syscall.SIGKILL)
		}
	})
	g0, g1 := ppidOf(t, pids[0]), ppidOf(t, pids[1])
	if g0 != g1 || g0 == sim.Process.Pid || g0 <= 1 {
		t.Fatalf("children should share one guard: ppids %d and %d (daemon %d)", g0, g1, sim.Process.Pid)
	}
	guard := g0
	_ = sim.Process.Kill()
	_, _ = sim.Process.Wait()
	expectDead(t, append(pids, guard), 2*time.Second)
}

func TestStartAndStop(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	p, err := Start(Spec{Name: "sleeper", Path: "/bin/sh", Self: os.Args[0],
		Args: []string{"-c", "echo $$ > " + pidFile + "; exec sleep 60"}})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitFile(t, pidFile)
	if !alive(pid) {
		t.Fatal("child not running")
	}
	p.Stop(2 * time.Second)
	select {
	case <-p.Done():
	default:
		t.Fatal("Stop returned before the process finished")
	}
	time.Sleep(100 * time.Millisecond)
	if alive(pid) {
		t.Fatal("child survived Stop")
	}
}

func TestKeepRestarts(t *testing.T) {
	log := filepath.Join(t.TempDir(), "runs")
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	Keep(ctx, Spec{Name: "flaky", Path: "/bin/sh", Self: os.Args[0],
		Args: []string{"-c", "echo run >> " + log + "; exit 3"}, Log: nil}, nil)
	b, _ := os.ReadFile(log)
	if n := strings.Count(string(b), "run"); n < 2 {
		t.Fatalf("expected at least 2 starts, got %d", n)
	}
}

func TestGuardArgs(t *testing.T) {
	for _, argv := range [][]string{
		{}, // not hub mode
		{"--bogus"},
		{"--hub", "--parent"},
		{"--hub", "--", "/usr/bin/true"},
	} {
		if code := RunGuard(argv); code != 2 {
			t.Errorf("%v: exit %d, want 2", argv, code)
		}
	}
	// A parent that is not us: the guard starts nothing and leaves.
	if code := RunGuard([]string{"--hub", "--parent", "1"}); code != 0 {
		t.Errorf("foreign parent: exit %d", code)
	}
}

func TestStartFailureAndExitStatus(t *testing.T) {
	if _, err := Start(Spec{Name: "nope", Path: "/nonexistent/binary", Self: os.Args[0]}); err == nil {
		t.Fatal("starting a missing binary should fail")
	}
	p, err := Start(Spec{Name: "three", Path: "/bin/sh", Self: os.Args[0], Args: []string{"-c", "exit 3"}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("child never finished")
	}
	if p.Err() == nil || !strings.Contains(p.Err().Error(), "3") {
		t.Fatalf("exit error = %v", p.Err())
	}
}

func TestEnvReachesChild(t *testing.T) {
	out := filepath.Join(t.TempDir(), "env")
	p, err := Start(Spec{Name: "env", Path: "/bin/sh", Self: os.Args[0], Env: []string{"GOGC=33"},
		Args: []string{"-c", "echo $GOGC > " + out}})
	if err != nil {
		t.Fatal(err)
	}
	<-p.Done()
	if b, _ := os.ReadFile(out); strings.TrimSpace(string(b)) != "33" {
		t.Fatalf("child saw GOGC=%q", b)
	}
}

// Children come and go; the guard follows its last child out and a later Start
// gets a fresh one.
func TestGuardIsReplacedAfterTheLastChildEnds(t *testing.T) {
	for i := 0; i < 3; i++ {
		p, err := Start(Spec{Name: "quick", Path: "/bin/sh", Self: os.Args[0], Args: []string{"-c", "exit 0"}})
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		select {
		case <-p.Done():
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: never finished", i)
		}
	}
}

// A child that writes one enormous line must not wedge: the log reader gives
// up on the line but has to keep draining the pipe, or the child blocks on
// its next write and never exits.
func TestHugeLogLineDoesNotWedgeChild(t *testing.T) {
	p, err := Start(Spec{Name: "chatty", Path: "/bin/sh", Self: os.Args[0],
		Args: []string{"-c", "head -c 3000000 /dev/zero | tr '\\0' a; echo; echo after"}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
	case <-time.After(10 * time.Second):
		_ = syscall.Kill(p.PID(), syscall.SIGKILL) // Stop would wait on the wedged pipe too
		t.Fatal("child wedged writing to its log pipe")
	}
}
