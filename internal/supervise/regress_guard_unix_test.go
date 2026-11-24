//go:build !windows

package supervise

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// The daemon dies (SIGKILL, a panic, power management) while a child is
// printing. The guard reads EOF on stdin and stops its children: SIGTERM, then
// SIGKILL after a grace period. But its next write to stdout (fd 1) hits a
// broken pipe, and a Go program that did not ask for SIGPIPE dies of it on fd
// 1 - before the grace period's SIGKILL. A child that takes its time over
// SIGTERM and keeps talking is then orphaned with the TUN.
func guardOrphan(t *testing.T, script string) (childAlive bool, guardState string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], GuardCmd, "--hub", "--parent", strconv.Itoa(os.Getpid()))
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(in).Encode(request{Op: "start", ID: 1, Path: "/bin/sh", Args: []string{"-c", script}})
	dec := json.NewDecoder(bufio.NewReader(out))
	pid := 0
	for pid == 0 {
		var ev event
		if err := dec.Decode(&ev); err != nil {
			t.Fatal(err)
		}
		if ev.Ev == "up" {
			pid = ev.PID
		}
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	time.Sleep(200 * time.Millisecond)
	// The daemon is gone: both of its pipe ends close at once.
	out.Close()
	in.Close()
	err := cmd.Wait()
	guardState = "exit 0"
	if err != nil {
		guardState = err.Error()
	}
	time.Sleep(5 * time.Second) // well past the guard's 3s SIGKILL fallback
	return syscall.Kill(pid, 0) == nil, guardState
}

func TestRegressGuardDiesOfSIGPIPEAndOrphansATalkingChild(t *testing.T) {
	alive, gs := guardOrphan(t, `trap 'echo closing' TERM; while :; do echo tick; sleep 0.01; done`)
	t.Logf("talking child that is slow to stop: guard %s, child alive 5s later: %v", gs, alive)
	if alive {
		t.Errorf("orphaned: the guard (%s) left a running child behind", gs)
	}
}

func TestRegressGuardKillsASilentSlowChild(t *testing.T) {
	alive, gs := guardOrphan(t, `trap '' TERM; while :; do sleep 0.05; done`)
	t.Logf("silent child that ignores SIGTERM: guard %s, child alive 5s later: %v", gs, alive)
	if alive {
		t.Errorf("orphaned: %s", gs)
	}
}

// sing-box at log level "fatal" prints nothing; ciadpi prints a line per
// reset. The daemon dies: the guard SIGKILLs ciadpi at once and SIGTERMs
// sing-box, ciadpi's last lines are relayed to the dead stdout, the guard dies
// of SIGPIPE, and the SIGKILL that was to follow sing-box's grace never comes.
func TestRegressGuardSIGPIPEOrphansASilentChildNextToATalkingOne(t *testing.T) {
	cmd := exec.Command(os.Args[0], GuardCmd, "--hub", "--parent", strconv.Itoa(os.Getpid()))
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(in)
	_ = enc.Encode(request{Op: "start", ID: 1, Path: "/bin/sh", Args: []string{"-c", `trap '' TERM; while :; do sleep 0.05; done`}}) // "sing-box": silent, slow to stop
	_ = enc.Encode(request{Op: "start", ID: 2, Path: "/bin/sh", Args: []string{"-c", `while :; do echo reset; done`}, Hard: true})   // "ciadpi": chatty
	dec := json.NewDecoder(bufio.NewReader(out))
	pids := map[int]int{}
	for len(pids) < 2 {
		var ev event
		if err := dec.Decode(&ev); err != nil {
			t.Fatal(err)
		}
		if ev.Ev == "up" {
			pids[ev.ID] = ev.PID
		}
	}
	t.Cleanup(func() {
		for _, p := range pids {
			_ = syscall.Kill(p, syscall.SIGKILL)
		}
	})
	time.Sleep(200 * time.Millisecond)
	out.Close()
	in.Close()
	err := cmd.Wait()
	time.Sleep(5 * time.Second)
	t.Logf("guard: %v; silent child alive 5s later: %v", err, syscall.Kill(pids[1], 0) == nil)
	if syscall.Kill(pids[1], 0) == nil {
		t.Errorf("the silent, slow child outlived the daemon and the guard (guard: %v)", err)
	}
}
