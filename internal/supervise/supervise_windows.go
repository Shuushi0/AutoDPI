package supervise

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// command starts the helper directly: Windows has no reparenting to watch
// for, the job object below does the guard's work. Its own process group
// keeps a Ctrl+C in the terminal (lab, foreground daemon) from reaching the
// child before the daemon has cleaned up; CREATE_NO_WINDOW keeps a console
// helper from opening a window when the daemon runs as a service.
// s.User is ignored: there is no "nobody" to drop to without a service
// account of our own, so helpers run as the daemon (LocalSystem).
func command(s Spec) *exec.Cmd {
	cmd := exec.Command(s.Path, s.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
		HideWindow:    true,
	}
	return cmd
}

var job struct {
	once sync.Once
	h    windows.Handle
	err  error
}

// killOnCloseJob is created once per daemon process and never closed: the
// kernel closes it when the daemon exits for any reason, and
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE then terminates every helper in it.
func killOnCloseJob() (windows.Handle, error) {
	job.once.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			job.err = err
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			windows.CloseHandle(h)
			job.err = err
			return
		}
		job.h = h
	})
	return job.h, job.err
}

// contain puts the freshly started child into the kill-on-close job. A
// helper that cannot be contained is refused: it could outlive the daemon
// and keep the TUN up with nobody watching it.
func contain(cmd *exec.Cmd) error {
	j, err := killOnCloseJob()
	if err != nil {
		return err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(j, h)
}

// Start launches the helper directly and puts it into the daemon's job object.
func Start(s Spec) (*Proc, error) {
	if s.Log == nil {
		s.Log = quiet()
	}
	cmd := command(s)
	if len(s.Env) > 0 {
		cmd.Env = append(os.Environ(), s.Env...)
	}
	cmd.WaitDelay = 2 * time.Second
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	go logLines(pr, s.Log, s.Name)
	if err := cmd.Start(); err != nil {
		pw.Close()
		return nil, err
	}
	if err := contain(cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		pw.Close()
		return nil, err
	}
	p := &Proc{pid: cmd.Process.Pid, done: make(chan struct{})}
	// Windows has no SIGTERM for a windowless console process, so stopping is
	// always the hard kill macOS keeps for HardKill helpers; sing-box's wintun
	// adapter (and the routes and DNS on it) is removed by the driver when its
	// owner exits.
	p.stop = func(grace time.Duration) {
		_ = cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(grace):
			<-p.done
		}
	}
	go func() {
		p.err = cmd.Wait()
		pw.Close()
		close(p.done)
	}()
	return p, nil
}

// RunGuard exists for the hidden "guard" sub-command; Windows never uses it
// (see command), so it only reports that.
func RunGuard([]string) int {
	_, _ = os.Stderr.WriteString("guard: " + errNoGuard.Error() + "\n")
	return 2
}

var errNoGuard = errors.New("not used on Windows: helpers live in the daemon's kill-on-close job object")
