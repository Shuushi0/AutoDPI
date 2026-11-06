//go:build !windows

package supervise

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// One guard process supervises every helper of a daemon. The daemon talks to
// it over the guard's stdin/stdout, one JSON object per line:
//
//	daemon -> guard   {"op":"start","id":1,"path":..,"args":[..],"env":[..],"uid":N,"gid":N,"cred":true,"hard":true}
//	                  {"op":"stop","id":1,"grace_ms":5000}
//	guard  -> daemon  {"ev":"up","id":1,"pid":123}
//	                  {"ev":"log","id":1,"line":".."}
//	                  {"ev":"exit","id":1,"code":0,"err":".."}
//
// The fail-open guarantee: the pipe's write end belongs to the daemon alone, so
// when the daemon dies (SIGKILL included) the kernel closes it and the guard
// reads EOF at once; the guard then stops every child and exits. A parent-pid
// check once a second backs that up.

type request struct {
	Op      string   `json:"op"`
	ID      int      `json:"id"`
	Path    string   `json:"path,omitempty"`
	Args    []string `json:"args,omitempty"`
	Env     []string `json:"env,omitempty"`
	Cred    bool     `json:"cred,omitempty"`
	Uid     uint32   `json:"uid,omitempty"`
	Gid     uint32   `json:"gid,omitempty"`
	Hard    bool     `json:"hard,omitempty"`
	GraceMS int      `json:"grace_ms,omitempty"`
}

type event struct {
	Ev   string `json:"ev"`
	ID   int    `json:"id"`
	PID  int    `json:"pid,omitempty"`
	Line string `json:"line,omitempty"`
	Code int    `json:"code,omitempty"`
	Err  string `json:"err,omitempty"`
}

// ---- daemon side -----------------------------------------------------------

type hub struct {
	self string
	cmd  *exec.Cmd
	pid  int

	mu      sync.Mutex
	in      io.WriteCloser
	enc     *json.Encoder
	procs   map[int]*hubProc
	next    int
	closing bool // no new children; the guard is being told to go
}

type hubProc struct {
	p    *Proc
	spec Spec
	up   chan int // child pid
}

var hubs struct {
	sync.Mutex
	bySelf map[string]*hub
}

// acquire returns the live hub for self, starting its guard when needed.
func acquire(self string, log *slog.Logger) (*hub, error) {
	hubs.Lock()
	defer hubs.Unlock()
	if hubs.bySelf == nil {
		hubs.bySelf = map[string]*hub{}
	}
	if h := hubs.bySelf[self]; h != nil {
		h.mu.Lock()
		usable := !h.closing
		h.mu.Unlock()
		if usable {
			return h, nil
		}
	}
	h, err := startHub(self, log)
	if err != nil {
		return nil, err
	}
	hubs.bySelf[self] = h
	return h, nil
}

func startHub(self string, log *slog.Logger) (*hub, error) {
	cmd := exec.Command(self, GuardCmd, "--hub", "--parent", strconv.Itoa(os.Getpid()))
	// Own process group: if the guard has to be swept, it and whatever it left
	// behind go together.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	cmd.Stderr = pw
	go logLines(pr, log, "guard")
	if err := cmd.Start(); err != nil {
		pw.Close()
		return nil, err
	}
	h := &hub{self: self, cmd: cmd, pid: cmd.Process.Pid, in: in, enc: json.NewEncoder(in),
		procs: map[int]*hubProc{}}
	go h.read(out, pw)
	return h, nil
}

// read dispatches the guard's events until it goes away.
func (h *hub) read(out io.Reader, pw *io.PipeWriter) {
	dec := json.NewDecoder(bufio.NewReader(out))
	for {
		var ev event
		if err := dec.Decode(&ev); err != nil {
			break
		}
		h.mu.Lock()
		hp := h.procs[ev.ID]
		h.mu.Unlock()
		if hp == nil {
			continue
		}
		switch ev.Ev {
		case "up":
			hp.up <- ev.PID
		case "log":
			hp.spec.Log.Info(ev.Line, "proc", hp.spec.Name)
		case "exit":
			var err error
			if ev.Err != "" {
				err = errors.New(ev.Err)
			} else if ev.Code != 0 {
				err = fmt.Errorf("exit status %d", ev.Code)
			}
			h.finish(ev.ID, err)
		}
	}
	// The guard is gone. Whatever it still supervised is orphaned: sweep its
	// process group (the guard led it) and report every child as finished.
	h.mu.Lock()
	h.closing = true
	left := make([]int, 0, len(h.procs))
	for id := range h.procs {
		left = append(left, id)
	}
	h.mu.Unlock()
	if len(left) > 0 {
		_ = syscall.Kill(-h.pid, syscall.SIGKILL)
	}
	for _, id := range left {
		h.finish(id, errors.New("guard exited"))
	}
	_ = h.cmd.Wait()
	pw.Close()
	hubs.Lock()
	if hubs.bySelf[h.self] == h {
		delete(hubs.bySelf, h.self)
	}
	hubs.Unlock()
}

// finish reports id as ended and, when it was the last child, lets the guard go.
func (h *hub) finish(id int, err error) {
	h.mu.Lock()
	hp := h.procs[id]
	if hp == nil {
		h.mu.Unlock()
		return
	}
	delete(h.procs, id)
	idle := len(h.procs) == 0 && !h.closing
	if idle {
		h.closing = true
	}
	h.mu.Unlock()
	hp.p.err = err
	close(hp.p.done)
	if idle {
		_ = h.in.Close() // EOF: the guard has nothing left to watch and exits
	}
}

func (h *hub) send(r request) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.enc.Encode(r)
}

var errHubClosing = errors.New("guard is shutting down")

// Start launches the process under the daemon's shared guard.
func Start(s Spec) (*Proc, error) {
	if s.Log == nil {
		s.Log = quiet()
	}
	for attempt := 0; ; attempt++ {
		h, err := acquire(s.Self, s.Log)
		if err != nil {
			return nil, err
		}
		p, err := h.start(s)
		if errors.Is(err, errHubClosing) && attempt < 3 {
			continue // the last child ended just now; use a fresh guard
		}
		return p, err
	}
}

func (h *hub) start(s Spec) (*Proc, error) {
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		return nil, errHubClosing
	}
	h.next++
	id := h.next
	p := &Proc{done: make(chan struct{})}
	hp := &hubProc{p: p, spec: s, up: make(chan int, 1)}
	h.procs[id] = hp
	req := request{Op: "start", ID: id, Path: s.Path, Args: s.Args, Env: s.Env, Hard: s.HardKill}
	if s.User != nil {
		req.Cred, req.Uid, req.Gid = true, s.User.Uid, s.User.Gid
	}
	err := h.enc.Encode(req)
	h.mu.Unlock()
	if err != nil {
		h.finish(id, err)
		return nil, err
	}
	select {
	case p.pid = <-hp.up:
	case <-p.done: // gone before it ever ran: the guard could not exec it
		if p.err == nil {
			p.err = errors.New("exited at once")
		}
		return nil, p.err
	case <-time.After(15 * time.Second):
		h.finish(id, errors.New("guard did not answer"))
		return nil, errors.New("guard did not answer")
	}
	p.stop = func(grace time.Duration) {
		_ = h.send(request{Op: "stop", ID: id, GraceMS: int(grace / time.Millisecond)})
		select {
		case <-p.done:
		case <-time.After(grace + 2*time.Second):
			_ = syscall.Kill(p.pid, syscall.SIGKILL) // the guard did not manage: do it ourselves
			<-p.done
		}
	}
	return p, nil
}

// ---- guard side ------------------------------------------------------------

type child struct {
	cmd  *exec.Cmd
	hard bool
	once sync.Once
}

// terminate stops the child: at once for hard-kill helpers, else SIGTERM with
// a grace period before SIGKILL.
func (c *child) terminate(grace time.Duration) {
	c.once.Do(func() {
		if c.hard {
			_ = c.cmd.Process.Kill()
			return
		}
		_ = c.cmd.Process.Signal(syscall.SIGTERM)
		time.AfterFunc(grace, func() { _ = c.cmd.Process.Kill() }) // no-op once reaped
	})
}

const maxLogLine = 64 << 10

// RunGuard is the body of the hidden "guard" sub-command: "--hub --parent PID".
// It runs the children the daemon asks for until the daemon's pipe closes, the
// process PID is no longer its parent, or it is signalled; then it stops them
// all and returns the exit code. The parent is named explicitly because a
// parent that dies before the guard even starts would otherwise look like
// launchd from the first instruction.
func RunGuard(argv []string) int {
	parent, isHub := 0, false
	for len(argv) > 0 {
		switch {
		case argv[0] == "--hub":
			isHub, argv = true, argv[1:]
		case len(argv) >= 2 && argv[0] == "--parent":
			parent, _ = strconv.Atoi(argv[1])
			argv = argv[2:]
		default:
			return 2
		}
	}
	if !isHub {
		return 2
	}
	if parent != 0 && os.Getppid() != parent {
		return 0 // the daemon is already gone: start nothing
	}

	var (
		outMu    sync.Mutex
		enc      = json.NewEncoder(os.Stdout)
		mu       sync.Mutex
		children = map[int]*child{}
		running  sync.WaitGroup
	)
	emit := func(ev event) {
		outMu.Lock()
		_ = enc.Encode(ev)
		outMu.Unlock()
	}

	launch := func(r request) {
		cmd := exec.Command(r.Path, r.Args...)
		if len(r.Env) > 0 {
			cmd.Env = append(os.Environ(), r.Env...)
		}
		if r.Cred { // supplementary groups are cleared too: nothing of root's stays
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: r.Uid, Gid: r.Gid}}
		}
		pr, pw, err := os.Pipe()
		if err != nil {
			emit(event{Ev: "exit", ID: r.ID, Code: 127, Err: err.Error()})
			return
		}
		cmd.Stdout, cmd.Stderr = pw, pw
		if err := cmd.Start(); err != nil {
			pw.Close()
			pr.Close()
			emit(event{Ev: "exit", ID: r.ID, Code: 127, Err: err.Error()})
			return
		}
		pw.Close()
		c := &child{cmd: cmd, hard: r.Hard}
		mu.Lock()
		children[r.ID] = c
		mu.Unlock()
		emit(event{Ev: "up", ID: r.ID, PID: cmd.Process.Pid})

		running.Add(1)
		relayDone := make(chan struct{})
		go func() { // output -> log events; long lines are cut, the rest drained
			defer close(relayDone)
			br := bufio.NewReaderSize(pr, 16<<10)
			var line []byte
			for {
				chunk, isPrefix, err := br.ReadLine()
				if err != nil {
					break
				}
				if len(line)+len(chunk) <= maxLogLine {
					line = append(line, chunk...)
				}
				if !isPrefix {
					emit(event{Ev: "log", ID: r.ID, Line: string(line)})
					line = line[:0]
				}
			}
			_, _ = io.Copy(io.Discard, pr)
			pr.Close()
		}()
		go func() {
			defer running.Done()
			err := cmd.Wait()
			select { // let the last output through, but never hang on a stray holder of the pipe
			case <-relayDone:
			case <-time.After(2 * time.Second):
			}
			mu.Lock()
			delete(children, r.ID)
			mu.Unlock()
			ev := event{Ev: "exit", ID: r.ID}
			var ee *exec.ExitError
			switch {
			case err == nil:
			case errors.As(err, &ee):
				ev.Code = ee.ExitCode()
				if ev.Code < 0 {
					ev.Code, ev.Err = 1, ee.Error() // killed by a signal
				}
			default:
				ev.Code, ev.Err = 1, err.Error()
			}
			emit(ev)
		}()
	}

	reqs := make(chan request)
	go func() { // stdin: EOF means the daemon is gone
		defer close(reqs)
		dec := json.NewDecoder(bufio.NewReader(os.Stdin))
		for {
			var r request
			if err := dec.Decode(&r); err != nil {
				return
			}
			reqs <- r
		}
	}()

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

loop:
	for {
		select {
		case r, ok := <-reqs:
			if !ok {
				break loop
			}
			switch r.Op {
			case "start":
				launch(r)
			case "stop":
				mu.Lock()
				c := children[r.ID]
				mu.Unlock()
				if c != nil {
					grace := time.Duration(r.GraceMS) * time.Millisecond
					if grace <= 0 || grace > 3*time.Second {
						grace = 3 * time.Second
					}
					c.terminate(grace)
				}
			}
		case <-sigs:
			break loop
		case <-tick.C:
			if parent != 0 && os.Getppid() != parent { // reparented to launchd: the daemon died
				break loop
			}
		}
	}
	mu.Lock()
	for _, c := range children {
		c.terminate(3 * time.Second)
	}
	mu.Unlock()
	running.Wait()
	return 0
}
