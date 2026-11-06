// Package supervise runs the helper processes (sing-box, ciadpi) so that none
// of them can outlive the daemon. On macOS all children are started through
// one shared guard process (a re-exec of this binary) that kills them when the
// daemon disappears; on Windows
// every child is put in a kill-on-close Job Object owned by the daemon, so
// the kernel ends it when the daemon's last handle goes away (crash and
// TerminateProcess included). That is what makes the whole thing fail open -
// if the daemon dies, sing-box dies, the TUN goes away and traffic flows
// normally again.
package supervise

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"time"
)

// GuardCmd is the hidden sub-command the daemon re-executes itself with.
const GuardCmd = "guard"

// Credential is the identity a child is dropped to (macOS only; Windows
// children keep the service's identity).
type Credential struct {
	Uid, Gid uint32
}

// Nobody is macOS's unprivileged account (uid/gid -2).
var Nobody = &Credential{Uid: 4294967294, Gid: 4294967294}

type Spec struct {
	Name string
	Path string
	Args []string
	User *Credential // nil keeps the caller's identity
	Self string      // path of the autodpi binary that provides the guard
	Env  []string    // extra KEY=VALUE entries for the child, on top of the daemon's environment
	Log  *slog.Logger
	// HardKill is for processes that ignore SIGTERM (ciadpi does): the guard
	// sends SIGKILL at once instead of waiting out a grace period first.
	HardKill bool
}

// Proc is one running child.
type Proc struct {
	pid  int
	done chan struct{}
	err  error
	stop func(grace time.Duration)
}

// Stop asks the child to terminate and waits up to grace for it to be reaped
// (the process is then killed outright).
func (p *Proc) Stop(grace time.Duration) { p.stop(grace) }

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func logLines(r io.Reader, log *slog.Logger, name string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		log.Info(sc.Text(), "proc", name)
	}
	// A line over the limit ends the scan; the pipe must still be drained or
	// the child blocks on its next write and Wait never returns.
	if err := sc.Err(); err != nil {
		log.Warn("log line too long, rest of output discarded", "proc", name, "err", err)
	}
	_, _ = io.Copy(io.Discard, r)
}

func (p *Proc) PID() int { return p.pid }

// Done is closed when the process has exited.
func (p *Proc) Done() <-chan struct{} { return p.done }

// Err is the exit error once Done is closed.
func (p *Proc) Err() error { return p.err }

// Keep runs the process, restarting it with exponential backoff until ctx ends.
// onUp is called after each successful start. More than maxFast exits inside
// the window put it to sleep for cooldown instead of hammering the system.
func Keep(ctx context.Context, s Spec, onUp func(*Proc)) {
	const (
		maxFast  = 5
		window   = time.Minute
		cooldown = 5 * time.Minute
	)
	if s.Log == nil {
		s.Log = quiet()
	}
	backoff := time.Second
	var recent []time.Time
	for ctx.Err() == nil {
		p, err := Start(s)
		if err != nil {
			s.Log.Error("start failed", "proc", s.Name, "err", err)
		} else {
			started := time.Now()
			if onUp != nil {
				onUp(p)
			}
			select {
			case <-p.Done():
				s.Log.Warn("exited", "proc", s.Name, "err", p.Err(), "after", time.Since(started).Round(time.Millisecond))
			case <-ctx.Done():
				p.Stop(5 * time.Second)
				return
			}
			if time.Since(started) > 30*time.Second {
				backoff = time.Second
			}
		}
		now := time.Now()
		recent = append(recent, now)
		for len(recent) > 0 && now.Sub(recent[0]) > window {
			recent = recent[1:]
		}
		wait := backoff
		if len(recent) > maxFast {
			s.Log.Error("crash loop, backing off (traffic flows untouched meanwhile)", "proc", s.Name, "for", cooldown)
			wait, recent = cooldown, nil
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}
