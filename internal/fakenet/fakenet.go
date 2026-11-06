// Package fakenet builds loopback stand-ins for the hostile network, so the
// observer and validator can be exercised without touching a real DPI box.
package fakenet

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/sni"
	"github.com/Shuushi0/AutoDPI/internal/socks"
)

// Mode is what a Censor does to a flow it dislikes.
type Mode int

const (
	Reset Mode = iota // RST the connection
	Drop              // swallow everything, never answer
	Close             // close it cleanly (FIN), the way some DPI boxes end a flow
)

// Censor is a transparent TCP middlebox that inspects only the *first segment*
// of a flow: if it parses as a ClientHello for a blocked name, the flow is
// reset (or black-holed). A ClientHello split across segments slips past, just
// like the weak DPI boxes this project is aimed at.
type Censor struct {
	ln      net.Listener
	Backend string
	Blocked func(name string) bool
	Mode    Mode
	Seen    chan string // SNI of every first flight that carried one

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func NewCensor(backend string, mode Mode, blocked func(string) bool) (*Censor, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	c := &Censor{ln: ln, Backend: backend, Blocked: blocked, Mode: mode, Seen: make(chan string, 64), conns: map[net.Conn]struct{}{}}
	go c.serve()
	return c, nil
}

func (c *Censor) Addr() string { return c.ln.Addr().String() }

func (c *Censor) Close() {
	c.ln.Close()
	c.mu.Lock()
	for k := range c.conns {
		k.Close()
	}
	c.mu.Unlock()
}

func (c *Censor) serve() {
	for {
		k, err := c.ln.Accept()
		if err != nil {
			return
		}
		c.mu.Lock()
		c.conns[k] = struct{}{}
		c.mu.Unlock()
		go c.handle(k)
	}
}

func (c *Censor) handle(k net.Conn) {
	defer func() {
		k.Close()
		c.mu.Lock()
		delete(c.conns, k)
		c.mu.Unlock()
	}()
	buf := make([]byte, 16<<10)
	n, err := k.Read(buf) // one segment's worth, the way a cheap DPI sees it
	if err != nil {
		return
	}
	if name, perr := sni.Parse(buf[:n]); perr == nil {
		select {
		case c.Seen <- name:
		default:
		}
		if c.Blocked != nil && c.Blocked(name) {
			switch c.Mode {
			case Reset:
				if tc, ok := k.(*net.TCPConn); ok {
					_ = tc.SetLinger(0)
				}
				return
			case Drop:
				_, _ = io.Copy(io.Discard, k)
				return
			case Close:
				return
			}
		}
	}
	up, err := net.Dial("tcp", c.Backend)
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := up.Write(buf[:n]); err != nil {
		return
	}
	pipe(k, up)
}

// pipe copies both ways until both directions end; a clean EOF on one side is
// passed on as a half-close so the other side can still finish its reply.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			_ = cw.CloseWrite()
		} else {
			dst.Close()
			src.Close()
		}
		done <- struct{}{}
	}
	go cp(b, a)
	go cp(a, b)
	<-done
	<-done
}

// SplitEngine is a SOCKS5 proxy that connects where asked and forwards the
// client's first write as two TCP segments, the way a ciadpi --split would.
type SplitEngine struct {
	ln net.Listener
	// Rewrite maps a requested address to the one actually dialled.
	Rewrite map[string]string
	Hits    chan string
}

func NewSplitEngine() (*SplitEngine, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	e := &SplitEngine{ln: ln, Hits: make(chan string, 64)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go e.handle(c)
		}
	}()
	return e, nil
}

func (e *SplitEngine) Addr() string { return e.ln.Addr().String() }
func (e *SplitEngine) Close()       { e.ln.Close() }

func (e *SplitEngine) handle(c net.Conn) {
	defer c.Close()
	bc, req, err := socks.Accept(c)
	if err != nil {
		return
	}
	target := req.Addr()
	if to, ok := e.Rewrite[target]; ok {
		target = to
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		_ = socks.Reply(bc, socks.RepRefused)
		return
	}
	defer up.Close()
	_ = socks.Reply(bc, socks.RepOK)
	select {
	case e.Hits <- target:
	default:
	}

	first := make([]byte, 16<<10)
	n, err := bc.Read(first)
	if err != nil {
		return
	}
	if n > 1 {
		_, _ = up.Write(first[:1])
		time.Sleep(60 * time.Millisecond) // long enough that a busy machine does not coalesce the two segments in the censor's first read
		_, _ = up.Write(first[1:n])
	} else {
		_, _ = up.Write(first[:n])
	}
	pipe(bc, up)
}
