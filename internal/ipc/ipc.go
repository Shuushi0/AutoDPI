// Package ipc is the control channel between the CLI and the daemon: one JSON
// request and one JSON response per connection over a unix socket (AF_UNIX, which Windows 10 1803+ has too).
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
)

// MaintActions are the actions of the "maint" command. They run in the
// daemon, which is root, so neither the command line nor the settings page
// needs an administrator prompt for them.
var MaintActions = []string{"clear-logs", "restart", "shutdown", "flush-dns", "retest", "reset-list", "reset-all-lists", "reconcile"}

// UpdateActions are the actions of the "update" command: look for a newer
// release now, download and install it now, or stop announcing it.
var UpdateActions = []string{"check", "install", "skip"}

type Request struct {
	Cmd    string `json:"cmd"`
	Domain string `json:"domain,omitempty"`
	Engine string `json:"engine,omitempty"`
	Host   string `json:"host,omitempty"`
	All    bool   `json:"all,omitempty"`
	N      int    `json:"n,omitempty"`
	Action string `json:"action,omitempty"` // for cmds "maint" and "update"
	// Lang is the client's language, "tr" or "en": the daemon writes the
	// errors it answers with in it. Call fills it in.
	Lang string `json:"lang,omitempty"`
}

// T returns tr when the client asked in Turkish and en when it asked in
// English. For a client that did not say, the daemon's own language decides
// (which, for a root daemon, is rarely the user's).
func (r Request) T(tr, en string) string {
	switch r.Lang {
	case "tr":
		return tr
	case "en":
		return en
	}
	return i18n.T(tr, en)
}

type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
	// Kind is set when the service did not take the request at all (KindBusy:
	// every control slot is in use), as opposed to refusing what it asked.
	Kind string `json:"kind,omitempty"`
}

type Handler func(ctx context.Context, req Request) (any, error)

const (
	// MaxRequest bounds one request: the largest real one (an add with a
	// long domain) is well under a kilobyte.
	MaxRequest = 64 << 10
	// MaxConns is how many connections are served at once; the apps poll
	// every few seconds, so a handful is the normal load. A client beyond it
	// waits up to busyWait for a slot, then is told the service is busy.
	MaxConns = 32
	busyWait = 2 * time.Second
)

// Serve listens on path until ctx ends. It refuses to start over a live daemon.
func Serve(ctx context.Context, path string, h Handler) error {
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return fmt.Errorf("another daemon already listens on %s", path)
	}
	// Replace a stale socket left by a crash, but never delete something that is
	// not one: a regular file or a directory at this path is somebody's data.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().IsRegular() || fi.IsDir() {
			return fmt.Errorf("%s exists and is not a socket; not touching it", path)
		}
		_ = os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := secureSocket(path); err != nil {
		ln.Close()
		return fmt.Errorf("control socket %s: %w", path, err)
	}
	// On the way out the socket file goes, but only while it is still this
	// listener's: a daemon started right after this one stopped listening has
	// its own socket at the same path by then, and removing that would leave
	// it running with nothing to reach it by.
	mine, _ := os.Stat(path)
	if ul, ok := ln.(*net.UnixListener); ok && mine != nil {
		ul.SetUnlinkOnClose(false) // Close would unlink the path whoever owns it
	}
	defer func() { // before Serve returns: its caller may look for the file next
		ln.Close()
		if mine == nil {
			os.Remove(path) // the file cannot be told apart here: as before
		} else if cur, err := os.Stat(path); err == nil && os.SameFile(mine, cur) {
			os.Remove(path)
		}
	}()
	go func() { <-ctx.Done(); ln.Close() }()

	var delay time.Duration
	slots := make(chan struct{}, MaxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// A temporary failure (out of file descriptors under load, a
			// connection aborted before accept) must not end the control
			// server: the daemon treats that as fatal. Back off and retry,
			// the way net/http does.
			var te interface{ Temporary() bool }
			var ne net.Error
			if (errors.As(err, &te) && te.Temporary()) || (errors.As(err, &ne) && ne.Timeout()) {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else if delay *= 2; delay > time.Second {
					delay = time.Second
				}
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return nil
				}
				continue
			}
			return err
		}
		delay = 0
		// A burst of clients waits a moment for a slot (the listen backlog
		// holds the rest); only one that finds none in time is turned away.
		select {
		case slots <- struct{}{}:
		default:
			wait := time.NewTimer(busyWait)
			select {
			case slots <- struct{}{}:
				wait.Stop()
			case <-wait.C:
				go refuse(c, "the service is busy (too many control connections); try again", KindBusy)
				continue
			case <-ctx.Done():
				wait.Stop()
				c.Close()
				return nil
			}
		}
		go func() {
			defer func() { <-slots }()
			serveConn(ctx, c, h)
		}()
	}
}

// idleReader pushes the read deadline forward before every read.
type idleReader struct {
	c    net.Conn
	idle time.Duration
	end  time.Time
}

func (r *idleReader) Read(p []byte) (int, error) {
	dl := time.Now().Add(r.idle)
	if dl.After(r.end) {
		dl = r.end
	}
	_ = r.c.SetReadDeadline(dl)
	return r.c.Read(p)
}

// refuse answers a connection with an error and closes it.
func refuse(c net.Conn, msg, kind string) {
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = json.NewEncoder(c).Encode(Response{Error: msg, Kind: kind})
}

func serveConn(ctx context.Context, c net.Conn, h Handler) {
	defer c.Close()
	// A client may stay silent for 5 seconds at a time, and take no longer than
	// a minute in all; a large request that keeps arriving is not cut short,
	// up to MaxRequest bytes.
	var req Request
	in := &io.LimitedReader{R: &idleReader{c: c, idle: 5 * time.Second, end: time.Now().Add(time.Minute)}, N: MaxRequest + 1}
	if err := json.NewDecoder(bufio.NewReader(in)).Decode(&req); err != nil {
		if in.N <= 0 {
			refuse(c, fmt.Sprintf("invalid request: larger than %d bytes", MaxRequest), "")
			return
		}
		// A client that sent something that is not a request gets told so; one
		// that connected and went away, or stalled, gets nothing.
		var syn *json.SyntaxError
		var typ *json.UnmarshalTypeError
		if errors.As(err, &syn) || errors.As(err, &typ) {
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_ = json.NewEncoder(c).Encode(Response{Error: "invalid request: " + err.Error()})
		}
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	resp := Response{OK: true}
	if data, err := safely(ctx, h, req); err != nil {
		resp = Response{Error: err.Error()}
	} else if data != nil {
		b, merr := json.Marshal(data)
		if merr != nil {
			resp = Response{Error: merr.Error()}
		} else {
			resp.Data = b
		}
	}
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = json.NewEncoder(c).Encode(resp)
}

func safely(ctx context.Context, h Handler, req Request) (data any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v", r)
		}
	}()
	return h(ctx, req)
}

// Call sends req to the daemon at path and decodes the response data into out.
// It asks for answers in this process's language unless req.Lang says.
// Why a call did not get an answer from the service. An answer that is an
// error (a refused request) is a plain error, not one of these.
const (
	KindDown   = "down"   // nothing runs behind the socket
	KindDenied = "denied" // it runs, and this user may not talk to it
	KindBusy   = "busy"   // it runs and did not answer (in time)
)

// CallError is Call's error when the service gave no answer; Msg is in the
// user's language.
type CallError struct{ Kind, Msg string }

func (e *CallError) Error() string { return e.Msg }

// Kind is the CallError kind of err, "" for any other error.
func Kind(err error) string {
	var ce *CallError
	if errors.As(err, &ce) {
		return ce.Kind
	}
	return ""
}

func Call(path string, req Request, out any, timeout time.Duration) error {
	if req.Lang == "" {
		req.Lang = i18n.Lang()
	}
	c, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		_, serr := os.Stat(path)
		switch {
		case errors.Is(err, os.ErrPermission) || errors.Is(serr, os.ErrPermission):
			// Not "not running": the service is there and this user may not
			// talk to it. A Start button would do nothing for that.
			return &CallError{Kind: KindDenied, Msg: i18n.T("bu kullanıcının servise erişim izni yok (yönetici olarak deneyin)",
				"this user is not allowed to talk to the service (try as an administrator)")}
		case errors.Is(err, os.ErrNotExist) || errors.Is(serr, os.ErrNotExist):
			return &CallError{Kind: KindDown, Msg: fmt.Sprintf(i18n.T("servis çalışmıyor (%s soketi yok)", "the service is not running (no socket at %s)"), path)}
		case refused(err):
			// The socket file outlived a daemon that was killed.
			return &CallError{Kind: KindDown, Msg: fmt.Sprintf(i18n.T("servis çalışmıyor (%s soketini dinleyen yok)", "the service is not running (nobody listens on %s)"), path)}
		}
		return &CallError{Kind: KindBusy, Msg: i18n.T("servise bağlanılamadı: ", "the service could not be reached: ") + err.Error()}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	busy := func(err error) error {
		// It took the connection and did not answer in time: it runs, and is
		// busy or stuck. Not the same as off.
		var ne net.Error
		if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return &CallError{Kind: KindBusy, Msg: fmt.Sprintf(i18n.T("servis %s içinde yanıt vermedi (meşgul olabilir; biraz sonra yeniden deneyin)",
				"the service did not answer within %s (it may be busy; try again in a moment)"), timeout)}
		}
		return &CallError{Kind: KindBusy, Msg: i18n.T("servisle bağlantı koptu: ", "the connection to the service broke: ") + err.Error()}
	}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return busy(err)
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&resp); err != nil {
		return busy(err)
	}
	if !resp.OK {
		if resp.Kind == KindBusy {
			// It runs and has no room for one more request right now. Said
			// as a plain error this read as "not running" in the apps, with
			// a hint to install; and it was the one message in English only
			// (the service does not know the caller's language before it has
			// read the request).
			return &CallError{Kind: KindBusy, Msg: i18n.T("servis şu an meşgul (çok fazla denetim bağlantısı açık); biraz sonra yeniden deneyin",
				"the service is busy right now (too many control connections); try again in a moment")}
		}
		return errors.New(resp.Error)
	}
	if out != nil && len(resp.Data) > 0 {
		return json.Unmarshal(resp.Data, out)
	}
	return nil
}
