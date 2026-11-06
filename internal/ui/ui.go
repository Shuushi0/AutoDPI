// Package ui serves a small local settings and status page. It talks to the
// daemon only through the control socket and writes config.json through an
// injectable saver (an administrator prompt on a real install).
package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
)

//go:embed web
var webFS embed.FS

// CallFunc sends one control-socket request and decodes the response data.
type CallFunc func(req ipc.Request, out any, timeout time.Duration) error

// SaveFunc replaces the config file at path with data.
type SaveFunc func(path string, data []byte) error

type Server struct {
	Token      string
	ConfigPath string
	Call       CallFunc
	Save       SaveFunc
	// Tray holds the actions of the app hosting this server (POST
	// /api/tray/{action}): the Windows tray app's, or in a plain `autodpi ui`
	// only "start-service" when the service is installed.
	Tray map[string]func() error

	saveMu sync.Mutex // serialises config saves

	// hosts are the accepted Host header values (set by Listen or by tests).
	hosts map[string]bool
	web   fs.FS
}

// NewToken returns 128 random bits as hex.
func NewToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// New builds a server; call AllowPort (or Listen) before serving.
func New(token, configPath string, call CallFunc, save SaveFunc) *Server {
	sub, _ := fs.Sub(webFS, "web")
	return &Server{Token: token, ConfigPath: configPath, Call: call, Save: save, web: sub, hosts: map[string]bool{}}
}

// AllowPort accepts Host headers 127.0.0.1:port and localhost:port.
func (s *Server) AllowPort(port string) {
	s.hosts["127.0.0.1:"+port] = true
	s.hosts["localhost:"+port] = true
}

// Listen binds a random loopback port and returns the listener and its URL.
func (s *Server) Listen() (net.Listener, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s.AllowPort(port)
	return ln, "http://127.0.0.1:" + port + "/?t=" + s.Token, nil
}

// Serve runs the HTTP server on ln until it is closed.
func (s *Server) Serve(ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 4 * time.Minute}
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page("index.html"))
	mux.HandleFunc("GET /mini", s.page("mini.html"))
	mux.HandleFunc("GET /common.js", s.asset("common.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /app.js", s.asset("app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /mini.js", s.asset("mini.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /style.css", s.asset("style.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /mini.css", s.asset("mini.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /api/tray", s.trayActions)
	mux.HandleFunc("POST /api/tray/{action}", s.trayAction)
	mux.HandleFunc("GET /api/status", s.passthrough(ipc.Request{Cmd: "status"}, 10*time.Second))
	mux.HandleFunc("GET /api/list", s.passthrough(ipc.Request{Cmd: "list", All: true}, 10*time.Second))
	mux.HandleFunc("POST /api/open/reset", s.passthrough(ipc.Request{Cmd: "open-reset"}, 10*time.Second))
	mux.HandleFunc("GET /api/log", s.passthrough(ipc.Request{Cmd: "log", N: 100}, 10*time.Second))
	mux.HandleFunc("POST /api/pause", s.passthrough(ipc.Request{Cmd: "pause"}, 10*time.Second))
	mux.HandleFunc("POST /api/resume", s.passthrough(ipc.Request{Cmd: "resume"}, 10*time.Second))
	mux.HandleFunc("POST /api/maint/{action}", s.maint)
	mux.HandleFunc("POST /api/update/{action}", s.update)
	mux.HandleFunc("POST /api/add", s.add)
	mux.HandleFunc("POST /api/remove", s.remove)
	mux.HandleFunc("GET /api/config", s.getConfig)
	mux.HandleFunc("POST /api/config", s.putConfig)
	return s.guard(mux)
}

// guard enforces the Host allow-list, the token, a same-origin check on
// browser-initiated writes, and restrictive response headers.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

		if !s.hosts[r.Host] {
			http.Error(w, i18n.T("yasak: tanınmayan Host", "forbidden host"), http.StatusForbidden)
			return
		}
		tok := r.URL.Query().Get("t")
		if tok == "" {
			tok = r.Header.Get("X-Token")
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) != 1 {
			http.Error(w, i18n.T("yasak: anahtar (t) eksik ya da yanlış", "forbidden"), http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet {
			if o := r.Header.Get("Origin"); o != "" && !s.hosts[strings.TrimPrefix(o, "http://")] {
				http.Error(w, i18n.T("yasak: başka bir sayfanın isteği (Origin)", "forbidden origin"), http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (s *Server) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := fs.ReadFile(s.web, name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := strings.NewReplacer("{{TOKEN}}", s.Token, "{{LANG}}", i18n.Lang()).Replace(string(b))
		_, _ = w.Write([]byte(localize(page, i18n.Turkish())))
	}
}

// pairRE matches the pages' text pairs, [[Türkçe|English]].
var pairRE = regexp.MustCompile(`\[\[([^|\]]*)\|([^\]]*)\]\]`)

// localize keeps one side of every [[Türkçe|English]] pair of a page; the
// scripts pick their texts themselves from the page's lang attribute.
func localize(page string, turkish bool) string {
	side := "$2"
	if turkish {
		side = "$1"
	}
	return pairRE.ReplaceAllString(page, side)
}

// trayActions lists the tray actions this server offers, so the compact view
// shows only the buttons that work here.
func (s *Server) trayActions(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(s.Tray))
	for name := range s.Tray {
		names = append(names, name)
	}
	slices.Sort(names)
	writeJSON(w, http.StatusOK, map[string]any{"actions": names})
}

func (s *Server) trayAction(w http.ResponseWriter, r *http.Request) {
	fn := s.Tray[r.PathValue("action")]
	if fn == nil {
		writeErr(w, http.StatusNotFound, fmt.Errorf(i18n.T("bilinmeyen tepsi eylemi %q", "unknown tray action %q"), r.PathValue("action")))
		return
	}
	if err := fn(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) asset(name, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := fs.ReadFile(s.web, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write(b)
	}
}
