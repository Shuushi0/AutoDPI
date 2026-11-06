package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/ipc"
)

const tok = "testtoken"

type harness struct {
	srv   *Server
	ts    *httptest.Server
	cfg   string
	mu    sync.Mutex
	reqs  []ipc.Request
	saved []byte
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir, err := os.MkdirTemp("", "ui")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &harness{cfg: filepath.Join(dir, "config.json")}
	sock := filepath.Join(dir, "s")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ipc.Serve(ctx, sock, func(_ context.Context, r ipc.Request) (any, error) {
		h.mu.Lock()
		h.reqs = append(h.reqs, r)
		h.mu.Unlock()
		switch r.Cmd {
		case "status":
			return map[string]any{"state": "active", "entries": 2}, nil
		case "list":
			return map[string]any{"networks": []any{map[string]any{"key": "asn:1", "current": true}}}, nil
		case "log":
			return []any{map[string]any{"kind": "listed", "subject": "x.com"}}, nil
		case "add":
			if r.Domain == "bad!" {
				return nil, os.ErrInvalid
			}
			return map[string]any{"added": true, "domain": r.Domain}, nil
		case "open-reset":
			return map[string]any{"removed": 1}, nil
		case "remove", "pause", "resume":
			return map[string]any{"ok": true}, nil
		}
		return nil, os.ErrNotExist
	})
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.srv = New(tok, h.cfg, func(req ipc.Request, out any, to time.Duration) error { return ipc.Call(sock, req, out, to) },
		func(path string, data []byte) error { h.saved = data; return os.WriteFile(path, data, 0o644) })
	h.ts = httptest.NewServer(h.srv.Handler())
	t.Cleanup(h.ts.Close)
	h.srv.AllowPort(strings.TrimPrefix(h.ts.URL, "http://127.0.0.1:"))
	return h
}

func (h *harness) do(t *testing.T, method, path, body string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, h.ts.URL+path, strings.NewReader(body))
	req.Header.Set("X-Token", tok)
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	if hh, ok := hdr["Host"]; ok {
		req.Host = hh
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	b.ReadFrom(resp.Body)
	return resp.StatusCode, b.String()
}

func TestAuth(t *testing.T) {
	h := newHarness(t)
	if c, body := h.do(t, "GET", "/api/status", "", map[string]string{"X-Token": ""}); c != 403 || !strings.HasPrefix(body, "yasak: ") {
		t.Errorf("no token: %d %q", c, body)
	}
	if c, _ := h.do(t, "GET", "/api/status", "", map[string]string{"X-Token": "nope"}); c != 403 {
		t.Errorf("bad token: %d", c)
	}
	if c, _ := h.do(t, "GET", "/api/status?t="+tok, "", map[string]string{"X-Token": ""}); c != 200 {
		t.Errorf("query token: %d", c)
	}
	if c, _ := h.do(t, "GET", "/api/status", "", map[string]string{"Host": "evil.example:80"}); c != 403 {
		t.Errorf("bad host (rebinding): %d", c)
	}
	if c, _ := h.do(t, "POST", "/api/pause", "", map[string]string{"Origin": "http://evil.example"}); c != 403 {
		t.Errorf("bad origin: %d", c)
	}
	if c, _ := h.do(t, "POST", "/api/pause", "", map[string]string{"Origin": h.ts.URL}); c != 200 {
		t.Errorf("same origin: %d", c)
	}
}

func TestPageAndAssets(t *testing.T) {
	h := newHarness(t)
	c, body := h.do(t, "GET", "/?t="+tok, "", nil)
	if c != 200 || !strings.Contains(body, "common.js?t="+tok) || !strings.Contains(body, "app.js?t="+tok) || strings.Contains(body, "{{TOKEN}}") {
		t.Errorf("page: %d %s", c, body)
	}
	for _, p := range []string{"/common.js", "/app.js", "/style.css"} {
		if c, b := h.do(t, "GET", p+"?t="+tok, "", nil); c != 200 || len(b) < 100 {
			t.Errorf("%s: %d", p, c)
		}
	}
	if c, _ := h.do(t, "GET", "/app.js", "", map[string]string{"X-Token": ""}); c != 403 {
		t.Errorf("asset without token: %d", c)
	}
}

func TestLocalize(t *testing.T) {
	page := `<html lang="x"><b>[[Kaydet|Save]]</b> <i title="[[Ağ geçidi|Gateway]]">[[Açık|Open]]</i> [x] a|b`
	if got := localize(page, true); got != `<html lang="x"><b>Kaydet</b> <i title="Ağ geçidi">Açık</i> [x] a|b` {
		t.Errorf("tr: %s", got)
	}
	if got := localize(page, false); got != `<html lang="x"><b>Save</b> <i title="Gateway">Open</i> [x] a|b` {
		t.Errorf("en: %s", got)
	}
	// No page may ship with a pair left in it.
	h := newHarness(t)
	for _, p := range []string{"/", "/mini"} {
		if _, b := h.do(t, "GET", p+"?t="+tok, "", nil); strings.Contains(b, "[[") || strings.Contains(b, "{{") {
			t.Errorf("%s still has a marker", p)
		}
	}
}

func TestMiniPageAndTrayActions(t *testing.T) {
	h := newHarness(t)
	c, body := h.do(t, "GET", "/mini?t="+tok, "", nil)
	if c != 200 || !strings.Contains(body, "common.js?t="+tok) || !strings.Contains(body, "mini.js?t="+tok) || strings.Contains(body, "{{TOKEN}}") {
		t.Errorf("mini page: %d %s", c, body)
	}
	for _, p := range []string{"/mini.js", "/mini.css"} {
		if c, b := h.do(t, "GET", p+"?t="+tok, "", nil); c != 200 || len(b) < 100 {
			t.Errorf("%s: %d", p, c)
		}
	}

	// A plain `autodpi ui` offers no tray actions.
	if c, b := h.do(t, "GET", "/api/tray", "", nil); c != 200 || !strings.Contains(b, `"actions":[]`) {
		t.Errorf("no tray: %d %s", c, b)
	}
	if c, _ := h.do(t, "POST", "/api/tray/quit", "", nil); c != 404 {
		t.Errorf("tray action without a tray: %d", c)
	}

	var hidden int
	h.srv.Tray = map[string]func() error{
		"hide": func() error { hidden++; return nil },
		"quit": func() error { return errors.New("busy") },
	}
	if c, b := h.do(t, "GET", "/api/tray", "", nil); c != 200 || !strings.Contains(b, `"actions":["hide","quit"]`) {
		t.Errorf("tray actions: %d %s", c, b)
	}
	if c, _ := h.do(t, "POST", "/api/tray/hide", "", nil); c != 200 || hidden != 1 {
		t.Errorf("hide: %d, called %d times", c, hidden)
	}
	if c, b := h.do(t, "POST", "/api/tray/quit", "", nil); c != 500 || !strings.Contains(b, "busy") {
		t.Errorf("failing action: %d %s", c, b)
	}
	if c, _ := h.do(t, "POST", "/api/tray/hide", "", map[string]string{"X-Token": ""}); c != 403 {
		t.Errorf("tray action without token: %d", c)
	}
}

func TestPassthrough(t *testing.T) {
	h := newHarness(t)
	for path, want := range map[string]string{"/api/status": `"active"`, "/api/list": `"asn:1"`, "/api/log": `"x.com"`} {
		c, b := h.do(t, "GET", path, "", nil)
		if c != 200 || !strings.Contains(b, want) {
			t.Errorf("%s: %d %s", path, c, b)
		}
	}
	h.do(t, "POST", "/api/pause", "", nil)
	h.do(t, "POST", "/api/resume", "", nil)
	c, b := h.do(t, "POST", "/api/add", `{"domain":" a.com ","engine":"tlsrec"}`, nil)
	if c != 200 || !strings.Contains(b, `"added":true`) {
		t.Errorf("add: %d %s", c, b)
	}
	if c, b := h.do(t, "POST", "/api/add", `{"domain":"bad!"}`, nil); c != 502 || !strings.Contains(b, "error") {
		t.Errorf("add error: %d %s", c, b)
	}
	if c, _ := h.do(t, "POST", "/api/add", `{"domain":""}`, nil); c != 400 {
		t.Errorf("add empty: %d", c)
	}
	if c, _ := h.do(t, "POST", "/api/add", `{"domain":"a.com","evil":1}`, nil); c != 400 {
		t.Errorf("unknown field: %d", c)
	}
	if c, _ := h.do(t, "POST", "/api/remove", `{"domain":"a.com"}`, nil); c != 200 {
		t.Errorf("remove: %d", c)
	}
	if c, _ := h.do(t, "GET", "/api/add", "", nil); c != 405 {
		t.Errorf("GET add: %d", c)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var cmds []string
	for _, r := range h.reqs {
		cmds = append(cmds, r.Cmd+":"+r.Domain+":"+r.Engine)
	}
	got := strings.Join(cmds, ",")
	if !strings.Contains(got, "pause::") || !strings.Contains(got, "resume::") || !strings.Contains(got, "add:a.com:tlsrec") || !strings.Contains(got, "remove:a.com:") {
		t.Errorf("daemon saw: %s", got)
	}
}

func TestOpenResetEndpoint(t *testing.T) {
	h := newHarness(t)
	if c, b := h.do(t, "POST", "/api/open/reset", "", nil); c != 200 || !strings.Contains(b, `"removed":1`) {
		t.Errorf("open reset: %d %s", c, b)
	}
	if c, _ := h.do(t, "GET", "/api/open/reset", "", nil); c != 405 {
		t.Errorf("GET reset must not be allowed: %d", c)
	}
	if c, _ := h.do(t, "POST", "/api/open/reset", "", map[string]string{"Origin": "http://evil.example"}); c != 403 {
		t.Errorf("cross-origin reset: %d", c)
	}
	// the retired clean-list endpoints are gone
	for _, p := range []string{"/api/clean", "/api/clean/reset"} {
		if c, _ := h.do(t, "GET", p, "", nil); c != 404 && c != 405 {
			t.Errorf("%s still served: %d", p, c)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var cmds []string
	for _, r := range h.reqs {
		cmds = append(cmds, r.Cmd)
	}
	if got := strings.Join(cmds, ","); got != "open-reset" {
		t.Errorf("daemon saw %s", got)
	}
}

func TestDaemonDown(t *testing.T) {
	h := newHarness(t)
	h.srv.Call = func(ipc.Request, any, time.Duration) error { return os.ErrNotExist }
	if c, _ := h.do(t, "GET", "/api/status", "", nil); c != 502 {
		t.Errorf("daemon down: %d", c)
	}
}

func TestConfigGetPut(t *testing.T) {
	h := newHarness(t)
	os.WriteFile(h.cfg, []byte(`{"ciadpi_args":"-r 1","max_conn":99}`), 0o644)
	c, b := h.do(t, "GET", "/api/config", "", nil)
	if c != 200 || !strings.Contains(b, `"tlsrec"`) || !strings.Contains(b, `"known_engines"`) {
		t.Fatalf("get: %d %s", c, b)
	}
	good := `{"engines":["ciadpi","tlsrec"],"spoof_sni":"example.org","dns_takeover":false,"block_quic":true,"retest_hours":6,"hedge_ms":800}`
	c, b = h.do(t, "POST", "/api/config", good, nil)
	if c != 200 || !strings.Contains(b, "yeniden başlat") {
		t.Fatalf("put: %d %s", c, b)
	}
	var m map[string]any
	if err := json.Unmarshal(h.saved, &m); err != nil {
		t.Fatal(err)
	}
	if m["ciadpi_args"] != "-r 1" || m["max_conn"] != float64(99) {
		t.Errorf("untouched keys lost: %v", m)
	}
	if m["spoof_sni"] != "example.org" || m["retest_hours"] != float64(6) || m["dns_takeover"] != false {
		t.Errorf("settings not applied: %v", m)
	}
	if es, _ := m["engines"].([]any); len(es) != 2 || es[0] != "ciadpi" {
		t.Errorf("engines: %v", m["engines"])
	}
}

func TestConfigRejects(t *testing.T) {
	h := newHarness(t)
	for name, body := range map[string]string{
		"no engines":  `{"engines":[],"spoof_sni":"a.com","retest_hours":3,"hedge_ms":1200}`,
		"bad engine":  `{"engines":["nope"],"spoof_sni":"a.com","retest_hours":3,"hedge_ms":1200}`,
		"dup engine":  `{"engines":["tlsrec","tlsrec"],"spoof_sni":"a.com","retest_hours":3,"hedge_ms":1200}`,
		"warp":        `{"engines":["warp"],"spoof_sni":"a.com","retest_hours":3,"hedge_ms":1200}`,
		"hedge range": `{"engines":["tlsrec"],"spoof_sni":"a.com","retest_hours":3,"hedge_ms":1}`,
		"empty sni":   `{"engines":["tlsrec"],"spoof_sni":" ","retest_hours":3,"hedge_ms":1200}`,
		"junk sni":    `{"engines":["tlsrec"],"spoof_sni":"a/b","retest_hours":3,"hedge_ms":1200}`,
		"extra key":   `{"engines":["tlsrec"],"spoof_sni":"a.com","retest_hours":3,"hedge_ms":1200,"max_conn":1}`,
		// would wrap time.Duration negative in the daemon's re-test timer
		"retest overflow": `{"engines":["tlsrec"],"spoof_sni":"a.com","retest_hours":3000000,"hedge_ms":1200}`,
	} {
		if c, _ := h.do(t, "POST", "/api/config", body, nil); c != 400 {
			t.Errorf("%s: got %d, want 400", name, c)
		}
	}
	if h.saved != nil {
		t.Error("invalid config was saved")
	}
}

// A config.json holding JSON null is valid for the daemon (defaults); saving
// over it used to panic the handler (assignment to a nil map).
func TestConfigPutOverNullFile(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(h.cfg, []byte("null\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := `{"engines":["tlsrec"],"spoof_sni":"a.com","dns_takeover":true,"block_quic":true,"retest_hours":3,"hedge_ms":1200}`
	if c, b := h.do(t, "POST", "/api/config", body, nil); c != 200 {
		t.Fatalf("put over a null config.json: %d %s", c, b)
	}
	var m map[string]any
	if err := json.Unmarshal(h.saved, &m); err != nil || m["spoof_sni"] != "a.com" {
		t.Fatalf("saved %s (%v)", h.saved, err)
	}
}

func TestAdminScript(t *testing.T) {
	s := AdminScript("/tmp/it's.json", `/Library/App "x"/config.json`)
	if !strings.HasPrefix(s, `do shell script "`) || !strings.Contains(s, "with administrator privileges") {
		t.Error(s)
	}
	if !strings.Contains(s, `'/tmp/it'\\''s.json'`) || !strings.Contains(s, `\"x\"`) {
		t.Errorf("quoting: %s", s)
	}
}

func TestSaveFileDirect(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := SaveFile(p, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "{}\n" {
		t.Errorf("content %q", b)
	}
}

// config-import writes exactly what it validated, and nothing that fails the
// daemon's rules.
func TestImportConfig(t *testing.T) {
	dir := t.TempDir()
	dst, src := filepath.Join(dir, "config.json"), filepath.Join(dir, "in.json")
	for _, bad := range []string{`{"retest_hours": 0}`, `{"engines": ["nope"]}`, `{`} {
		os.WriteFile(src, []byte(bad), 0o644)
		if err := ImportConfig(dst, src); err == nil {
			t.Errorf("%s imported", bad)
		}
		if _, err := os.Stat(dst); err == nil {
			t.Fatalf("%s written", bad)
		}
	}
	good := "{\n  \"retest_hours\": 5\n}\n"
	os.WriteFile(src, []byte(good), 0o644)
	if err := ImportConfig(dst, src); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != good {
		t.Errorf("wrote %q", b)
	}
}

// Windows has no osascript: when the config directory is not writable the
// save must say how to get rights, not try the macOS dialog.
func TestSaveFileWindowsNeedsElevatedUI(t *testing.T) {
	old := goos
	goos = "windows"
	defer func() { goos = old }()
	p := filepath.Join(t.TempDir(), "missing", "config.json") // not writable: no such directory
	err := SaveFile(p, []byte("{}\n"))
	if err == nil || !strings.Contains(err.Error(), "yönetici") || strings.Contains(err.Error(), "osascript") {
		t.Fatalf("got %v", err)
	}
}

func TestRestartHintPerOS(t *testing.T) {
	if h := restartHint("windows"); !strings.Contains(h, "Restart-Service AutoDPI") {
		t.Errorf("windows: %q", h)
	}
	if h := restartHint("darwin"); !strings.Contains(h, "launchctl kickstart") {
		t.Errorf("darwin: %q", h)
	}
}

// A top-level const that reads itself throws before anything renders (a
// `const LOC = TR ? LOC : ...` once left every page on "Connecting…").
// node --check does not catch it, so look for it here.
func TestScriptsDoNotReadAConstBeforeItExists(t *testing.T) {
	decl := regexp.MustCompile(`^const (\w+) = (.*)$`)
	for _, name := range []string{"common.js", "app.js", "mini.js"} {
		b, err := fs.ReadFile(webFS, "web/"+name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			m := decl.FindStringSubmatch(line)
			if m != nil && regexp.MustCompile(`\b`+m[1]+`\b`).MatchString(m[2]) {
				t.Errorf("%s:%d: %s reads itself: %s", name, i+1, m[1], line)
			}
		}
	}
}
