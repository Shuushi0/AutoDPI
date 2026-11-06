package ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
)

// ---------------------------------------------------------------------------
// BUG (low): readBody accepts trailing garbage after the JSON value.
// handlers.go:readBody decodes one value and never checks dec.More()/EOF, so
// `{"domain":"a.com"} garbage` is treated as valid.
func TestArea4_BodyWithTrailingGarbageIsRejected(t *testing.T) {
	h := newHarness(t)
	c, b := h.do(t, "POST", "/api/remove", `{"domain":"a.com"} garbage {"x":1}`, nil)
	if c == 200 || c == 502 { // 502 = it reached the daemon
		t.Errorf("trailing garbage after the JSON body was accepted (status %d, %s)", c, b)
	}
}

// BUG (low, API contract): POST /api/config with the boolean fields omitted
// silently turns them OFF (Settings has plain bools), including for a user
// whose file never mentioned them and so had the default true.
func TestArea4_OmittedBoolsDoNotSilentlyDisableFeatures(t *testing.T) {
	h := newHarness(t)
	// no config file: defaults are block_quic=true dns_takeover=true
	body := `{"engines":["tlsrec"],"spoof_sni":"a.com","retest_hours":3,"hedge_ms":1200}`
	if c, b := h.do(t, "POST", "/api/config", body, nil); c == 200 {
		var m map[string]any
		_ = json.Unmarshal(h.saved, &m)
		if m["block_quic"] == false || m["dns_takeover"] == false {
			t.Errorf("omitted block_quic/dns_takeover were saved as false: %v", m)
		}
	} else {
		t.Logf("rejected with %d %s (also acceptable)", c, b)
	}
}

// Hardening: a Server built with an empty token accepts requests that send no
// token at all (subtle.ConstantTimeCompare of two empty slices is 1).
// NewToken never returns "", so this is only reachable through misuse of New.
func TestArea4_EmptyTokenServerRejectsMissingToken(t *testing.T) {
	h := newHarness(t)
	h.srv.Token = ""
	if c, _ := h.do(t, "GET", "/api/status", "", map[string]string{"X-Token": ""}); c == 200 {
		t.Logf("hardening note (not reachable via NewToken): server with empty Token served a request carrying no token")
	}
}

// ---------------------------------------------------------------------------
// Things that hold (regression guards for the checks the page relies on).

func TestArea4_HostAndOriginMatrix(t *testing.T) {
	h := newHarness(t)
	port := strings.TrimPrefix(h.ts.URL, "http://127.0.0.1:")
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]", "127.0.0.1:" + port + ".evil.com", "localhost.:" + port, "LOCALHOST:" + port + " ", "0.0.0.0:" + port, "127.1:" + port, ""} {
		req := map[string]string{"Host": host}
		if c, _ := h.do(t, "GET", "/api/status", "", req); c != 403 && host != "" {
			t.Errorf("Host %q accepted: %d", host, c)
		}
	}
	for _, o := range []string{"null", "http://evil.com", "https://127.0.0.1:" + port, "http://127.0.0.1", "http://127.0.0.1:" + port + "/", "http://127.0.0.1:" + port + "@evil.com", "http://localhost:1", "file://", "HTTP://127.0.0.1:" + port} {
		if c, _ := h.do(t, "POST", "/api/pause", "", map[string]string{"Origin": o}); c != 403 {
			t.Errorf("Origin %q accepted: %d", o, c)
		}
	}
	for _, o := range []string{"http://127.0.0.1:" + port, "http://localhost:" + port} {
		if c, _ := h.do(t, "POST", "/api/pause", "", map[string]string{"Origin": o}); c != 200 {
			t.Errorf("legit Origin %q refused: %d", o, c)
		}
	}
	// token is required even for 404 paths, and the token is not accepted via cookie / other header names
	if c, _ := h.do(t, "GET", "/nope", "", map[string]string{"X-Token": ""}); c != 403 {
		t.Errorf("unauthenticated 404 path leaks existence: %d", c)
	}
	if c, _ := h.do(t, "GET", "/api/status", "", map[string]string{"X-Token": "", "Cookie": "t=" + tok, "Authorization": "Bearer " + tok}); c != 403 {
		t.Errorf("token accepted from cookie/authorization: %d", c)
	}
	// wrong length tokens
	for _, bad := range []string{"t", tok + "x", tok[:len(tok)-1], strings.ToUpper(tok)} {
		if c, _ := h.do(t, "GET", "/api/status", "", map[string]string{"X-Token": bad}); c != 403 {
			t.Errorf("token %q accepted", bad)
		}
	}
}

func TestArea4_SecurityHeadersOnEveryResponse(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/?t=" + tok, "/app.js?t=" + tok, "/api/status", "/nope", "/api/status?t=bad"} {
		req, _ := http.NewRequest("GET", h.ts.URL+p, nil)
		req.Header.Set("X-Token", tok)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		for _, k := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Cache-Control", "Referrer-Policy", "X-Frame-Options"} {
			if resp.Header.Get(k) == "" {
				t.Errorf("%s lacks %s", p, k)
			}
		}
	}
}

// The page substitutes the token into HTML: it must stay inside the markup
// the browser trusts (hex only) and the HTML must not hold inline script.
func TestArea4_PageHasNoInlineScriptAndTokenIsHex(t *testing.T) {
	h := newHarness(t)
	h.srv.Token = NewToken()
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(h.srv.Token) {
		t.Fatalf("token format %q", h.srv.Token)
	}
	//lint:ignore SA4000 two calls, two random tokens
	if NewToken() == NewToken() {
		t.Fatal("tokens repeat")
	}
	_, body := h.do(t, "GET", "/?t="+h.srv.Token, "", map[string]string{"X-Token": h.srv.Token})
	for _, m := range regexp.MustCompile(`(?is)<script[^>]*>`).FindAllString(body, -1) {
		if !strings.Contains(m, "src=") {
			t.Errorf("inline script: %s", m)
		}
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(body) {
		t.Error("inline event handler in index.html (CSP would block it)")
	}
	if regexp.MustCompile(`(?i)\sstyle\s*=`).MatchString(body) {
		t.Error("inline style attribute in index.html (CSP style-src 'self' blocks it)")
	}
}

// The scripts must only write server data with textContent / Option, never innerHTML.
func TestArea4_AppJSNeverUsesInnerHTML(t *testing.T) {
	for _, name := range []string{"common.js", "app.js", "mini.js"} {
		b, err := os.ReadFile("web/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s uses %s", name, bad)
			}
		}
	}
}

func TestArea4_ReadBodyLimitAndTypes(t *testing.T) {
	h := newHarness(t)
	big := `{"domain":"` + strings.Repeat("a", 70<<10) + `"}`
	if c, _ := h.do(t, "POST", "/api/add", big, nil); c != 400 {
		t.Errorf("oversize body: %d", c)
	}
	for name, body := range map[string]string{
		"array":       `[]`,
		"null":        `null`,
		"number":      `1`,
		"wrong type":  `{"domain":5}`,
		"empty":       ``,
		"truncated":   `{"domain":"a.com"`,
		"nul byte":    "{\"domain\":\"a\x00.com\"}",
		"engine only": `{"engine":"tlsrec"}`,
	} {
		c, _ := h.do(t, "POST", "/api/add", body, nil)
		if c == 200 {
			t.Errorf("%s: accepted", name)
		}
		if c >= 500 && c != 502 {
			t.Errorf("%s: server error %d", name, c)
		}
	}
	// `null` decodes into the struct without error and leaves Domain empty -> 400
	if c, _ := h.do(t, "POST", "/api/add", `null`, nil); c != 400 {
		t.Errorf("null body: %d", c)
	}
	// unicode whitespace around the domain is trimmed only by TrimSpace
	if c, _ := h.do(t, "POST", "/api/add", `{"domain":" "}`, nil); c == 200 {
		t.Logf("NBSP-only domain forwarded (daemon decides): %d", c)
	}
}

// Unknown methods / HEAD on write endpoints.
func TestArea4_MethodsAreStrict(t *testing.T) {
	h := newHarness(t)
	for _, m := range []string{"PUT", "DELETE", "PATCH", "OPTIONS"} {
		if c, _ := h.do(t, m, "/api/pause", "", nil); c != 405 {
			t.Errorf("%s /api/pause: %d", m, c)
		}
		if c, _ := h.do(t, m, "/api/config", "", nil); c != 405 {
			t.Errorf("%s /api/config: %d", m, c)
		}
	}
	if c, _ := h.do(t, "HEAD", "/api/pause", "", nil); c != 405 {
		t.Errorf("HEAD /api/pause: %d", c)
	}
	// a GET must never reach a state-changing daemon command
	h.do(t, "GET", "/api/pause", "", nil)
	h.do(t, "GET", "/api/resume", "", nil)
	h.do(t, "GET", "/api/clean/reset", "", nil)
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.reqs {
		t.Errorf("GET reached the daemon with %q", r.Cmd)
	}
}

// ---------------------------------------------------------------------------
// config GET / save

func TestArea4_GetConfigVariants(t *testing.T) {
	h := newHarness(t)
	type resp struct {
		Warning  string   `json:"warning"`
		Settings Settings `json:"settings"`
	}
	get := func() resp {
		c, b := h.do(t, "GET", "/api/config", "", nil)
		if c != 200 {
			t.Fatalf("get: %d %s", c, b)
		}
		var r resp
		if err := json.Unmarshal([]byte(b), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	// missing file -> defaults, no warning
	if r := get(); r.Warning != "" || len(r.Settings.Engines) == 0 {
		t.Errorf("missing file: %+v", r)
	}
	for name, content := range map[string]string{
		"garbage":       `{not json`,
		"empty file":    ``,
		"array":         `[1,2]`,
		"engines null":  `{"engines":null}`,
		"bad engine":    `{"engines":["zapret"]}`,
		"out of range":  `{"hedge_ms":1}`,
		"wrong type":    `{"hedge_ms":"fast"}`,
		"BOM":           "\xef\xbb\xbf{}",
		"only spaces":   "   \n",
		"float for int": `{"retest_hours":3.0}`,
	} {
		os.WriteFile(h.cfg, []byte(content), 0o644)
		r := get()
		if r.Warning == "" {
			t.Errorf("%s: no warning for a config the daemon will ignore", name)
		}
		if len(r.Settings.Engines) == 0 {
			t.Errorf("%s: GET returned an empty engine list; the page would render an unusable form", name)
		}
	}
	// directory instead of a file
	os.Remove(h.cfg)
	os.Mkdir(h.cfg, 0o755)
	if r := get(); r.Warning == "" || len(r.Settings.Engines) == 0 {
		t.Errorf("directory as config: %+v", r)
	}
}

func goodSettings() Settings {
	return Settings{Engines: []string{"tlsrec", "ciadpi"}, SpoofSNI: "www.google.com", DNSTakeover: true, BlockQUIC: true, RetestHours: 3, HedgeMS: 1200}
}

func TestArea4_MergeConfigEdges(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")

	// existing keys in other case must not override the page's value after the merge
	os.WriteFile(p, []byte(`{"Engines":["warp"],"SPOOF_SNI":"old.example","Hedge_MS":99999,"warp_profile":"/x"}`), 0o644)
	out, err := MergeConfig(p, goodSettings())
	if err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	if err := json.Unmarshal(out, &c); err != nil {
		t.Fatal(err)
	}
	if c.Engines[0] != "tlsrec" || c.SpoofSNI != "www.google.com" || c.HedgeMS != 1200 {
		t.Errorf("case-variant keys won over the page's values: %+v", c)
	}

	// result must always be loadable by the daemon's own loader
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(p); err != nil {
		t.Errorf("saved file does not load: %v", err)
	}

	// invalid existing JSON is reported, not overwritten
	os.WriteFile(p, []byte(`{oops`), 0o644)
	if _, err := MergeConfig(p, goodSettings()); err == nil {
		t.Error("corrupt existing config silently replaced")
	}
	// JSON array root
	os.WriteFile(p, []byte(`[]`), 0o644)
	if _, err := MergeConfig(p, goodSettings()); err == nil {
		t.Error("array root accepted")
	}
	// existing file unreadable (directory)
	if _, err := MergeConfig(dir, goodSettings()); err == nil {
		t.Error("directory accepted as config")
	}
	// settings that must be refused
	bad := map[string]func(*Settings){
		"nil engines":     func(s *Settings) { s.Engines = nil },
		"neg retest":      func(s *Settings) { s.RetestHours = -1 },
		"neg hedge":       func(s *Settings) { s.HedgeMS = -1 },
		"zero hedge":      func(s *Settings) { s.HedgeMS = 0 },
		"max int retest":  func(s *Settings) { s.RetestHours = int(^uint(0) >> 1) },
		"sni newline":     func(s *Settings) { s.SpoofSNI = "a.com\nb.com" },
		"sni tab inside":  func(s *Settings) { s.SpoofSNI = "a\tb" },
		"sni unicode":     func(s *Settings) { s.SpoofSNI = "bücher.de" },
		"sni quote":       func(s *Settings) { s.SpoofSNI = `a"b` },
		"sni backslash":   func(s *Settings) { s.SpoofSNI = `a\b` },
		"sni slash":       func(s *Settings) { s.SpoofSNI = "a/b" },
		"sni del char":    func(s *Settings) { s.SpoofSNI = "a\x7fb" },
		"sni nul":         func(s *Settings) { s.SpoofSNI = "a\x00b" },
		"engine case":     func(s *Settings) { s.Engines = []string{"TLSREC"} },
		"engine space":    func(s *Settings) { s.Engines = []string{" tlsrec"} },
		"engine empty":    func(s *Settings) { s.Engines = []string{""} },
		"all five dup":    func(s *Settings) { s.Engines = []string{"tlsrec", "ciadpi", "tlsrec"} },
		"warp no profile": func(s *Settings) { s.Engines = []string{"tlsrec", "warp"} },
	}
	os.Remove(p)
	for name, mut := range bad {
		s := goodSettings()
		mut(&s)
		if _, err := MergeConfig(p, s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// BUG (low): spoof_sni validation lets through names that are not hostnames
// ("..", ".", "-", "*", "a:b", "[x]", ""-less dots); the daemon then hands them
// to sing-box as tls_spoof. Whether sing-box rejects them at `check` time is
// what matters: if it does, the saved config bricks capture after the restart.
func TestArea4_SpoofSNIValuesSingBoxCheck(t *testing.T) {
	bin := ""
	for _, c := range []string{filepath.Join("..", "..", "bin", "sing-box")} {
		if _, err := os.Stat(c); err == nil {
			bin, _ = filepath.Abs(c)
		}
	}
	if bin == "" {
		t.Skip("no sing-box binary")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	for _, sni := range []string{"a..b", ".", "-", "*", "a:b", "[x]", "...", "a_b", "1", "www.google.com."} {
		s := goodSettings()
		s.Engines = []string{"tlsspoof"}
		s.SpoofSNI = sni
		if _, err := MergeConfig(p, s); err != nil {
			continue // rejected by the page: fine
		}
		rd := t.TempDir()
		if err := singbox.WriteRuleSet(rd, "tlsspoof", []string{"discord.com"}); err != nil {
			t.Fatal(err)
		}
		cfg, err := singbox.Build(singbox.Options{
			Engines:      []singbox.Engine{{Name: "tlsspoof", Kind: singbox.TLSSpoof, Port: 21085}},
			ObserverPort: 21082, RuleDir: rd, Tun: true, IPv4Only: true, SpoofSNI: sni,
		})
		if err != nil {
			t.Errorf("sni %q: build: %v", sni, err)
			continue
		}
		f := filepath.Join(dir, "sb.json")
		os.WriteFile(f, cfg, 0o600)
		var out bytes.Buffer
		cmd := exec.Command(bin, "check", "-c", f)
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			t.Errorf("spoof_sni %q passes the page's validation but sing-box check fails: %v\n%s", sni, err, strings.TrimSpace(out.String()))
		}
	}
}

// ---------------------------------------------------------------------------
// SaveFile / AdminScript

func TestArea4_SaveDirectPermsReplaceAndNoLeftovers(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	os.WriteFile(p, []byte("old"), 0o600)
	if err := SaveFile(p, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("leftover temp files: %v", ents)
	}
	// config path is a directory: rename fails, no temp left behind, and saveAdmin must not be tried for a real error with goos=windows
	old := goos
	goos = "windows"
	defer func() { goos = old }()
	d2 := filepath.Join(dir, "sub")
	os.Mkdir(d2, 0o755)
	os.Mkdir(filepath.Join(d2, "config.json"), 0o755)
	if err := SaveFile(filepath.Join(d2, "config.json"), []byte("x")); err == nil {
		t.Error("saving over a directory succeeded")
	}
	ents, _ = os.ReadDir(d2)
	if len(ents) != 1 {
		t.Errorf("leftover temp files after failed save: %v", ents)
	}
}

// Saving through a symlinked config.json replaces the symlink with a regular
// file (the link target keeps the old content). Documented here; low.
func TestArea4_SaveThroughSymlinkReplacesLink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	link := filepath.Join(dir, "config.json")
	os.WriteFile(real, []byte("old"), 0o644)
	os.Symlink(real, link)
	if err := SaveFile(link, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(real); string(b) != "new" {
		t.Logf("symlinked config.json: link replaced by a regular file, target still %q", b)
	}
}

// End-to-end quoting check: run the generated AppleScript through the real
// osascript, with the privileged `install -o root -g wheel` swapped for an
// unprivileged install, for hostile path names.
func TestArea4_AdminScriptQuotingRealOsascript(t *testing.T) {
	if _, err := os.Stat("/usr/bin/osascript"); err != nil {
		t.Skip("no osascript")
	}
	base := t.TempDir()
	names := []string{
		"plain.json", "sp ace.json", "it's.json", `dq"x.json`, `back\slash.json`, "dollar$HOME.json",
		"tick`id`.json", "semi;touch pwned.json", "amp&.json", "paren(1).json", "glob*.json", "uni-ç-ü-ö.json", "tilde~.json",
		"star' ; touch pwned2 ; '.json", `\"; touch pwned3; "`,
	}
	for i, n := range names {
		src := filepath.Join(base, "src"+string(rune('a'+i))+"_"+n)
		dstDir := filepath.Join(base, "dst dir '"+string(rune('a'+i))+"'")
		if err := os.MkdirAll(dstDir, 0o755); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dstDir, n)
		if err := os.WriteFile(src, []byte("payload-"+n), 0o600); err != nil {
			t.Skipf("fs rejects name %q: %v", n, err)
		}
		script := AdminScript(src, dst)
		// drop the privilege parts, keep the quoting layers under test
		script = strings.Replace(script, "/usr/bin/install -m 644 -o root -g wheel ", "/usr/bin/install -m 644 ", 1)
		script = regexp.MustCompile(` with administrator privileges with prompt "[^"]*"$`).ReplaceAllString(script, "")
		cmd := exec.Command("/usr/bin/osascript", "-e", script)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		done := make(chan error, 1)
		go func() { done <- cmd.Run() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%q: osascript: %v %s", n, err, stderr.String())
				continue
			}
		case <-time.After(20 * time.Second):
			cmd.Process.Kill()
			t.Fatalf("%q: osascript hung", n)
		}
		b, err := os.ReadFile(dst)
		if err != nil || string(b) != "payload-"+n {
			t.Errorf("%q: destination wrong: %v %q", n, err, b)
		}
		for _, canary := range []string{"pwned.json", "pwned2", "pwned3"} {
			if _, err := os.Stat(filepath.Join(base, canary)); err == nil {
				t.Errorf("%q: command injection created %s", n, canary)
			}
		}
	}
}

// saveAdmin stages the file in os.TempDir() (a user-writable dir) and root's
// `install` reads it after an interactive password prompt. Nothing here can be
// tested without root; this guards the *shape*: the staged file must not be
// readable/writable by others (0600) so at least other users cannot swap it.
func TestArea4_StagedFileModeIsPrivate(t *testing.T) {
	f, err := os.CreateTemp("", "autodpi-config-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	st, _ := f.Stat()
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("os.CreateTemp mode %v", st.Mode().Perm())
	}
}

// Fake the CallFunc to return nasty payloads: the passthrough must stay valid JSON.
func TestArea4_PassthroughEmptyAndNullData(t *testing.T) {
	h := newHarness(t)
	for name, call := range map[string]CallFunc{
		"no data":   func(ipc.Request, any, time.Duration) error { return nil },
		"null data": func(r ipc.Request, out any, _ time.Duration) error { return json.Unmarshal([]byte("null"), out) },
	} {
		h.srv.Call = call
		for _, p := range []string{"/api/status", "/api/list", "/api/log"} {
			c, b := h.do(t, "GET", p, "", nil)
			if c != 200 || !json.Valid([]byte(b)) {
				t.Errorf("%s %s: %d %q", name, p, c, b)
			}
		}
	}
	// error text is JSON-escaped
	h.srv.Call = func(ipc.Request, any, time.Duration) error { return os.ErrPermission }
	c, b := h.do(t, "GET", "/api/status", "", nil)
	var m map[string]string
	if c != 502 || json.Unmarshal([]byte(b), &m) != nil || m["error"] == "" {
		t.Errorf("error body: %d %q", c, b)
	}
}

// BUG (low): nothing bounds the length of spoof_sni (only the 64 KiB body cap),
// and a DNS name cannot exceed 253 bytes (63 per label). The value becomes the
// SNI of a forged ClientHello in sing-box's tls_spoof.
func TestArea4_SpoofSNILengthIsBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	for name, sni := range map[string]string{
		"300 bytes":        strings.Repeat("a", 300),
		"64-byte label":    strings.Repeat("a", 64) + ".com",
		"20000 bytes":      strings.Repeat("a.", 10000) + "com",
		"empty label dots": "a..com",
	} {
		s := goodSettings()
		s.SpoofSNI = sni
		if _, err := MergeConfig(p, s); err == nil {
			t.Errorf("spoof_sni %s accepted (len %d)", name, len(sni))
		}
	}
}

// BUG (low): POST /api/config is not serialised. Each request runs MergeConfig
// then Save; with the real SaveFile each Save is a macOS administrator prompt
// (up to 4 minutes), so a double click stacks two password dialogs and the two
// read-merge-write sequences interleave (last one wins, silently).
func TestArea4_ConcurrentConfigSavesAreSerialised(t *testing.T) {
	h := newHarness(t)
	var cur, max int32
	h.srv.Save = func(path string, data []byte) error {
		n := atomicAdd(&cur, 1)
		for {
			m := atomicLoad(&max)
			if n <= m || atomicCAS(&max, m, n) {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
		atomicAdd(&cur, -1)
		return os.WriteFile(path, data, 0o644)
	}
	body := `{"engines":["tlsrec"],"spoof_sni":"a.com","dns_takeover":true,"block_quic":true,"retest_hours":3,"hedge_ms":1200}`
	done := make(chan int, 3)
	for i := 0; i < 3; i++ {
		go func() {
			c, _ := h.do(t, "POST", "/api/config", body, nil)
			done <- c
		}()
	}
	for i := 0; i < 3; i++ {
		<-done
	}
	if m := atomicLoad(&max); m > 1 {
		t.Errorf("%d config saves ran at the same time (would be %d stacked admin dialogs)", m, m)
	}
}
