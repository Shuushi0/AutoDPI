package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
)

// ctl performs one control-socket request and returns the raw response data.
func (s *Server) ctl(req ipc.Request, timeout time.Duration) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := s.Call(req, &raw, timeout); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		raw = json.RawMessage("null")
	}
	return raw, nil
}

// forward sends req to the daemon and writes its answer, or its error as a
// bad gateway.
func (s *Server) forward(w http.ResponseWriter, req ipc.Request, timeout time.Duration) {
	raw, err := s.ctl(req, timeout)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

func (s *Server) passthrough(req ipc.Request, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.forward(w, req, timeout) }
}

// readRaw reads a request body of at most 64 KiB.
func readRaw(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf(i18n.T("geçersiz istek: %v", "invalid request: %v"), err))
		return nil, false
	}
	return b, true
}

// decodeStrict decodes exactly one JSON value into v: unknown fields and
// anything after the value are errors.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New(i18n.T("isteğin sonunda fazladan veri var", "extra data after the request"))
	}
	return nil
}

func readBody(w http.ResponseWriter, r *http.Request, v any) bool {
	b, ok := readRaw(w, r)
	if !ok {
		return false
	}
	if err := decodeStrict(b, v); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf(i18n.T("geçersiz istek: %v", "invalid request: %v"), err))
		return false
	}
	return true
}

func (s *Server) add(w http.ResponseWriter, r *http.Request) {
	var in struct{ Domain, Engine string }
	if !readBody(w, r, &in) {
		return
	}
	in.Domain = strings.TrimSpace(in.Domain)
	if in.Domain == "" {
		writeErr(w, http.StatusBadRequest, errors.New(i18n.T("alan adı boş", "the domain is empty")))
		return
	}
	s.forward(w, ipc.Request{Cmd: "add", Domain: in.Domain, Engine: in.Engine}, 10*time.Second)
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	var in struct{ Domain string }
	if !readBody(w, r, &in) {
		return
	}
	in.Domain = strings.TrimSpace(in.Domain)
	if in.Domain == "" {
		writeErr(w, http.StatusBadRequest, errors.New(i18n.T("alan adı boş", "the domain is empty")))
		return
	}
	s.forward(w, ipc.Request{Cmd: "remove", Domain: in.Domain}, 10*time.Second)
}

// Settings is the subset of config.json the page edits.
type Settings struct {
	Engines     []string `json:"engines"`
	SpoofSNI    string   `json:"spoof_sni"`
	DNSTakeover bool     `json:"dns_takeover"`
	BlockQUIC   bool     `json:"block_quic"`
	Escalate    bool     `json:"escalate_on_silence"`
	Local       []string `json:"local_domains"`
	RetestHours int      `json:"retest_hours"`
	HedgeMS     int      `json:"hedge_ms"`
	Language    string   `json:"language"` // "tr", "en" or "" (the system's)
	AutoUpdate  bool     `json:"auto_update"`
	UpdateHours int      `json:"update_check_hours"`
}

// KnownEngines is the list the engine-order editor offers.
var KnownEngines = []string{"tlsrec", "ciadpi", "tlsspoof", "tlsfrag", "warp"}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	c, err := config.Load(s.ConfigPath)
	out := map[string]any{"path": s.ConfigPath, "known_engines": KnownEngines}
	if err != nil {
		out["warning"] = err.Error()
		if c.Engines == nil {
			c = config.Default()
		}
	}
	out["settings"] = Settings{c.Engines, c.SpoofSNI, c.DNSTakeover, c.BlockQUIC, c.EscalateOnSilence, c.LocalDomains, c.RetestHours, c.HedgeMS, c.Language, c.AutoUpdate, c.UpdateCheckHours}
	out["system_language"] = i18n.System()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	raw, ok := readRaw(w, r)
	if !ok {
		return
	}
	var in Settings
	if err := decodeStrict(raw, &in); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf(i18n.T("geçersiz istek: %v", "invalid request: %v"), err))
		return
	}
	var present map[string]json.RawMessage
	_ = json.Unmarshal(raw, &present)

	// One save at a time: each is a password dialog on macOS (up to minutes),
	// and the read-merge-write sequences of two saves must not interleave.
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	// A field the request leaves out keeps the value it has now.
	cur, err := config.Load(s.ConfigPath)
	if err != nil && cur.Engines == nil {
		cur = config.Default()
	}
	if _, ok := present["engines"]; !ok {
		in.Engines = cur.Engines
	}
	if _, ok := present["spoof_sni"]; !ok {
		in.SpoofSNI = cur.SpoofSNI
	}
	if _, ok := present["dns_takeover"]; !ok {
		in.DNSTakeover = cur.DNSTakeover
	}
	if _, ok := present["block_quic"]; !ok {
		in.BlockQUIC = cur.BlockQUIC
	}
	if _, ok := present["escalate_on_silence"]; !ok {
		in.Escalate = cur.EscalateOnSilence
	}
	if _, ok := present["local_domains"]; !ok {
		in.Local = cur.LocalDomains
	}
	if _, ok := present["retest_hours"]; !ok {
		in.RetestHours = cur.RetestHours
	}
	if _, ok := present["hedge_ms"]; !ok {
		in.HedgeMS = cur.HedgeMS
	}
	if _, ok := present["language"]; !ok {
		in.Language = cur.Language
	}
	if _, ok := present["auto_update"]; !ok {
		in.AutoUpdate = cur.AutoUpdate
	}
	if _, ok := present["update_check_hours"]; !ok {
		in.UpdateHours = cur.UpdateCheckHours
	}
	data, err := MergeConfig(s.ConfigPath, in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Save(s.ConfigPath, data); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	i18n.Reload() // a changed language shows from the next page load on
	writeJSON(w, http.StatusOK, map[string]any{
		"saved":   true,
		"message": i18n.T("Ayarlar kaydedildi. Uygulanması için servisin yeniden başlatılması gerekir (", "Settings saved. Restart the service to apply them (") + restartHint(goos) + ").",
	})
}

// restartHint is the command that restarts the installed service.
func restartHint(goos string) string {
	if goos == "windows" {
		return i18n.T("yönetici PowerShell'de: Restart-Service AutoDPI", "in an administrator PowerShell: Restart-Service AutoDPI")
	}
	return "sudo launchctl kickstart -k system/com.autodpi.daemon"
}

func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if !slices.Contains(ipc.UpdateActions, action) {
		writeErr(w, http.StatusNotFound, fmt.Errorf(i18n.T("bilinmeyen güncelleme eylemi %q", "unknown update action %q"), action))
		return
	}
	s.forward(w, ipc.Request{Cmd: "update", Action: action}, 45*time.Second)
}

func (s *Server) maint(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if !slices.Contains(ipc.MaintActions, action) {
		writeErr(w, http.StatusNotFound, fmt.Errorf(i18n.T("bilinmeyen bakım eylemi %q", "unknown maintenance action %q"), action))
		return
	}
	s.forward(w, ipc.Request{Cmd: "maint", Action: action}, 20*time.Second)
}
