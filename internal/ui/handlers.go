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
		writeCallErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

// writeCallErr answers a failed control-socket call. kind tells the page what
// to show: the service is off (down), this user may not reach it (denied), it
// did not answer (busy), or it answered with an error ("").
func writeCallErr(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "kind": ipc.Kind(err)})
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
	UpdateHours int      `json:"update_check_hours"`
}

// KnownEngines is the list the engine-order editor offers.
var KnownEngines = []string{"tlsrec", "ciadpi", "tlsspoof", "tlsfrag", "warp"}

// offered is KnownEngines for this config: warp only where a profile is set
// (warp_profile, which the page does not edit). Offered without one, it could
// be ticked and then never saved.
func offered(c config.Config) []string {
	out := make([]string, 0, len(KnownEngines))
	for _, e := range KnownEngines {
		if e != "warp" || c.WarpProfile != "" {
			out = append(out, e)
		}
	}
	return out
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	c, err := config.Load(s.ConfigPath)
	out := map[string]any{"path": s.ConfigPath}
	if err != nil {
		// The service runs on the defaults while the file is like this (it
		// does not parse, or holds a value the service refuses), and says so
		// nowhere else: the page does, and a save puts it right.
		out["warning"] = i18n.T("config.json kullanılamıyor, servis varsayılan ayarlarla çalışıyor. Kaydet'e basınca dosya bu sayfadaki ayarlarla yeniden yazılır; eski dosyanın bir kopyası saklanır. Ayrıntı: ",
			"config.json cannot be used, so the service runs on the default settings. Saving writes the file anew from this page; a copy of the old file is kept. Detail: ") + err.Error()
		out["broken"] = true
		c = config.Default() // what the service runs on, and what a save starts from
	} else if len(c.Warnings) > 0 {
		out["warning"] = strings.Join(c.Warnings, "; ")
	}
	out["known_engines"] = offered(c)
	out["settings"] = Settings{c.Engines, c.SpoofSNI, c.DNSTakeover, c.BlockQUIC, c.EscalateOnSilence, c.LocalDomains, c.RetestHours, c.HedgeMS, c.Language, c.UpdateCheckHours}
	out["system_language"] = i18n.System()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	raw, ok := readRaw(w, r)
	if !ok {
		return
	}
	var present map[string]json.RawMessage
	_ = json.Unmarshal(raw, &present)
	// "auto_update" was a setting until 0.1.1. A page that was left open
	// over the update still sends it: taken out, not refused as unknown.
	if _, ok := present["auto_update"]; ok {
		delete(present, "auto_update")
		if b, err := json.Marshal(present); err == nil {
			raw = b
		}
	}
	var in Settings
	if err := decodeStrict(raw, &in); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf(i18n.T("geçersiz istek: %v", "invalid request: %v"), err))
		return
	}

	// One save at a time: each is a password dialog on macOS (up to minutes),
	// and the read-merge-write sequences of two saves must not interleave.
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	// A field the request leaves out keeps the value it has now.
	cur, err := config.Load(s.ConfigPath)
	old := Unusable(s.ConfigPath)
	unreadable := err != nil // the service runs on defaults then, whatever the file says
	if err != nil {
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
	if _, ok := present["update_check_hours"]; !ok {
		in.UpdateHours = cur.UpdateCheckHours
	}
	in.Local = append([]string(nil), in.Local...) // MergeConfig tidies the entries in place
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
	// The service reads the update setting and the language afresh; for the
	// rest it has to start again, and it can do that itself (it runs with
	// the rights for it): no command for the user to type.
	live := in
	live.UpdateHours, live.Language = cur.UpdateCheckHours, cur.Language
	was := Settings{cur.Engines, cur.SpoofSNI, cur.DNSTakeover, cur.BlockQUIC, cur.EscalateOnSilence, cur.LocalDomains, cur.RetestHours, cur.HedgeMS, cur.Language, cur.UpdateCheckHours}
	message, restarted := i18n.T("Ayarlar kaydedildi.", "Settings saved."), false
	if unreadable || !sameSettings(live, was) {
		switch rerr := s.Call(ipc.Request{Cmd: "maint", Action: "restart"}, nil, 20*time.Second); {
		case rerr == nil:
			restarted = true
			message = i18n.T("Ayarlar kaydedildi; servis yeni ayarlarla yeniden başlıyor (birkaç saniye).", "Settings saved; the service is restarting with them (a few seconds).")
		case ipc.Kind(rerr) == ipc.KindDown:
			message = i18n.T("Ayarlar kaydedildi; servis başladığında geçerli olur.", "Settings saved; they apply when the service starts.")
		case ipc.Kind(rerr) == ipc.KindBusy:
			message = i18n.T("Ayarlar kaydedildi, ama servis şu an yanıt vermiyor. Biraz sonra Bakım bölümündeki Yeniden başlat düğmesine basın.",
				"Settings saved, but the service is not answering right now. Press the Restart button under Maintenance in a moment.")
		default:
			// It refused (not run by the service manager, or this user may
			// not ask): the Restart button would be refused the same way.
			message = i18n.T("Ayarlar kaydedildi; servis bir sonraki başlayışında geçerli olur. (Şimdi yeniden başlatılamadı: ", "Settings saved; they apply the next time the service starts. (It could not be restarted now: ") +
				strings.TrimRight(rerr.Error(), ". ") + ".)"
		}
	}
	if old != nil {
		// Only now, after a save that went through: a refused one must not
		// leave copies behind, and the copy is said where it really is.
		if kept := KeepOld(s.ConfigPath, old); kept != "" {
			message += i18n.T(" Eski dosya burada saklandı: ", " The old file was kept here: ") + kept
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "restarted": restarted, "message": message})
}

// sameSettings reports whether two sets of settings are the same to the
// service. The page sends an empty list where the file has no key at all, and
// may leave a space around the server name: neither is a change, and counting
// them as one restarted the service on every single save.
func sameSettings(a, b Settings) bool {
	norm := func(s Settings) Settings {
		if len(s.Local) == 0 {
			s.Local = nil
		}
		if len(s.Engines) == 0 {
			s.Engines = nil
		}
		s.SpoofSNI = strings.TrimSpace(s.SpoofSNI)
		return s
	}
	x, _ := json.Marshal(norm(a))
	y, _ := json.Marshal(norm(b))
	return bytes.Equal(x, y)
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
