package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/i18n"
)

// MergeConfig applies in over the existing config file, keeping every key the
// page does not edit (ciadpi_args, warp_profile, ...), and validates the result
// with the same rules the daemon uses. It returns the JSON to write.
//
// An existing file the service cannot use (it does not parse, or holds a
// value the service refuses) is what the service already ignores, running on
// the defaults. The save then starts from an empty file: keeping its keys
// would keep the refused value, and every save would fail on something the
// page cannot edit. The caller keeps the old file (Unusable, KeepOld).
func MergeConfig(path string, in Settings) ([]byte, error) {
	raw := map[string]json.RawMessage{}
	var had []string // the local_domains the file already holds
	if b, err := os.ReadFile(path); err == nil {
		if cur, perr := config.Parse(b); perr != nil || json.Unmarshal(b, &raw) != nil {
			raw = map[string]json.RawMessage{}
		} else {
			had = cur.LocalDomains
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if raw == nil { // the file held JSON null, which Unmarshal turns into a nil map (the daemon reads it as defaults)
		raw = map[string]json.RawMessage{}
	}
	set := func(k string, v any) {
		b, _ := json.Marshal(v)
		raw[k] = b
	}
	in.SpoofSNI = strings.TrimSpace(in.SpoofSNI)
	set("engines", in.Engines)
	set("spoof_sni", in.SpoofSNI)
	set("dns_takeover", in.DNSTakeover)
	set("block_quic", in.BlockQUIC)
	set("escalate_on_silence", in.Escalate)
	for i, d := range in.Local {
		in.Local[i] = config.NormalizeSuffix(d) // as it is matched (see config.parse)
		// An entry the user adds must not be a public suffix; one the file
		// already had stays theirs.
		if !slices.Contains(had, in.Local[i]) {
			if err := config.CheckLocalDomain(in.Local[i]); err != nil {
				return nil, err
			}
		}
	}
	if len(in.Local) == 0 {
		delete(raw, "local_domains")
	} else {
		set("local_domains", in.Local)
	}
	set("retest_hours", in.RetestHours)
	set("hedge_ms", in.HedgeMS)
	for k := range raw {
		if config.Retired(k) {
			delete(raw, k) // a setting of an earlier version that nothing reads any more
		}
	}
	set("update_check_hours", in.UpdateHours)
	if in.Language == "" {
		delete(raw, "language") // the system's: no key at all, as in a fresh file
	} else {
		set("language", in.Language)
	}

	merged, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, err
	}
	merged = append(merged, '\n')

	if in.SpoofSNI == "" {
		return nil, errors.New(i18n.T("spoof_sni boş olamaz", "spoof_sni must not be empty"))
	}
	if !config.ValidHostname(in.SpoofSNI) {
		return nil, errors.New(i18n.T("spoof_sni geçerli bir alan adı değil (en çok 253 karakter, etiketler 1-63 karakter: harf, rakam, tire)", "spoof_sni is not a valid domain name (at most 253 characters, labels of 1-63 letters, digits or hyphens)"))
	}
	// As the service will read it.
	if _, err := config.Parse(merged); err != nil {
		return nil, err
	}
	return merged, nil
}

// Unusable returns the contents of the config file at path when the service
// cannot use it (it does not parse or fails validation), nil otherwise.
func Unusable(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if _, err := config.Parse(b); err == nil {
		return nil
	}
	return b
}

// KeepOld saves what a config file held before a save replaced it, and
// returns where: beside the file when this user may write there, else in the
// temporary folder (a real install's folder is root's or the
// administrators'). Each copy has a name of its own, so a later one does not
// replace an earlier one that may still be wanted. "" when it could not be
// kept anywhere.
func KeepOld(path string, old []byte) string {
	name := filepath.Base(path) + ".broken-" + time.Now().Format("20060102-150405")
	for _, dir := range []string{filepath.Dir(path), os.TempDir()} {
		f := filepath.Join(dir, name)
		if os.WriteFile(f, old, 0o600) == nil {
			return f
		}
	}
	return ""
}

// goos selects the platform behaviour; tests override it.
var goos = runtime.GOOS

// SaveFile writes data to path. If the directory is writable by the current
// user it replaces the file atomically; otherwise it asks for administrator
// rights: the macOS authorization dialog, or on Windows a UAC prompt for
// `autodpi config-import` (saveElevated).
func SaveFile(path string, data []byte) error {
	err := saveDirect(path, data)
	if err == nil {
		return nil
	}
	if goos == "windows" {
		return saveElevated(path, data, err)
	}
	return saveAdmin(path, data)
}

// ImportConfig is `autodpi config-import FILE`, the elevated half of a
// Windows save: it validates FILE with the daemon's rules and writes it to
// path, the service's config file (never a path from the command line). FILE
// is read once: it belongs to the unelevated caller, who could change it
// between a read that is validated and one that is written.
func ImportConfig(path, file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if _, err := config.Parse(data); err != nil {
		return err
	}
	return saveDirect(path, data)
}

// writeTemp writes data to a new temporary file in dir (os.TempDir when
// empty) and returns its name; the caller removes it.
func writeTemp(dir, pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Sync(); err != nil { // before the rename: see fsx
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func saveDirect(path string, data []byte) error {
	tmp, err := writeTemp(filepath.Dir(path), ".config-*.tmp", data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	shareConfig(tmp, path)
	return os.Rename(tmp, path)
}

func saveAdmin(path string, data []byte) error {
	tmp, err := writeTemp("", "autodpi-config-*.json", data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := runAdminScript(AdminScript(tmp, path)); err != nil {
		if errors.Is(err, errAdminCancelled) {
			return errors.New(i18n.T("yönetici izni iptal edildi, config.json yazılmadı", "administrator permission was cancelled; config.json was not written"))
		}
		return fmt.Errorf(i18n.T("config.json yazılamadı: %s", "config.json could not be written: %s"), err)
	}
	return nil
}

// errAdminCancelled is runAdminScript's answer when the prompt was declined.
var errAdminCancelled = errors.New("administrator prompt cancelled")

// runAdminScript runs a `do shell script ... with administrator privileges`
// AppleScript. A declined prompt (osascript error -128) is errAdminCancelled;
// any other failure is what osascript wrote to stderr.
func runAdminScript(script string) error {
	var stderr bytes.Buffer
	cmd := exec.Command("/usr/bin/osascript", "-e", script)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if strings.Contains(msg, "-128") {
			return errAdminCancelled
		}
		return errors.New(msg)
	}
	return nil
}

// shQuote single-quotes s for /bin/sh.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// AdminScript builds the AppleScript that installs src as dst (root:wheel 0644)
// under an administrator prompt.
func AdminScript(src, dst string) string {
	sh := "/usr/bin/install -m 644 -o root -g wheel " + shQuote(src) + " " + shQuote(dst)
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(sh)
	return `do shell script "` + esc + `" with administrator privileges with prompt "` + i18n.T("AutoDPI ayarlarını kaydetmek için yönetici izni gerekiyor.", "AutoDPI needs administrator permission to save its settings.") + `"`
}
