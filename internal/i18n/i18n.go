// Package i18n picks the language of everything a person reads: Turkish or
// English. Texts are written in place as pairs, T("Türkçe", "English"), so
// each message keeps both versions side by side.
//
// The choice, first match wins: the AUTODPI_LANG environment variable, the
// "language" key of config.json, the system's language (Turkish when it is
// Turkish, English for every other).
package i18n

import (
	"encoding/json"
	"os"
	"strings"
	"sync"

	"github.com/Shuushi0/AutoDPI/internal/paths"
)

var (
	mu       sync.Mutex
	resolved bool
	turkish  bool
)

// T returns tr when the language is Turkish and en otherwise.
func T(tr, en string) string {
	if Turkish() {
		return tr
	}
	return en
}

// Turkish reports whether the language is Turkish.
func Turkish() bool {
	mu.Lock()
	defer mu.Unlock()
	if !resolved {
		turkish, resolved = resolve(), true
	}
	return turkish
}

// Lang is "tr" or "en".
func Lang() string {
	if Turkish() {
		return "tr"
	}
	return "en"
}

// Reload forgets the choice, so the next call reads the settings again (after
// a settings page changed the language).
func Reload() {
	mu.Lock()
	resolved = false
	mu.Unlock()
}

// Normalize maps a language tag (tr, tr_TR.UTF-8, en-US, ...) to "tr", "en",
// or "" when it names neither.
func Normalize(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	switch {
	case tag == "tr" || strings.HasPrefix(tag, "tr_") || strings.HasPrefix(tag, "tr-") || strings.HasPrefix(tag, "tr."):
		return "tr"
	case tag == "en" || strings.HasPrefix(tag, "en_") || strings.HasPrefix(tag, "en-") || strings.HasPrefix(tag, "en."):
		return "en"
	}
	return ""
}

func resolve() bool {
	if l := Normalize(os.Getenv("AUTODPI_LANG")); l != "" {
		return l == "tr"
	}
	if l := Configured(); l != "" {
		return l == "tr"
	}
	return System() == "tr"
}

// Configured returns the language config.json sets ("tr", "en"), or "" for
// the system's.
func Configured() string {
	b, err := os.ReadFile(paths.Default().Config)
	if err != nil {
		return ""
	}
	var c struct {
		Language string `json:"language"`
	}
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	return Normalize(c.Language)
}

// System is the system's language, "tr" or "en", whatever the settings say.
func System() string {
	if Normalize(systemLanguage()) == "tr" {
		return "tr"
	}
	return "en"
}
