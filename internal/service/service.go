// Package service is the OS service manager seen from the CLI: launchd on
// macOS, the Service Control Manager on Windows.
package service

import (
	"errors"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
)

// ErrTrayAbsent is InstallTray's answer when there is no tray app to install:
// the folder install ran from has no autodpi-tray.exe, or the platform has
// none (the macOS menu bar app is copied to /Applications by hand).
var ErrTrayAbsent = errors.New("autodpi-tray.exe missing")

// stateText is a job's state as the service manager names it ("running",
// "stopped", ...) in the user's language, the way doctor shows it.
func stateText(state string) string {
	label := map[string]string{
		"running":          i18n.T("çalışıyor", "running"),
		"not running":      i18n.T("çalışmıyor", "not running"),
		"waiting":          i18n.T("bekliyor", "waiting"),
		"spawn scheduled":  i18n.T("başlatılacak", "spawn scheduled"),
		"exited":           i18n.T("çıktı", "exited"),
		"stopped":          i18n.T("durdu", "stopped"),
		"start pending":    i18n.T("başlıyor", "start pending"),
		"stop pending":     i18n.T("duruyor", "stop pending"),
		"paused":           i18n.T("duraklatıldı", "paused"),
		"pause pending":    i18n.T("duraklatılıyor", "pause pending"),
		"continue pending": i18n.T("sürdürülüyor", "continue pending"),
	}[state]
	if label == "" {
		label = state
	}
	return i18n.T("durum = ", "state = ") + label
}
