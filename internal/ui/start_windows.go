package ui

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/paths"
)

// StartService starts the installed service through a UAC prompt: the tray
// app's "Start the service", and the compact view's start button in a plain
// `autodpi ui`.
func StartService() error {
	_, err := RunElevated("sc.exe", "start "+paths.ServiceName, false)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return errors.New(i18n.T("yönetici izni verilmedi, servis başlatılmadı", "administrator permission was not given; the service was not started"))
	}
	if err != nil {
		return fmt.Errorf(i18n.T("servis başlatılamadı: %w", "the service did not start: %w"), err)
	}
	return nil
}
