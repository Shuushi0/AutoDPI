//go:build !windows

package ui

import (
	"errors"
	"fmt"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/paths"
)

// StartService starts the installed service (launchctl kickstart) under the
// macOS administrator prompt: the compact view's start button in a plain
// `autodpi ui`, after its own shut-down button, say.
func StartService() error {
	prompt := i18n.T("AutoDPI servisini başlatmak için yönetici izni gerekiyor.", "AutoDPI needs administrator permission to start its service.")
	script := `do shell script "/bin/launchctl kickstart system/` + paths.Label + `" with administrator privileges with prompt "` + prompt + `"`
	if err := runAdminScript(script); err != nil {
		if errors.Is(err, errAdminCancelled) {
			return errors.New(i18n.T("yönetici izni iptal edildi, servis başlatılmadı", "administrator permission was cancelled; the service was not started"))
		}
		return fmt.Errorf(i18n.T("servis başlatılamadı: %s", "the service did not start: %s"), err)
	}
	return nil
}
