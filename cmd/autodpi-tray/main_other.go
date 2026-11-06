//go:build !windows

// autodpi-tray is the Windows notification-area app; macOS has its own menu
// bar app (macos-app).
package main

import (
	"fmt"
	"os"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
)

func main() {
	fmt.Fprintln(os.Stderr, i18n.T("autodpi-tray yalnızca Windows içindir; macOS'ta menü çubuğu uygulamasını (AutoDPI.app) kullanın",
		"autodpi-tray is for Windows only; on macOS use the menu bar app (AutoDPI.app)"))
	os.Exit(1)
}
