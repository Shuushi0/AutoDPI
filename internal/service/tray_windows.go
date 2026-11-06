package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/sysx"
)

// The notification-area app (cmd/autodpi-tray) is installed next to the
// service, started at every user's sign-in and listed in the Start menu, the
// way the menu bar app sits next to the daemon on macOS. It is optional: a
// release folder without it installs the service alone.

const (
	trayName = "autodpi-tray.exe"
	runKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	runValue = "AutoDPI"
	linkName = "AutoDPI.lnk"
)

// TrayPath is where the tray app is installed.
func TrayPath(p paths.Set) string { return filepath.Join(p.Support, trayName) }

// InstallTray copies autodpi-tray.exe from next to self, registers it to
// start at sign-in (with --autostart, so a user who hid the icon is left
// alone) and creates the Start menu entry, which also brings a hidden icon
// back. It reports ErrTrayAbsent when there is nothing to install.
func InstallTray(p paths.Set, self string) error {
	src := filepath.Join(filepath.Dir(self), trayName)
	if _, err := os.Stat(src); err != nil {
		return ErrTrayAbsent
	}
	dst := TrayPath(p)
	sysx.KillByPath(dst) // a running copy locks the file (every user's)
	if err := copyExec(src, dst); err != nil {
		return fmt.Errorf(i18n.T("%s kopyalanamadı: %w", "install %s: %w"), trayName, err)
	}
	if err := sysx.SecureExe(dst); err != nil {
		return fmt.Errorf(i18n.T("%s izinleri ayarlanamadı: %w", "set permissions on %s: %w"), dst, err)
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf(i18n.T("oturum açılışında başlatma ayarlanamadı: %w", "autostart: %w"), err)
	}
	err = k.SetStringValue(runValue, `"`+dst+`" --autostart`)
	k.Close()
	if err != nil {
		return fmt.Errorf(i18n.T("oturum açılışında başlatma ayarlanamadı: %w", "autostart: %w"), err)
	}
	if err := startMenuLink(dst); err != nil {
		return fmt.Errorf(i18n.T("Başlat menüsü kaydı oluşturulamadı: %w", "Start menu: %w"), err)
	}
	return nil
}

// uninstallTray undoes InstallTray; safe to run when it never ran.
func uninstallTray(p paths.Set) {
	sysx.KillByPath(TrayPath(p))
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(runValue)
		k.Close()
	}
	if l, err := linkPath(); err == nil {
		_ = os.Remove(l)
	}
	removeOrDefer(TrayPath(p))
}

func linkPath() (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, linkName), nil
}

// startMenuLink writes the all-users Start menu shortcut through the shell's
// own COM object (WScript.Shell); the paths go in through the environment so
// nothing needs quoting.
func startMenuLink(target string) error {
	l, err := linkPath()
	if err != nil {
		return err
	}
	ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if sys, err := windows.GetSystemDirectory(); err == nil {
		ps = filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe") // not from PATH: this runs elevated
	}
	const script = `$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:AUTODPI_LINK); ` +
		`$s.TargetPath = $env:AUTODPI_TARGET; $s.WorkingDirectory = Split-Path $env:AUTODPI_TARGET; ` +
		`$s.Description = 'AutoDPI'; $s.Save()`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "AUTODPI_LINK="+l, "AUTODPI_TARGET="+target)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}
