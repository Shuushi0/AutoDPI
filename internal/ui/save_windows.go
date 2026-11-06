package ui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/sysx"
)

var (
	shell32            = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteEx = shell32.NewProc("ShellExecuteExW")
)

// shellExecuteInfo is SHELLEXECUTEINFOW.
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         windows.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     windows.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hIcon        windows.Handle
	hProcess     windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
	swHide                = 0
)

// RunElevated starts exe with args through a UAC prompt and, when wait is
// set, waits for it and returns its exit code. A declined prompt is
// windows.ERROR_CANCELLED.
func RunElevated(exe, args string, wait bool) (uint32, error) {
	info := shellExecuteInfo{
		fMask:        seeMaskNoAsync,
		lpVerb:       windows.StringToUTF16Ptr("runas"),
		lpFile:       windows.StringToUTF16Ptr(exe),
		lpParameters: windows.StringToUTF16Ptr(args),
		nShow:        swHide,
	}
	if wait {
		info.fMask |= seeMaskNoCloseProcess
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, err := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return 0, err
	}
	if !wait || info.hProcess == 0 {
		return 0, nil
	}
	defer windows.CloseHandle(info.hProcess)
	if _, err := windows.WaitForSingleObject(info.hProcess, 5*60*1000); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return 0, err
	}
	return code, nil
}

// adminExe is the autodpi.exe that does the elevated part: the installed one,
// or the running binary when that is autodpi.exe itself (a run from the
// extracted folder before installing).
func adminExe() (string, error) {
	if p := paths.Default().Installed; p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	self, err := os.Executable()
	if err == nil && strings.EqualFold(filepath.Base(self), "autodpi.exe") {
		return self, nil
	}
	return "", errors.New(i18n.T("autodpi.exe bulunamadı (servis kurulu değil)", "autodpi.exe not found (the service is not installed)"))
}

// shareConfig gives the service's new config file, before it replaces the
// old one, the access the tray app needs: signed-in users read it, only
// administrators change it (sysx.ShareConfig). Best effort: the service sets
// it again at every start.
func shareConfig(tmp, dst string) {
	if p := paths.Default(); p.System && strings.EqualFold(dst, p.Config) {
		_ = sysx.ShareConfig(tmp)
	}
}

// saveElevated writes data to a temporary file and has an elevated
// `autodpi config-import` validate and install it: the config file lives in
// a directory only SYSTEM and Administrators may write.
func saveElevated(path string, data []byte, cause error) error {
	// config-import writes only the service's own file.
	if !strings.EqualFold(path, paths.Default().Config) {
		return fmt.Errorf(i18n.T("config.json yazılamadı (%v)", "config.json could not be written (%v)"), cause)
	}
	exe, err := adminExe()
	if err != nil {
		return fmt.Errorf(i18n.T("config.json yazılamadı (%v): %w", "config.json could not be written (%v): %w"), cause, err)
	}
	tmp, err := writeTemp("", "autodpi-config-*.json", data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	code, err := RunElevated(exe, `config-import "`+tmp+`"`, true)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return errors.New(i18n.T("yönetici izni verilmedi, config.json yazılmadı", "administrator permission was not given; config.json was not written"))
	}
	if err != nil {
		return fmt.Errorf(i18n.T("config.json yazılamadı: %w", "config.json could not be written: %w"), err)
	}
	if code != 0 {
		return fmt.Errorf(i18n.T("config.json yazılamadı (config-import çıkış kodu %d)", "config.json could not be written (config-import exit code %d)"), code)
	}
	return nil
}
