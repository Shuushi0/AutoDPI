package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Balloon notifications on the icon fyne.io/systray put up. The library has
// no call for them, but the icon is an ordinary notification-area icon: its
// window (class SystrayClass, in this process) and id (100) are enough for
// Shell_NotifyIcon to show a balloon on it, which Windows 10 and 11 turn into
// a toast.

var (
	shell32                   = windows.NewLazySystemDLL("shell32.dll")
	pShellNotifyIcon          = shell32.NewProc("Shell_NotifyIconW")
	pFindWindowEx             = user32.NewProc("FindWindowExW")
	pGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
)

const (
	nimModify  = 1
	nifInfo    = 0x10
	niifInfo   = 1
	systrayID  = 100
	systrayCls = "SystrayClass"
)

// notifyIconData is NOTIFYICONDATAW as fyne.io/systray declares it.
type notifyIconData struct {
	Size                       uint32
	Wnd                        windows.Handle
	ID, Flags, CallbackMessage uint32
	Icon                       windows.Handle
	Tip                        [128]uint16
	State, StateMask           uint32
	Info                       [256]uint16
	Timeout, Version           uint32
	InfoTitle                  [64]uint16
	InfoFlags                  uint32
	GuidItem                   windows.GUID
	BalloonIcon                windows.Handle
}

// trayWindow finds systray's window in this process; another program using
// the same library has one of the same class.
func trayWindow() windows.Handle {
	self := windows.GetCurrentProcessId()
	var h uintptr
	for {
		h, _, _ = pFindWindowEx.Call(0, h, uintptr(unsafe.Pointer(utf16(systrayCls))), 0)
		if h == 0 {
			return 0
		}
		var pid uint32
		_, _, _ = pGetWindowThreadProcessId.Call(h, uintptr(unsafe.Pointer(&pid)))
		if pid == self {
			return windows.Handle(h)
		}
	}
}

// balloon shows a notification from the tray icon.
func balloon(title, text string) {
	h := trayWindow()
	if h == 0 {
		return
	}
	nid := notifyIconData{Wnd: h, ID: systrayID, Flags: nifInfo, InfoFlags: niifInfo}
	nid.Size = uint32(unsafe.Sizeof(nid))
	copyUTF16(nid.InfoTitle[:], title)
	copyUTF16(nid.Info[:], text)
	_, _, _ = pShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

// copyUTF16 fills dst with s, cut to fit and NUL-terminated.
func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}
