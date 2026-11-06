package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// The few user32/dwmapi calls the popup window needs; x/sys/windows does not
// wrap them.
var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	dwmapi = windows.NewLazySystemDLL("dwmapi.dll")

	pRegisterClassEx     = user32.NewProc("RegisterClassExW")
	pCreateWindowEx      = user32.NewProc("CreateWindowExW")
	pDefWindowProc       = user32.NewProc("DefWindowProcW")
	pDestroyWindow       = user32.NewProc("DestroyWindow")
	pShowWindow          = user32.NewProc("ShowWindow")
	pSetWindowPos        = user32.NewProc("SetWindowPos")
	pSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	pIsWindowVisible     = user32.NewProc("IsWindowVisible")
	pFindWindow          = user32.NewProc("FindWindowW")
	pPostMessage         = user32.NewProc("PostMessageW")
	pGetMessage          = user32.NewProc("GetMessageW")
	pTranslateMessage    = user32.NewProc("TranslateMessage")
	pDispatchMessage     = user32.NewProc("DispatchMessageW")
	pPostQuitMessage     = user32.NewProc("PostQuitMessage")
	pSetTimer            = user32.NewProc("SetTimer")
	pKillTimer           = user32.NewProc("KillTimer")
	pGetCursorPos        = user32.NewProc("GetCursorPos")
	pMonitorFromPoint    = user32.NewProc("MonitorFromPoint")
	pGetMonitorInfo      = user32.NewProc("GetMonitorInfoW")
	pGetDpiForWindow     = user32.NewProc("GetDpiForWindow")
	pSetDpiAwarenessCtx  = user32.NewProc("SetProcessDpiAwarenessContext")
	pLoadCursor          = user32.NewProc("LoadCursorW")
	pMessageBox          = user32.NewProc("MessageBoxW")
	pDwmSetWindowAttr    = dwmapi.NewProc("DwmSetWindowAttribute")
	pAllowSetForeground  = user32.NewProc("AllowSetForegroundWindow")
)

const (
	wmDestroy    = 0x0002
	wmSize       = 0x0005
	wmActivate   = 0x0006
	wmClose      = 0x0010
	wmTimer      = 0x0113
	wmDPIChanged = 0x02E0
	wmApp        = 0x8000

	wsPopup        = 0x80000000
	wsExToolWindow = 0x00000080
	wsExTopmost    = 0x00000008
	csDropShadow   = 0x00020000

	swHide       = 0
	swShow       = 5
	swpNoActive  = 0x0010
	hwndTopmost  = ^uintptr(0) // (HWND)-1
	monitorNear  = 2
	idcArrow     = 32512
	waInactive   = 0
	mbOKCancel   = 0x00000001
	mbIconInfo   = 0x00000040
	mbTopmost    = 0x00040000
	idOK         = 1
	asfwAny      = ^uintptr(0) // ASFW_ANY
	dwmCornerPrf = 33          // DWMWA_WINDOW_CORNER_PREFERENCE (Windows 11)
	dwmRound     = 2           // DWMWCP_ROUND
)

// Messages the tray posts to the popup window.
const (
	msgToggle = wmApp + 1 // show, or hide if it is showing
	msgHide   = wmApp + 2
)

type point struct{ X, Y int32 }

type rect struct{ Left, Top, Right, Bottom int32 }

type msg struct {
	Hwnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	private uint32
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type monitorInfo struct {
	Size    uint32
	Monitor rect
	Work    rect
	Flags   uint32
}

func utf16(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

// findWindow returns the top-level window of class, or 0.
func findWindow(class string) windows.Handle {
	h, _, _ := pFindWindow.Call(uintptr(unsafe.Pointer(utf16(class))), 0)
	return windows.Handle(h)
}

func postMessage(h windows.Handle, m uint32) {
	_, _, _ = pPostMessage.Call(uintptr(h), uintptr(m), 0, 0)
}

// confirm shows an OK/Cancel message box and reports whether OK was chosen.
func confirm(title, text string) bool {
	r, _, _ := pMessageBox.Call(0, uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16(title))),
		mbOKCancel|mbIconInfo|mbTopmost)
	return r == idOK
}
