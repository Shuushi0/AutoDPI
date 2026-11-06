package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The popup is the window the tray icon opens, the counterpart of the macOS
// menu bar popover: the compact page (/mini) in a WebView2 control. It runs
// in a process of its own (`autodpi-tray --popup URL`) so the browser engine
// only costs memory while it is in use: once hidden for popupLinger the
// process exits, and the next click starts a fresh one.

const (
	popupClass  = "AutoDPIPopup"
	popupLinger = 30 * time.Second
	popupWidth  = 372 // logical pixels, the macOS popover's size; scaled by the monitor's DPI
	popupHeight = 640
	lingerTimer = 1
)

type popup struct {
	hwnd     windows.Handle
	web      *edge.Chromium
	url      string
	hiddenAt time.Time
}

var pop popup

func runPopup(url string) int {
	if pSetDpiAwarenessCtx.Find() == nil { // Windows 10 1703+
		_, _, _ = pSetDpiAwarenessCtx.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
	}
	pop.url = url
	if !pop.create() {
		return 1
	}
	pop.show()
	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return 0
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (p *popup) create() bool {
	var inst windows.Handle
	_ = windows.GetModuleHandleEx(0, nil, &inst)
	cursor, _, _ := pLoadCursor.Call(0, idcArrow)
	wc := wndClassEx{
		Style:     csDropShadow,
		WndProc:   windows.NewCallback(popupProc),
		Instance:  inst,
		Cursor:    windows.Handle(cursor),
		ClassName: utf16(popupClass),
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, _ := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return false
	}
	h, _, _ := pCreateWindowEx.Call(wsExToolWindow|wsExTopmost, uintptr(unsafe.Pointer(utf16(popupClass))),
		uintptr(unsafe.Pointer(utf16("AutoDPI"))), wsPopup, 0, 0, popupWidth, popupHeight, 0, 0, uintptr(inst), 0)
	if h == 0 {
		return false
	}
	p.hwnd = windows.Handle(h)
	if pDwmSetWindowAttr.Find() == nil {
		pref := uint32(dwmRound)
		_, _, _ = pDwmSetWindowAttr.Call(h, dwmCornerPrf, uintptr(unsafe.Pointer(&pref)), 4)
	}
	p.place()

	web := edge.NewChromium()
	if dir, err := os.UserCacheDir(); err == nil { // %LOCALAPPDATA%: the install directory is not the user's
		web.DataPath = filepath.Join(dir, "AutoDPI", "WebView2")
	}
	if !web.Embed(h) {
		// No WebView2 runtime: the full panel in the browser is the next best thing.
		openURL(strings.Replace(p.url, "/mini?", "/?", 1))
		return false
	}
	if s, err := web.GetSettings(); err == nil {
		_ = s.PutAreDefaultContextMenusEnabled(false)
		_ = s.PutAreDevToolsEnabled(false)
		_ = s.PutIsStatusBarEnabled(false)
		_ = s.PutIsZoomControlEnabled(false)
		_ = s.PutAreBrowserAcceleratorKeysEnabled(false) // no Ctrl+P, F5 or Ctrl+F in a popup
	}
	// The page's own background (mini.css) while it loads, so the window does
	// not flash white in the dark theme.
	if c := web.GetController(); c != nil {
		if c2 := c.GetICoreWebView2Controller2(); c2 != nil {
			bg := edge.COREWEBVIEW2_COLOR{A: 255, R: 0xf5, G: 0xf5, B: 0xf7}
			if appsUseDarkTheme() {
				bg = edge.COREWEBVIEW2_COLOR{A: 255, R: 0x20, G: 0x21, B: 0x24}
			}
			_ = c2.PutDefaultBackgroundColor(bg)
		}
	}
	p.web = web
	web.Resize()
	web.Navigate(p.url)
	return true
}

// place puts the window next to the notification area: at the cursor (the
// click on the tray icon), pushed inside the work area, on whichever edge the
// taskbar is.
func (p *popup) place() {
	scale := 1.0
	if pGetDpiForWindow.Find() == nil {
		if dpi, _, _ := pGetDpiForWindow.Call(uintptr(p.hwnd)); dpi > 0 {
			scale = float64(dpi) / 96
		}
	}
	w, h := int32(popupWidth*scale), int32(popupHeight*scale)
	margin := int32(12 * scale)

	var c point
	_, _, _ = pGetCursorPos.Call(uintptr(unsafe.Pointer(&c)))
	mon, _, _ := pMonitorFromPoint.Call(uintptr(*(*uint64)(unsafe.Pointer(&c))), monitorNear)
	mi := monitorInfo{}
	mi.Size = uint32(unsafe.Sizeof(mi))
	_, _, _ = pGetMonitorInfo.Call(mon, uintptr(unsafe.Pointer(&mi)))
	work := mi.Work
	h = min(h, work.Bottom-work.Top-2*margin)

	x, y := c.X-w/2, c.Y-h/2
	switch {
	case c.Y >= work.Bottom: // taskbar at the bottom (the usual case)
		y = work.Bottom - h - margin
	case c.Y < work.Top:
		y = work.Top + margin
	}
	switch {
	case c.X >= work.Right:
		x = work.Right - w - margin
	case c.X < work.Left:
		x = work.Left + margin
	}
	x = max(work.Left+margin, min(x, work.Right-w-margin))
	y = max(work.Top+margin, min(y, work.Bottom-h-margin))
	_, _, _ = pSetWindowPos.Call(uintptr(p.hwnd), hwndTopmost, uintptr(x), uintptr(y), uintptr(w), uintptr(h), swpNoActive)
}

func (p *popup) visible() bool {
	r, _, _ := pIsWindowVisible.Call(uintptr(p.hwnd))
	return r != 0
}

func (p *popup) show() {
	_, _, _ = pKillTimer.Call(uintptr(p.hwnd), lingerTimer)
	p.place()
	_, _, _ = pShowWindow.Call(uintptr(p.hwnd), swShow)
	_, _, _ = pSetForegroundWindow.Call(uintptr(p.hwnd))
	if p.web != nil {
		_ = p.web.Show()
		p.web.Resize()
		p.web.Focus()
	}
}

func (p *popup) hide() {
	if !p.visible() {
		return
	}
	if p.web != nil {
		_ = p.web.Hide() // the page sees "hidden" and stops polling
	}
	_, _, _ = pShowWindow.Call(uintptr(p.hwnd), swHide)
	p.hiddenAt = time.Now()
	_, _, _ = pSetTimer.Call(uintptr(p.hwnd), lingerTimer, uintptr(popupLinger.Milliseconds()), 0)
}

func popupProc(hwnd, m, wp, lp uintptr) uintptr {
	p := &pop
	switch uint32(m) {
	case wmActivate:
		if wp&0xFFFF == waInactive {
			p.hide() // a click anywhere else closes it, like a menu
		}
	case msgToggle:
		switch {
		case p.visible():
			p.hide()
		case time.Since(p.hiddenAt) < 300*time.Millisecond:
			// The click on the tray icon that took the focus away and hid it.
		default:
			p.show()
		}
		return 0
	case msgHide:
		p.hide()
		return 0
	case wmTimer:
		if wp == lingerTimer {
			_, _, _ = pDestroyWindow.Call(hwnd)
		}
		return 0
	case wmSize, wmDPIChanged:
		if p.web != nil {
			p.web.Resize()
		}
	case wmClose:
		_, _, _ = pDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		_, _, _ = pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, m, wp, lp)
	return r
}

// appsUseDarkTheme reports the Windows app theme (Settings > Personalization >
// Colors), the one WebView2 answers prefers-color-scheme from.
func appsUseDarkTheme() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	return err == nil && v == 0
}

// openURL hands url to the default browser.
func openURL(url string) {
	_ = windows.ShellExecute(0, utf16("open"), utf16(url), nil, nil, swShow)
}
