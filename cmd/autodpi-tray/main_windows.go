// autodpi-tray is the Windows counterpart of the macOS menu bar app: an icon
// in the notification area that shows the service's state, and on a click a
// window with the same content (see popup_windows.go). It runs per user, at
// sign-in, without administrator rights; the service itself keeps running
// whether or not it does.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/ipc"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/ui"
	"github.com/Shuushi0/AutoDPI/internal/update"
	"github.com/Shuushi0/AutoDPI/internal/version"
)

func main() {
	popupURL := flag.String("popup", "", "internal: run the popup window for this URL")
	autostart := flag.Bool("autostart", false, "started at sign-in: stay quiet if the icon was hidden")
	restarted := flag.Bool("restarted", false, "internal: started by the previous icon after an update")
	flag.Parse()
	if *popupURL != "" {
		os.Exit(runPopup(*popupURL))
	}

	st := loadSettings()
	if *autostart && st.Hidden {
		return // "hide the icon": the service runs on, the icon waits for the Start menu
	}
	if st.Hidden {
		st.Hidden = false
		_ = st.save()
	}
	// One icon per user session. A second start (the Start menu shortcut while
	// the icon is there) just opens the window of the first.
	mutex, err := windows.CreateMutex(nil, false, utf16(`Local\AutoDPI.Tray`))
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) && *restarted {
		// The previous icon is closing to make way for this one: wait for it.
		for i := 0; i < 50 && errors.Is(err, windows.ERROR_ALREADY_EXISTS); i++ {
			windows.CloseHandle(mutex)
			time.Sleep(100 * time.Millisecond)
			mutex, err = windows.CreateMutex(nil, false, utf16(`Local\AutoDPI.Tray`))
		}
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if !*autostart {
			if h := findWindow(popupClass); h != 0 {
				postMessage(h, msgToggle)
			} else if h := findWindow(signalClass); h != 0 {
				postMessage(h, msgToggle)
			}
		}
		return
	}
	trayMutex = mutex
	defer func() { windows.CloseHandle(trayMutex) }()

	a, err := newApp()
	if err != nil {
		confirm("AutoDPI", i18n.T("Tepsi uygulaması başlatılamadı: ", "The tray app could not start: ")+err.Error())
		os.Exit(1)
	}
	if !*autostart && !*restarted {
		go func() { time.Sleep(700 * time.Millisecond); a.togglePopup() }()
	}
	systray.Run(a.onReady, a.onExit)
}

var trayMutex windows.Handle

// settings is the user's own tray state, in %LOCALAPPDATA%\AutoDPI.
type settings struct {
	Hidden bool `json:"hidden"` // the icon was hidden; autostart stays quiet
	// Seen is the service version this user last saw; a newer one gets a
	// "updated" notification. Announced is the newest release a notification
	// told them about, so each is announced once.
	Seen      string `json:"seen,omitempty"`
	Announced string `json:"announced,omitempty"`
}

func settingsPath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "AutoDPI", "tray.json")
}

func loadSettings() settings {
	var s settings
	if b, err := os.ReadFile(settingsPath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func (s settings) save() error {
	p := settingsPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(s)
	return os.WriteFile(p, b, 0o644)
}

type status struct {
	State   string `json:"state"`
	Detail  string `json:"detail"`
	Version string `json:"version"`
	Update  *struct {
		Latest    string `json:"latest"`
		URL       string `json:"url"`
		Auto      bool   `json:"auto"`
		Skipped   bool   `json:"skipped"`
		Failed    bool   `json:"failed"`
		Supported bool   `json:"supported"`
	} `json:"update"`
}

type app struct {
	sock     string
	miniURL  string
	panelURL string
	self     string      // this program's file
	selfFile os.FileInfo // what was there at start; an update replaces it

	mu    sync.Mutex
	state string // daemon state, "unreachable", or "" before the first look

	mOpen, mToggle, mStart, mPanel, mHide, mQuit, mShutdown *systray.MenuItem
}

func newApp() (*app, error) {
	p := paths.Default()
	// No state yet: the first refresh always sets the menu up, also for a
	// service that is not running (the menu starts out as for a running one).
	a := &app{sock: p.Sock}
	if self, err := os.Executable(); err == nil {
		a.self = self
		a.selfFile, _ = os.Stat(self)
	}
	srv := ui.New(ui.NewToken(), p.Config, func(req ipc.Request, out any, to time.Duration) error {
		return ipc.Call(p.Sock, req, out, to)
	}, ui.SaveFile)
	srv.Tray = map[string]func() error{
		"panel":         func() error { a.closePopup(); openURL(a.panelURL); return nil },
		"close":         func() error { a.closePopup(); return nil },
		"hide":          func() error { a.hideIcon(); return nil },
		"quit":          func() error { a.quit(); return nil },
		"start-service": a.startService,
		"notes":         a.openNotes,
	}
	ln, url, err := srv.Listen()
	if err != nil {
		return nil, err
	}
	go func() { _ = srv.Serve(ln) }()
	a.panelURL = url
	a.miniURL = strings.Replace(url, "/?t=", "/mini?t=", 1)
	return a, nil
}

func (a *app) onReady() {
	newSignalWindow(a)
	systray.SetTitle("AutoDPI")
	systray.SetIcon(trayIcon("unreachable"))
	systray.SetTooltip("AutoDPI")
	systray.SetOnTapped(a.togglePopup)

	a.mOpen = systray.AddMenuItem(i18n.T("AutoDPI'yi aç", "Open AutoDPI"), i18n.T("Durum penceresini aç", "Open the status window"))
	a.mToggle = systray.AddMenuItem(i18n.T("Duraklat", "Pause"), i18n.T("Tüm trafiği serbest bırak (servis açık kalır)", "Let all traffic go (the service stays on)"))
	a.mStart = systray.AddMenuItem(i18n.T("Servisi başlat", "Start the service"), i18n.T("Sistem servisini başlatır (yönetici izni sorulur)", "Starts the system service (asks for administrator permission)"))
	a.mStart.Hide()
	a.mPanel = systray.AddMenuItem(i18n.T("Ayarlar (tarayıcıda)", "Settings (in the browser)"), i18n.T("Ayrıntılı ayarlar ve liste tarayıcıda açılır", "Detailed settings and the list open in the browser"))
	systray.AddSeparator()
	a.mHide = systray.AddMenuItem(i18n.T("Simgeyi gizle, arka planda çalışsın", "Hide the icon, keep running in the background"),
		i18n.T("Servis çalışmaya devam eder; simgeyi Başlat menüsündeki AutoDPI geri getirir", "The service keeps running; AutoDPI in the Start menu brings the icon back"))
	a.mQuit = systray.AddMenuItem(i18n.T("Yalnızca simgeyi kapat", "Close the icon only"), i18n.T("Servis çalışmaya devam eder", "The service keeps running"))
	a.mShutdown = systray.AddMenuItem(i18n.T("Servisi kapat ve çık", "Shut down the service and quit"), i18n.T("Servisi durdurur ve simgeyi kapatır", "Stops the service and closes the icon"))

	go a.menuLoop()
	go a.statusLoop()
}

func (a *app) onExit() { a.closePopup() }

func (a *app) menuLoop() {
	for {
		select {
		case <-a.mOpen.ClickedCh:
			a.togglePopup()
		case <-a.mToggle.ClickedCh:
			a.mu.Lock()
			cmd := "pause"
			if a.state == "paused" {
				cmd = "resume"
			}
			a.mu.Unlock()
			_ = ipc.Call(a.sock, ipc.Request{Cmd: cmd}, nil, 10*time.Second)
			a.refresh()
		case <-a.mStart.ClickedCh:
			if err := a.startService(); err != nil {
				confirm("AutoDPI", err.Error())
			}
		case <-a.mPanel.ClickedCh:
			openURL(a.panelURL)
		case <-a.mHide.ClickedCh:
			if confirm("AutoDPI", i18n.T("Simge gizlenecek ve açılışta da gelmeyecek. AutoDPI arka planda çalışmaya devam eder.\n\nSimgeyi geri getirmek için Başlat menüsünden AutoDPI'yi açın.",
				"The icon goes away and does not come back at sign-in. AutoDPI keeps running in the background.\n\nOpen AutoDPI from the Start menu to bring the icon back.")) {
				a.hideIcon()
			}
		case <-a.mQuit.ClickedCh:
			a.quit()
		case <-a.mShutdown.ClickedCh:
			if err := ipc.Call(a.sock, ipc.Request{Cmd: "maint", Action: "shutdown"}, nil, 20*time.Second); err != nil {
				confirm("AutoDPI", i18n.T("Servis kapatılamadı: ", "The service did not shut down: ")+err.Error())
				continue
			}
			a.quit()
		}
	}
}

func stateTitle(state string) string {
	return map[string]string{
		"active": i18n.T("Aktif", "Active"), "starting": i18n.T("Başlıyor", "Starting"), "standby": i18n.T("Beklemede", "Standby"),
		"paused": i18n.T("Duraklatıldı", "Paused"), "offline": i18n.T("Çevrimdışı", "Offline"), "error": i18n.T("Hata", "Error"),
		"unreachable": i18n.T("Servis çalışmıyor", "The service is not running"),
	}[state]
}

func (a *app) statusLoop() {
	for {
		a.refresh()
		time.Sleep(5 * time.Second)
	}
}

// refresh asks the service for its state and updates the icon and the menu.
func (a *app) refresh() {
	var st status
	state := "unreachable"
	if err := ipc.Call(a.sock, ipc.Request{Cmd: "status"}, &st, 5*time.Second); err == nil && st.State != "" {
		state = st.State
	}
	a.mu.Lock()
	changed := state != a.state
	a.state = state
	a.mu.Unlock()

	if state != "unreachable" {
		a.followUpdate(st)
	}

	tip := "AutoDPI: " + stateTitle(state)
	if st.Detail != "" {
		tip += "\n" + st.Detail
	}
	if r := []rune(tip); len(r) > 120 { // the notification area cuts tooltips at 127 characters
		tip = string(r[:119]) + "…"
	}
	systray.SetTooltip(tip)
	if !changed {
		return
	}
	systray.SetIcon(trayIcon(state))
	if state == "unreachable" {
		a.mToggle.Hide()
		a.mStart.Show()
		a.mShutdown.Disable()
		return
	}
	a.mStart.Hide()
	a.mToggle.Show()
	a.mShutdown.Enable()
	if state == "paused" {
		a.mToggle.SetTitle(i18n.T("Sürdür", "Resume"))
		a.mToggle.SetTooltip(i18n.T("Bypass'ı yeniden aç", "Switch the bypass back on"))
	} else {
		a.mToggle.SetTitle(i18n.T("Duraklat", "Pause"))
		a.mToggle.SetTooltip(i18n.T("Tüm trafiği serbest bırak (servis açık kalır)", "Let all traffic go (the service stays on)"))
	}
}

// followUpdate tells the user about a new or just installed version, and
// starts the new tray app once an update has replaced this one's file.
func (a *app) followUpdate(st status) {
	if a.selfFile != nil && st.Version != version.Version {
		if fi, err := os.Stat(a.self); err == nil && !os.SameFile(fi, a.selfFile) {
			a.relaunch()
			return
		}
	}
	s := loadSettings()
	changed := false
	if st.Version != "" && st.Version != s.Seen {
		if s.Seen != "" && update.Compare(st.Version, s.Seen) > 0 {
			balloon(i18n.T("AutoDPI güncellendi", "AutoDPI was updated"), i18n.T("Sürüm "+st.Version+" çalışıyor.", "Version "+st.Version+" is running."))
		}
		s.Seen, changed = st.Version, true
	}
	if u := st.Update; u != nil && u.Latest != "" && !u.Skipped && u.Latest != s.Announced && (!u.Auto || !u.Supported || u.Failed) {
		balloon(i18n.T("AutoDPI "+u.Latest+" hazır", "AutoDPI "+u.Latest+" is out"),
			i18n.T("Kurmak için AutoDPI penceresini açın.", "Open the AutoDPI window to install it."))
		s.Announced, changed = u.Latest, true
	}
	if changed {
		_ = s.save()
	}
}

// relaunch hands over to the updated tray app: it frees the one-icon lock,
// starts the new file and closes this icon.
func (a *app) relaunch() {
	cmd := exec.Command(a.self, "--restarted")
	if err := cmd.Start(); err != nil {
		return
	}
	a.selfFile = nil // once
	windows.CloseHandle(trayMutex)
	trayMutex = 0
	a.quit()
}

// openNotes opens the newer release's page in the browser.
func (a *app) openNotes() error {
	var st status
	if err := ipc.Call(a.sock, ipc.Request{Cmd: "status"}, &st, 5*time.Second); err != nil {
		return err
	}
	if st.Update == nil || st.Update.URL == "" {
		return errors.New(i18n.T("yeni sürüm yok", "there is no newer version"))
	}
	a.closePopup()
	openURL(st.Update.URL)
	return nil
}

// togglePopup opens the window, or closes it when it is open. The window
// lives in its own process; a hidden one is reused while it lingers.
func (a *app) togglePopup() {
	_, _, _ = pAllowSetForeground.Call(asfwAny) // let the popup take the focus our click gave us
	if h := findWindow(popupClass); h != 0 {
		postMessage(h, msgToggle)
		return
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(self, "--popup", a.miniURL)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err == nil {
		go func() { _ = cmd.Wait() }()
	}
}

func (a *app) closePopup() {
	if h := findWindow(popupClass); h != 0 {
		postMessage(h, msgHide)
	}
}

// hideIcon removes the icon until the user opens AutoDPI from the Start menu:
// sign-in starts this program with --autostart, which then exits at once.
func (a *app) hideIcon() {
	_ = settings{Hidden: true}.save()
	a.quit()
}

func (a *app) quit() {
	if h := findWindow(popupClass); h != 0 {
		postMessage(h, wmClose)
	}
	systray.Quit()
}

// startService starts the stopped service through a UAC prompt.
func (a *app) startService() error {
	if err := ui.StartService(); err != nil {
		return err
	}
	go func() { time.Sleep(3 * time.Second); a.refresh() }()
	return nil
}

// A hidden window of its own class, so a second start can find this instance
// and ask it to open its popup.
const signalClass = "AutoDPITraySignal"

var signalApp *app

// newSignalWindow creates that window and returns once it exists.
func newSignalWindow(a *app) {
	signalApp = a
	done := make(chan struct{})
	go func() {
		// Its own thread with its own message loop: systray's loop runs on the
		// main thread and is not ours to extend.
		runtime.LockOSThread()
		var inst windows.Handle
		_ = windows.GetModuleHandleEx(0, nil, &inst)
		wc := wndClassEx{WndProc: windows.NewCallback(signalProc), Instance: inst, ClassName: utf16(signalClass)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		_, _, _ = pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
		_, _, _ = pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(utf16(signalClass))), 0, 0, 0, 0, 0, 0, 0, 0, uintptr(inst), 0)
		close(done)
		var m msg
		for {
			if r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0); int32(r) <= 0 {
				return
			}
			_, _, _ = pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()
	<-done
}

func signalProc(hwnd, m, wp, lp uintptr) uintptr {
	if uint32(m) == msgToggle && signalApp != nil {
		go signalApp.togglePopup()
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, m, wp, lp)
	return r
}
