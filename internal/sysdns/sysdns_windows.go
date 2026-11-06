package sysdns

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"sync"

	"golang.org/x/sys/windows"
)

// Manager on Windows does not repoint any adapter's resolver.
//
// On macOS the resolver has to be moved because a resolver on the local
// subnet is reached around the TUN. On Windows sing-box does the equivalent
// itself: with dns_mode "hijack" the wintun adapter gets the TUN as its DNS
// server, and strict_route (set by the daemon on Windows) installs WFP
// filters that block port 53 on every other interface, which defeats
// Windows' parallel multi-homed name resolution (the leak networksetup
// fixes on macOS). What is left for this package is to drop answers the
// DNS Client service cached from the poisoned resolver before the capture,
// on Take, and the TUN's answers on Release.
type Manager struct {
	File string // kept for API parity; nothing is saved on Windows
	Log  *slog.Logger

	// Flush clears the resolver cache. Tests may replace it.
	Flush func()

	mu      sync.Mutex
	holding bool
}

var dnsFlush = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

func flushCaches() {
	if dnsFlush.Find() == nil {
		if r, _, _ := dnsFlush.Call(); r != 0 {
			return
		}
	}
	_ = exec.Command("ipconfig", "/flushdns").Run()
}

func (m *Manager) flush() {
	if m.Flush != nil {
		m.Flush()
		return
	}
	flushCaches()
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Holding reports whether Take ran since the last Release.
func (m *Manager) Holding() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.holding
}

// Take flushes the DNS client cache once the capture is verified, so names
// resolved through the poisoned resolver before it are asked again (through
// the TUN this time).
func (m *Manager) Take(iface string) error {
	m.mu.Lock()
	m.holding = true
	m.mu.Unlock()
	m.flush()
	m.log().Info("DNS cache flushed; resolution goes through the TUN (sing-box dns_mode hijack + strict_route)", "iface", iface)
	return nil
}

// Release flushes again so nothing the TUN answered outlives it. A dns-saved
// file left by a macOS-style build is removed. Safe to call any time.
func (m *Manager) Release() error {
	m.mu.Lock()
	was := m.holding
	m.holding = false
	m.mu.Unlock()
	if m.File != "" {
		if err := os.Remove(m.File); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if was {
		m.flush()
		m.log().Info("DNS cache flushed after the capture")
	}
	return nil
}
