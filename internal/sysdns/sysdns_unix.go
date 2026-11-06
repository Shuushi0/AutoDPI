//go:build !windows

package sysdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

type saved struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"` // empty: the DHCP-provided resolver
}

type Manager struct {
	File string // the user's original settings, kept while we hold the resolver
	Log  *slog.Logger

	// Run executes networksetup; Flush clears the resolver caches. Tests
	// replace both.
	Run   func(args ...string) (string, error)
	Flush func()

	// mu keeps Take and Release whole: the daemon's shutdown may release
	// while the engage loop is taking, and interleaved they could leave the
	// system on Capture with the saved settings already gone.
	mu sync.Mutex
}

func networksetup(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/networksetup", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("networksetup %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func flushCaches() {
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}

func (m *Manager) run(args ...string) (string, error) {
	if m.Run != nil {
		return m.Run(args...)
	}
	return networksetup(args...)
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

var serviceLine = regexp.MustCompile(`^\((?:\d+|\*)\)\s+(.+)$`)
var deviceLine = regexp.MustCompile(`Device:\s*([^)\s]+)\)`)

// ServiceFor returns the network service (as networksetup names it) that
// owns iface.
func (m *Manager) ServiceFor(iface string) (string, error) {
	out, err := m.run("-listnetworkserviceorder")
	if err != nil {
		return "", err
	}
	name, disabled, fallback := "", false, ""
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if s := serviceLine.FindStringSubmatch(ln); s != nil {
			name, disabled = s[1], strings.HasPrefix(ln, "(*)")
			continue
		}
		if d := deviceLine.FindStringSubmatch(ln); d != nil && d[1] == iface && name != "" {
			if !disabled {
				return name, nil
			}
			if fallback == "" { // a disabled duplicate's DNS setting does nothing
				fallback = name
			}
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("no network service for %s", iface)
}

// serviceGone reports whether the system's service list no longer has a
// service called name.
func (m *Manager) serviceGone(name string) (bool, error) {
	out, err := m.run("-listnetworkserviceorder")
	if err != nil {
		return false, err
	}
	for _, ln := range strings.Split(out, "\n") {
		if s := serviceLine.FindStringSubmatch(strings.TrimSpace(ln)); s != nil && s[1] == name {
			return false, nil
		}
	}
	return true, nil
}

func (m *Manager) servers(service string) ([]string, error) {
	out, err := m.run("-getdnsservers", service)
	if err != nil {
		return nil, err
	}
	var list []string
	for _, f := range strings.Fields(out) {
		if _, err := netip.ParseAddr(f); err == nil {
			list = append(list, f)
		}
	}
	return list, nil
}

func (m *Manager) set(service string, list []string) error {
	args := []string{"-setdnsservers", service}
	if len(list) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, list...)
	}
	_, err := m.run(args...)
	return err
}

func (m *Manager) load() (*saved, error) {
	b, err := os.ReadFile(m.File)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s saved
	if err := json.Unmarshal(b, &s); err != nil || s.Service == "" {
		return nil, fmt.Errorf("%s: unreadable, leaving DNS settings alone", m.File)
	}
	return &s, nil
}

// Holding reports whether the resolver is currently ours.
func (m *Manager) Holding() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _ := m.load()
	return s != nil
}

// Take points the service owning iface at Capture. The original settings are
// written to File before anything changes, so a crash can always be undone by
// Release. Taking a different service first releases the previous one.
func (m *Manager) Take(iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	service, err := m.ServiceFor(iface)
	if err != nil {
		return err
	}
	cur, err := m.load()
	if err != nil {
		return err
	}
	if cur != nil && cur.Service != service {
		if err := m.release(); err != nil {
			return err
		}
		cur = nil
	}
	if cur == nil {
		orig, err := m.servers(service)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(saved{Service: service, Servers: orig})
		if err := os.WriteFile(m.File, b, 0o600); err != nil {
			return err
		}
	} else if now, err := m.servers(service); err == nil && slices.Equal(now, []string{Capture}) {
		return nil // already ours
	}
	if err := m.set(service, []string{Capture}); err != nil {
		return err
	}
	m.flush()
	m.log().Info("system resolver captured", "service", service, "dns", Capture)
	return nil
}

// Release restores the saved settings, if we hold any. Safe to call any time.
func (m *Manager) Release() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.release()
}

func (m *Manager) release() error {
	s, err := m.load()
	if err != nil || s == nil {
		return err
	}
	if err := m.set(s.Service, s.Servers); err != nil {
		// A service that is gone (renamed, removed in System Settings) can never
		// be restored; keeping its record would fail every later Take and
		// Release. Drop it when the system confirms the service is not there.
		if gone, lerr := m.serviceGone(s.Service); lerr != nil || !gone {
			return err
		}
		m.log().Warn("saved resolver record dropped: the service no longer exists", "service", s.Service, "err", err)
		if rerr := os.Remove(m.File); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return rerr
		}
		return nil
	}
	m.flush()
	if err := os.Remove(m.File); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	orig := strings.Join(s.Servers, " ")
	if orig == "" {
		orig = "DHCP"
	}
	m.log().Info("system resolver restored", "service", s.Service, "dns", orig)
	return nil
}
