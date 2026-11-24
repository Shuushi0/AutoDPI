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

	"github.com/Shuushi0/AutoDPI/internal/fsx"
)

type saved struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"` // empty: the DHCP-provided resolver
	// At is set on a record that was set aside (see leave).
	At time.Time `json:"at,omitempty"`
}

// leftFor is how long a record that was set aside still counts.
const leftFor = 14 * 24 * time.Hour

// leave sets a record aside that could not be acted on: its service is gone
// from the list (renamed), or reads as changed (which is also what another
// network location looks like, whose settings are simply other ones). In
// both cases the resolver may still be ours where it cannot be seen right
// now, and dropping the record outright left it on the capture address for
// good; the next take then recorded that address as the user's own.
func (m *Manager) leave(s *saved) {
	s.At = time.Now()
	b, _ := json.Marshal(s)
	_ = fsx.WriteFile(m.File+".left", b, 0o600)
}

func (m *Manager) left() *saved {
	b, err := os.ReadFile(m.File + ".left")
	if err != nil {
		return nil
	}
	var s saved
	if json.Unmarshal(b, &s) != nil || s.Service == "" || time.Since(s.At) > leftFor || time.Since(s.At) < 0 {
		_ = os.Remove(m.File + ".left")
		return nil
	}
	return &s
}

// settleLeft gives the resolver back from a record that was set aside, once
// it can be seen again: the same service reading our address (back on the
// location it was taken on), or, when that service is gone from the list,
// whichever service reads exactly our address (the renamed one).
func (m *Manager) settleLeft() {
	l := m.left()
	if l == nil {
		return
	}
	gone, err := m.serviceGone(l.Service)
	if err != nil {
		return
	}
	var where []string
	if !gone {
		if now, err := m.servers(l.Service); err == nil && slices.Equal(now, []string{Capture}) {
			where = []string{l.Service}
		}
	} else if out, err := m.run("-listnetworkserviceorder"); err == nil {
		for _, ln := range strings.Split(out, "\n") {
			if sv := serviceLine.FindStringSubmatch(strings.TrimSpace(ln)); sv != nil {
				if now, err := m.servers(sv[1]); err == nil && slices.Equal(now, []string{Capture}) {
					where = append(where, sv[1])
				}
			}
		}
	}
	done := false
	for _, service := range where {
		if m.set(service, l.Servers) == nil {
			done = true
			m.log().Info("system resolver restored from a record that had been set aside", "service", service)
		}
	}
	if done {
		_ = os.Remove(m.File + ".left")
		m.flush()
	}
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
		// Half a file after a power cut, say. The second copy, written right
		// after the first, says the same thing.
		if bb, berr := os.ReadFile(m.File + ".bak"); berr == nil && json.Unmarshal(bb, &s) == nil && s.Service != "" {
			return &s, nil
		}
		return nil, errUnreadable
	}
	return &s, nil
}

// drop removes the record and its second copy.
func (m *Manager) drop() error {
	_ = os.Remove(m.File + ".bak")
	return os.Remove(m.File)
}

// errUnreadable: there is a record, so the resolver was ours when it was
// written, but it no longer says of which service or what to go back to.
var errUnreadable = errors.New("saved resolver settings are unreadable")

// recoverLost deals with an unreadable record. Which service it was about is
// not known any more, so every service whose resolver is exactly our capture
// address goes back to the network's own setting: that address alone is what
// this program sets, and leaving it would make it permanent with nothing left
// to say it was ours. The record is set aside only once that is done, so a
// failure here is tried again by whoever calls next, in this run or the next
// one (the mark used to live in memory only and a restart forgot it).
func (m *Manager) recoverLost() error {
	out, err := m.run("-listnetworkserviceorder")
	if err != nil {
		return err
	}
	reset := 0
	for _, ln := range strings.Split(out, "\n") {
		sv := serviceLine.FindStringSubmatch(strings.TrimSpace(ln))
		if sv == nil {
			continue
		}
		now, err := m.servers(sv[1])
		if err != nil || !slices.Equal(now, []string{Capture}) {
			continue
		}
		if err := m.set(sv[1], nil); err != nil {
			// One service that cannot be set must not keep the record in
			// the way for good: with it there, nothing can be taken again.
			m.log().Warn("resolver could not be given back", "service", sv[1], "err", err)
			continue
		}
		reset++
		m.log().Warn("resolver given back to the network's own setting: the record of the original was unreadable", "service", sv[1])
	}
	_ = os.Remove(m.File + ".bak")
	if err := os.Rename(m.File, m.File+".unreadable"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if reset > 0 {
		m.flush()
	}
	m.log().Warn("saved resolver settings were unreadable and are set aside", "file", m.File+".unreadable")
	return nil
}

// Holding reports whether the resolver is currently ours (an unreadable
// record counts: it still has to be dealt with).
func (m *Manager) Holding() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.load()
	return s != nil || errors.Is(err, errUnreadable)
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
	if errors.Is(err, errUnreadable) {
		err = m.recoverLost()
	}
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
		if !slices.Equal(orig, []string{Capture}) {
			// It reads as something else: nothing of ours is left on it.
			_ = os.Remove(m.File + ".left")
		} else if l := m.left(); l != nil {
			// Our own address, from a hold whose record was set aside: what
			// to go back to is what that record says, not this.
			if gone, gerr := m.serviceGone(l.Service); l.Service == service || (gerr == nil && gone) {
				orig = l.Servers
				_ = os.Remove(m.File + ".left")
			}
		}
		b, _ := json.Marshal(saved{Service: service, Servers: orig})
		// In one step: a power cut must leave the old file or the new one.
		// And on disk before the resolver changes: this record is the only
		// way back to the user's own setting.
		if err := fsx.WriteFile(m.File, b, 0o600); err != nil {
			return err
		}
		// A second copy: the record is the only thing that knows what the
		// user's own setting was, and without it the way back is a guess
		// (recoverLost).
		_ = fsx.WriteFile(m.File+".bak", b, 0o600)
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
	if errors.Is(err, errUnreadable) {
		return m.recoverLost()
	}
	if err == nil && s == nil {
		m.settleLeft()
	}
	if err != nil || s == nil {
		return err
	}
	if now, err := m.servers(s.Service); err == nil && !slices.Equal(now, []string{Capture}) {
		// Not ours any more: a record left by a run that could not give the
		// resolver back, and the user has set something else since. Putting
		// the old setting over theirs would undo it.
		m.log().Warn("saved resolver record set aside: the resolver reads as changed since", "service", s.Service, "now", strings.Join(now, " "))
		m.leave(s)
		if rerr := m.drop(); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return rerr
		}
		return nil
	}
	if err := m.set(s.Service, s.Servers); err != nil {
		// A service that is gone (renamed, removed in System Settings) can never
		// be restored; keeping its record would fail every later Take and
		// Release. Drop it when the system confirms the service is not there.
		if gone, lerr := m.serviceGone(s.Service); lerr != nil || !gone {
			return err
		}
		m.log().Warn("saved resolver record set aside: the service no longer exists", "service", s.Service, "err", err)
		m.leave(s)
		if rerr := m.drop(); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return rerr
		}
		m.settleLeft() // renamed: the service that reads our address now
		return nil
	}
	m.flush()
	if err := m.drop(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	orig := strings.Join(s.Servers, " ")
	if orig == "" {
		orig = "DHCP"
	}
	m.log().Info("system resolver restored", "service", s.Service, "dns", orig)
	return nil
}
