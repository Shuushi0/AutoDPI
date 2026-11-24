//go:build !windows

package sysdns

import (
	"os"
	"testing"
)

// Power cut while the resolver is ours: the record comes back unreadable. The
// daemon's start (Run) calls Release, which sets it aside and remembers in
// memory only that it was lost. If the process ends before its first Take -
// an update restart, maint restart, a crash, or simply no capture this boot
// (paused, captive portal, dns_takeover off, uninstall) - the next process has
// no record and no memory: 1.1.1.1 becomes "the user's own" setting.
func TestRegressLostRecordForgottenAcrossARestart(t *testing.T) {
	m1, f := rig(t)
	f.dns["Wi-Fi"] = []string{Capture}                        // ours, from the run that lost power
	if err := os.WriteFile(m1.File, nil, 0o600); err != nil { // zero-length after the power cut
		t.Fatal(err)
	}
	if err := m1.Release(); err != nil { // Run() at boot
		t.Fatal(err)
	}
	t.Logf("after boot-time Release: resolver=%v holding=%v", f.dns["Wi-Fi"], m1.Holding())

	// The service restarts before it ever took the resolver.
	m2 := &Manager{File: m1.File, Run: f.run, Flush: func() {}}
	if err := m2.Release(); err != nil { // the next Run()
		t.Fatal(err)
	}
	if err := m2.Take("en0"); err != nil {
		t.Fatal(err)
	}
	if err := m2.Release(); err != nil {
		t.Fatal(err)
	}
	t.Logf("after restart, take and release: resolver=%v", f.dns["Wi-Fi"])
	if len(f.dns["Wi-Fi"]) != 0 {
		t.Errorf("the capture address is now the user's permanent resolver: %v", f.dns["Wi-Fi"])
	}
}

// Without a later Take at all (paused, or dns_takeover off): nothing ever
// gives the network's own resolver back.
func TestRegressLostRecordWithoutTakeStaysOnCapture(t *testing.T) {
	m, f := rig(t)
	f.dns["Wi-Fi"] = []string{Capture}
	_ = os.WriteFile(m.File, []byte("{"), 0o600)
	_ = m.Release()
	if m.Holding() {
		t.Fatal("holding")
	}
	t.Logf("paused / takeover off after a lost record: resolver=%v, Holding=%v (settleDNS acts only on Holding)", f.dns["Wi-Fi"], m.Holding())
	if len(f.dns["Wi-Fi"]) != 0 {
		t.Errorf("left on %v with nothing that would ever undo it", f.dns["Wi-Fi"])
	}
}

// Another network location while the resolver is held: the service reads as
// "changed", the record used to be dropped, and back on the first location
// the resolver stayed on the capture address for good (the next take even
// recorded it as the user's own).
func TestRegressLocationSwitchDoesNotLeaveTheCaptureAddress(t *testing.T) {
	m, f := rig(t)
	f.dns["Wi-Fi"] = []string{"192.168.1.1"}
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	delete(f.dns, "Wi-Fi") // the other location's settings
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	f.dns["Wi-Fi"] = []string{Capture}  // back on the first location: still ours
	if err := m.Release(); err != nil { // the daemon's next start
		t.Fatal(err)
	}
	if got := f.dns["Wi-Fi"]; len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("resolver = %v, want the user's own 192.168.1.1", got)
	}
	// And when the next thing that happens is a take: the original is the
	// user's, not our address.
	m2, f2 := rig(t)
	f2.dns["Wi-Fi"] = []string{"192.168.1.1"}
	_ = m2.Take("en0")
	delete(f2.dns, "Wi-Fi")
	_ = m2.Release()
	f2.dns["Wi-Fi"] = []string{Capture}
	m3 := &Manager{File: m2.File, Run: f2.run, Flush: func() {}}
	if err := m3.Take("en0"); err != nil {
		t.Fatal(err)
	}
	if err := m3.Release(); err != nil {
		t.Fatal(err)
	}
	if got := f2.dns["Wi-Fi"]; len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("after take and release: resolver = %v, want 192.168.1.1", got)
	}
}

// A resolver the user really changed by hand while it was held stays theirs.
func TestRegressAHandChangeIsStillRespected(t *testing.T) {
	m, f := rig(t)
	f.dns["Wi-Fi"] = []string{"192.168.1.1"}
	_ = m.Take("en0")
	f.dns["Wi-Fi"] = []string{"9.9.9.9"}
	_ = m.Release()
	_ = m.Release()
	if got := f.dns["Wi-Fi"]; len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("resolver = %v, want the user's 9.9.9.9", got)
	}
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if got := f.dns["Wi-Fi"]; len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("after another take and release: %v, want 9.9.9.9", got)
	}
}
