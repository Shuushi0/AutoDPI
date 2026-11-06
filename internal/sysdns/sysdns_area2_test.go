//go:build !windows

// Area 2 review tests for sysdns. Everything goes through Manager.Run (a fake
// networksetup); the real tool is never executed. TestArea2Bug_* tests fail
// today and reproduce a confirmed finding.

package sysdns

import (
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// A saved record whose service no longer exists under that name (renamed in
// System Settings, profile removed) can never be restored: -setdnsservers
// fails for it every time. Release keeps failing, and Take for ANY service
// first releases the old record, so it keeps failing too: the daemon can
// never take the resolver again, and (rename case) the renamed service keeps
// 1.1.1.1 forever.
func TestArea2Bug_SavedServiceGoneWedgesTakeForever(t *testing.T) {
	m, f := rig(t)
	if err := os.WriteFile(m.File, []byte(`{"service":"Old Wi-Fi","servers":["9.9.9.9"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	inner := m.Run
	m.Run = func(args ...string) (string, error) {
		if args[0] == "-setdnsservers" && args[1] == "Old Wi-Fi" {
			return "", errors.New("networksetup -setdnsservers: exit status 1: ** Error: Old Wi-Fi is not a recognized network service.")
		}
		return inner(args...)
	}
	if err := m.Release(); err == nil {
		t.Log("Release succeeded: fine")
	}
	if err := m.Take("en0"); err != nil {
		t.Fatalf("a record for a vanished service blocks every future Take: %v", err)
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{Capture}) {
		t.Fatalf("resolver not taken: %v", f.dns)
	}
}

// An unreadable record is never acted on (good) but also never cleared: Take
// and Release both fail until someone deletes the file by hand.
func TestArea2_CorruptRecordLeavesSettingsAloneButBlocksTake(t *testing.T) {
	m, f := rig(t)
	f.dns["Wi-Fi"] = []string{"9.9.9.9"}
	for _, bad := range []string{"", "{", `{"service":""}`, "null"} {
		if err := os.WriteFile(m.File, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := m.Release(); err == nil && bad != "null" {
			t.Errorf("%q: Release should report the unreadable record", bad)
		}
		if err := m.Take("en0"); err == nil {
			t.Errorf("%q: Take proceeded over an unreadable record", bad)
		}
		if !slices.Equal(f.dns["Wi-Fi"], []string{"9.9.9.9"}) || f.sets != 0 {
			t.Fatalf("%q: settings modified (%v, sets=%d)", bad, f.dns, f.sets)
		}
	}
}

func TestArea2_ReleaseFailureKeepsRecordAndRetries(t *testing.T) {
	m, f := rig(t)
	f.dns["Wi-Fi"] = []string{"9.9.9.9"}
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	inner, fail := m.Run, true
	m.Run = func(args ...string) (string, error) {
		if fail && args[0] == "-setdnsservers" {
			return "", errors.New("boom")
		}
		return inner(args...)
	}
	if err := m.Release(); err == nil {
		t.Fatal("expected the failure to be reported")
	}
	if !m.Holding() {
		t.Fatal("record dropped although the resolver was not restored")
	}
	fail = false
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{"9.9.9.9"}) || m.Holding() {
		t.Fatalf("not restored on retry: %v", f.dns)
	}
}

// Taking another service while the old one cannot be restored must leave the
// new service untouched and the old record intact.
func TestArea2_ServiceSwitchWithFailingReleaseTouchesNothingNew(t *testing.T) {
	m, f := rig(t)
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	inner := m.Run
	m.Run = func(args ...string) (string, error) {
		if args[0] == "-setdnsservers" && args[1] == "Wi-Fi" {
			return "", errors.New("boom")
		}
		return inner(args...)
	}
	if err := m.Take("en5"); err == nil {
		t.Fatal("expected failure")
	}
	if len(f.dns["USB LAN"]) != 0 {
		t.Fatalf("new service modified: %v", f.dns)
	}
	b, _ := os.ReadFile(m.File)
	var s saved
	if json.Unmarshal(b, &s) != nil || s.Service != "Wi-Fi" {
		t.Fatalf("record lost or changed: %s", b)
	}
}

// A new process (daemon restart after SIGKILL) restores from the record.
func TestArea2_CrashRecovery(t *testing.T) {
	m, f := rig(t)
	f.dns["Wi-Fi"] = []string{"9.9.9.9", "fe80::1%en0"}
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	m2 := &Manager{File: m.File, Run: f.run, Flush: func() {}} // the restarted daemon
	if err := m2.Release(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{"9.9.9.9", "fe80::1%en0"}) {
		t.Fatalf("not restored: %v", f.dns)
	}
	if _, err := os.Stat(m.File); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("record left behind")
	}
}

// Take failing at the final step keeps the record with the TRUE original and a
// retry must not overwrite it with 1.1.1.1.
func TestArea2_TakeFailureKeepsOriginalThroughRetries(t *testing.T) {
	m, f := rig(t)
	f.dns["Wi-Fi"] = []string{"9.9.9.9"}
	inner, fail := m.Run, true
	m.Run = func(args ...string) (string, error) {
		if fail && args[0] == "-setdnsservers" {
			return "", errors.New("timeout")
		}
		return inner(args...)
	}
	for i := 0; i < 3; i++ {
		if err := m.Take("en0"); err == nil {
			t.Fatal("expected failure")
		}
	}
	fail = false
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{"9.9.9.9"}) {
		t.Fatalf("original lost: %v", f.dns)
	}
}

// networksetup timing out after it already applied the change reports an
// error; the next Take must see the resolver already ours and keep the record.
func TestArea2_TakeThatAppliedButReportedErrorIsStillUndoable(t *testing.T) {
	m, f := rig(t)
	f.dns["Wi-Fi"] = []string{"9.9.9.9"}
	inner, once := m.Run, true
	m.Run = func(args ...string) (string, error) {
		out, err := inner(args...)
		if once && args[0] == "-setdnsservers" {
			once = false
			return out, errors.New("signal: killed")
		}
		return out, err
	}
	if err := m.Take("en0"); err == nil {
		t.Fatal("expected the error to surface")
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{Capture}) {
		t.Fatalf("setup: %v", f.dns)
	}
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{"9.9.9.9"}) {
		t.Fatalf("original lost: %v", f.dns)
	}
}

func TestArea2_SavedRecordContents(t *testing.T) {
	m, f := rig(t)
	// noise lines and an IPv6 zone address
	m.Run = func(args ...string) (string, error) {
		if args[0] == "-getdnsservers" {
			return "9.9.9.9\nfe80::1%en0\nTry again\n", nil
		}
		return f.run(args...)
	}
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(m.File)
	var s saved
	if err := json.Unmarshal(b, &s); err != nil || s.Service != "Wi-Fi" || !slices.Equal(s.Servers, []string{"9.9.9.9", "fe80::1%en0"}) {
		t.Fatalf("record %s (%v)", b, err)
	}
	if st, _ := os.Stat(m.File); st.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %v", st.Mode())
	}
}

func TestArea2_ServiceForEdgeCases(t *testing.T) {
	order := `An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi (5 GHz)
(Hardware Port: Wi-Fi, Device: en0)

(10) (weird) name
(Hardware Port: Ethernet Adapter (en7), Device: en7)

(11) No Device
(Hardware Port: Thing, Device: )

(12) Null Device
(Hardware Port: VPN, Device: (null))
`
	m := &Manager{Run: func(...string) (string, error) { return order, nil }}
	for iface, want := range map[string]string{"en0": "Wi-Fi (5 GHz)", "en7": "(weird) name"} {
		if got, err := m.ServiceFor(iface); err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", iface, got, err, want)
		}
	}
	for _, iface := range []string{"", "(null)", "en"} {
		if got, err := m.ServiceFor(iface); err == nil {
			t.Errorf("iface %q matched service %q", iface, got)
		}
	}
	// failure of networksetup itself
	m2 := &Manager{Run: func(...string) (string, error) { return "", errors.New("nope") }}
	if _, err := m2.ServiceFor("en0"); err == nil {
		t.Error("error swallowed")
	}
}

// Randomised use with injected networksetup failures. Invariant: once failures
// stop and Release succeeds, every service has exactly its original setting and
// no record remains.
func TestArea2_RandomTakeReleaseWithFailures(t *testing.T) {
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		m, f := rig(t)
		orig := map[string][]string{"Wi-Fi": {"192.168.1.1"}, "USB LAN": nil, "Thunderbolt Bridge": {"10.0.0.53", "10.0.0.54"}}
		for k, v := range orig {
			if v != nil {
				f.dns[k] = slices.Clone(v)
			}
		}
		failRate := 0.25
		inner := m.Run
		m.Run = func(args ...string) (string, error) {
			if args[0] != "-listnetworkserviceorder" && rng.Float64() < failRate {
				if args[0] == "-setdnsservers" && rng.Intn(2) == 0 { // applied, then "failed"
					_, _ = inner(args...)
				}
				return "", errors.New("injected")
			}
			return inner(args...)
		}
		for i := 0; i < 40; i++ {
			switch rng.Intn(4) {
			case 0, 1:
				_ = m.Take([]string{"en0", "en5", "bridge0", "ppp0"}[rng.Intn(4)])
			case 2:
				_ = m.Release()
			default:
				_ = m.Holding()
			}
		}
		failRate = 0
		if err := m.Release(); err != nil {
			t.Fatalf("seed %d: final Release: %v", seed, err)
		}
		for k, v := range orig {
			if !slices.Equal(f.dns[k], v) && !(len(v) == 0 && len(f.dns[k]) == 0) {
				t.Fatalf("seed %d: %s = %v, want %v", seed, k, f.dns[k], v)
			}
		}
		if m.Holding() {
			t.Fatalf("seed %d: record left", seed)
		}
	}
}

// Many goroutines: the fake is unsynchronised on purpose, so only the
// Manager's own serialisation keeps this race-free.
func TestArea2_ConcurrentTakeReleaseHolding(t *testing.T) {
	m, f := rig(t)
	f.dns["Wi-Fi"] = []string{"192.168.1.1"}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				switch (g + i) % 4 {
				case 0:
					_ = m.Take("en0")
				case 1:
					_ = m.Take("en5")
				case 2:
					_ = m.Release()
				default:
					_ = m.Holding()
				}
			}
		}(g)
	}
	wg.Wait()
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{"192.168.1.1"}) || len(f.dns["USB LAN"]) != 0 || m.Holding() {
		t.Fatalf("end state %v", f.dns)
	}
}

// A record file in a directory that does not exist: Take must fail before it
// touches any setting.
func TestArea2_UnwritableRecordMeansNoChange(t *testing.T) {
	m, f := rig(t)
	m.File = filepath.Join(t.TempDir(), "missing", "dns.json")
	f.dns["Wi-Fi"] = []string{"9.9.9.9"}
	if err := m.Take("en0"); err == nil {
		t.Fatal("expected failure")
	}
	if f.sets != 0 || !slices.Equal(f.dns["Wi-Fi"], []string{"9.9.9.9"}) {
		t.Fatalf("changed the resolver without a way back: %v", f.dns)
	}
	_ = strings.TrimSpace
}

// When the system's service list cannot be read, a failed restore is not read
// as "the service is gone": the record stays for the next try.
func TestReleaseKeepsRecordWhenServiceListFails(t *testing.T) {
	m, _ := rig(t)
	if err := os.WriteFile(m.File, []byte(`{"service":"Old Wi-Fi","servers":["9.9.9.9"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m.Run = func(args ...string) (string, error) { return "", errors.New("networksetup: boom") }
	if err := m.Release(); err == nil {
		t.Fatal("Release reported success")
	}
	if _, err := os.Stat(m.File); err != nil {
		t.Fatalf("record dropped although the service list was unreadable: %v", err)
	}
}
