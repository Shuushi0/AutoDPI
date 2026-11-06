//go:build !windows

package sysdns

import (
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const serviceOrder = `An asterisk (*) denotes that a network service is disabled.
(1) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(*) USB LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)
`

// fakeNet mimics networksetup's DNS settings per service.
type fakeNet struct {
	dns     map[string][]string
	sets    int
	flushes int
}

func (f *fakeNet) run(args ...string) (string, error) {
	switch args[0] {
	case "-listnetworkserviceorder":
		return serviceOrder, nil
	case "-getdnsservers":
		if l := f.dns[args[1]]; len(l) > 0 {
			return strings.Join(l, "\n") + "\n", nil
		}
		return "There aren't any DNS Servers set on " + args[1] + ".\n", nil
	case "-setdnsservers":
		f.sets++
		if args[2] == "Empty" {
			delete(f.dns, args[1])
		} else {
			f.dns[args[1]] = append([]string(nil), args[2:]...)
		}
		return "", nil
	}
	panic(args[0])
}

func rig(t *testing.T) (*Manager, *fakeNet) {
	f := &fakeNet{dns: map[string][]string{}}
	m := &Manager{File: filepath.Join(t.TempDir(), "dns.json"), Run: f.run, Flush: func() { f.flushes++ }}
	return m, f
}

func TestServiceFor(t *testing.T) {
	m, _ := rig(t)
	for iface, want := range map[string]string{"en0": "Wi-Fi", "en5": "USB LAN", "bridge0": "Thunderbolt Bridge"} {
		if got, err := m.ServiceFor(iface); err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", iface, got, err, want)
		}
	}
	if _, err := m.ServiceFor("en9"); err == nil {
		t.Error("unknown interface should fail")
	}
}

func TestTakeReleaseDHCP(t *testing.T) {
	m, f := rig(t)
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{Capture}) || !m.Holding() {
		t.Fatalf("not captured: %v", f.dns)
	}
	if err := m.Take("en0"); err != nil || f.sets != 1 {
		t.Fatalf("second take should be a no-op (sets=%d, err=%v)", f.sets, err)
	}
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if _, set := f.dns["Wi-Fi"]; set || m.Holding() {
		t.Fatalf("DHCP resolver not restored: %v", f.dns)
	}
	if err := m.Release(); err != nil {
		t.Fatal("release without a hold must be harmless:", err)
	}
}

func TestManualServersSurviveAndServiceSwitch(t *testing.T) {
	m, f := rig(t)
	f.dns["Wi-Fi"] = []string{"9.9.9.9", "149.112.112.112"}
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	// The default route moves to the USB adapter: Wi-Fi gets its own servers
	// back, the adapter is captured.
	if err := m.Take("en5"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{"9.9.9.9", "149.112.112.112"}) {
		t.Fatalf("Wi-Fi not restored: %v", f.dns["Wi-Fi"])
	}
	if !slices.Equal(f.dns["USB LAN"], []string{Capture}) {
		t.Fatalf("USB LAN not captured: %v", f.dns)
	}
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if _, set := f.dns["USB LAN"]; set {
		t.Fatalf("USB LAN not restored to DHCP: %v", f.dns)
	}
}

func TestUserChangeWhileHeldIsReapplied(t *testing.T) {
	m, f := rig(t)
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	f.dns["Wi-Fi"] = []string{"8.8.8.8"} // someone edits it in System Settings
	if err := m.Take("en0"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{Capture}) {
		t.Fatalf("capture not reapplied: %v", f.dns)
	}
	_ = m.Release()
	if _, set := f.dns["Wi-Fi"]; set {
		t.Fatalf("original (DHCP) setting lost: %v", f.dns)
	}
}

// The daemon's shutdown releases the resolver while the engage loop may be in
// the middle of taking it. Interleaved, Release could restore and delete the
// saved settings before Take writes 1.1.1.1, leaving the system pointed at
// 1.1.1.1 with nothing left to undo it. Take and Release must not interleave.
func TestTakeAndReleaseDoNotInterleave(t *testing.T) {
	m, f := rig(t)
	var mu sync.Mutex
	entered, proceed := make(chan struct{}), make(chan struct{})
	inner := m.Run
	m.Run = func(args ...string) (string, error) {
		if args[0] == "-setdnsservers" && len(args) == 3 && args[2] == Capture {
			close(entered)
			<-proceed
		}
		mu.Lock()
		defer mu.Unlock()
		return inner(args...)
	}
	took := make(chan error, 1)
	go func() { took <- m.Take("en0") }()
	<-entered // Take has saved the original and is about to switch
	released := make(chan error, 1)
	go func() { released <- m.Release() }()
	select {
	case err := <-released: // Release ran to completion mid-Take
		close(proceed)
		<-took
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		close(proceed)
		if err := <-took; err != nil {
			t.Fatal(err)
		}
		if err := <-released; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if _, set := f.dns["Wi-Fi"]; set || m.Holding() {
		t.Fatalf("resolver left at %v (holding=%v) after Take and Release both returned", f.dns["Wi-Fi"], m.Holding())
	}
}

// A disabled duplicate of a service (same device) listed first must not win:
// DNS set on a disabled service does nothing.
func TestServiceForPrefersEnabledService(t *testing.T) {
	order := `An asterisk (*) denotes that a network service is disabled.
(*) Wi-Fi (old)
(Hardware Port: Wi-Fi, Device: en0)

(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(*) USB LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)
`
	m := &Manager{Run: func(args ...string) (string, error) { return order, nil }}
	if got, err := m.ServiceFor("en0"); err != nil || got != "Wi-Fi" {
		t.Fatalf("got %q, %v; want the enabled Wi-Fi", got, err)
	}
	if got, err := m.ServiceFor("en5"); err != nil || got != "USB LAN" {
		t.Fatalf("only a disabled service: got %q, %v", got, err)
	}
}
