package hoststate

import (
	"testing"
	"time"
)

// The wall clock is set back (NTP correction after a bad RTC, manual change,
// dual-boot local-time RTC): an entry made before lives for the jump plus ttl.
func TestRegressDeadClockSetBack(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	d := NewDead(10*time.Minute, 16)
	d.now = func() time.Time { return now }
	k := DeadKey{Host: "a.test", Dest: "1.2.3.4:443"}
	d.Add(k)
	now = now.Add(-3 * time.Hour) // clock set back 3 h
	now = now.Add(2 * time.Hour)  // two real hours later
	if d.Has(k) {
		t.Errorf("entry made with a 10 min ttl still live 2 h (real time) later after the clock was set back 3 h")
	}
}
