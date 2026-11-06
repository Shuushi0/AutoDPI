package daemon

import (
	"log/slog"
	"testing"
)

func stateLines(d *Daemon) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, j := range d.journal {
		if j.Kind == "state" {
			n++
		}
	}
	return n
}

// Behind a login page every pass fails with another local port or another way
// of being turned away, and the wait counts down. None of that is news: the
// journal says it once, and the current text stays available to status.
func TestRepeatingAStateWithOtherNumbersIsJournalledOnce(t *testing.T) {
	d := &Daemon{log: slog.New(slog.DiscardHandler)}
	details := map[string][]string{
		StateStandby: {
			`not engaging, health check failed: DoH (all resolvers): 1.0.0.1: read tcp 10.52.200.233:64086->1.0.0.1:443: wsarecv: forcibly closed`,
			`not engaging, health check failed: DoH (all resolvers): 1.0.0.1: read tcp 10.52.200.233:64115->1.0.0.1:443: wsarecv: forcibly closed`,
			`not engaging, health check failed: DoH (all resolvers): 1.0.0.1: http: server gave HTTP response to HTTPS client`,
			`not engaging, health check failed: observer self-test: timeout (context deadline exceeded)`,
		},
		StateError: {
			`config: bad value 7; next attempt in 1m0s`,
			`config: bad value 7; next attempt in 59s`,
		},
	}
	want := 0
	for _, s := range []string{StateStandby, StateError} {
		want++
		for _, detail := range details[s] {
			d.setState(s, detail)
			if n := stateLines(d); n != want {
				t.Fatalf("%d state lines after %q, want %d", n, detail, want)
			}
			if got, det := d.state, d.detail; got != s || det != detail {
				t.Fatalf("state %q %q, want the current %q %q", got, det, s, detail)
			}
		}
	}
}

func TestCountdownAcrossAMinuteIsJournalledOnce(t *testing.T) {
	d := &Daemon{log: slog.New(slog.DiscardHandler)}
	for _, left := range []string{"16m0s", "2m0s", "1m0s", "59s", "1s"} {
		d.setState(StateStandby, "capture released earlier; next attempt in "+left)
	}
	if n := stateLines(d); n != 1 {
		t.Fatalf("%d state lines, want 1", n)
	}
}

// Another state or another reason is news, also on the way back.
func TestAnotherReasonOrStateIsJournalled(t *testing.T) {
	d := &Daemon{log: slog.New(slog.DiscardHandler)}
	steps := []struct{ state, detail string }{
		{StateStandby, "not engaging, health check failed: x"},
		{StateStandby, "capture released earlier; next attempt in 30s"},
		{StateStandby, "another tunnel owns the traffic (utun3); engages once it is gone"},
		{StateStandby, "another tunnel owns the traffic (utun4); engages once it is gone"},
		{StateActive, ""},
		{StateStandby, "another tunnel owns the traffic (utun4); engages once it is gone"},
	}
	for i, s := range steps {
		d.setState(s.state, s.detail)
		want := i + 1
		if i >= 3 {
			want = i // utun3 to utun4 is the same reason
		}
		if n := stateLines(d); n != want {
			t.Fatalf("step %d: %d state lines, want %d", i, n, want)
		}
	}
}
