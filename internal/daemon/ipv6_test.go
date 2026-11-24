//go:build !windows

package daemon

import (
	"context"
	"testing"
	"time"
)

type v6Rig struct {
	d      *Daemon
	probes int
	reach  func(n int) bool // the n-th probe's answer (from 1)
}

func newV6Rig(t *testing.T) *v6Rig {
	d, _ := rig(t, Options{})
	r := &v6Rig{d: d, reach: func(int) bool { return false }}
	oldP, oldR, oldC := v6Prefixes, v6Reach, v6Confirm
	t.Cleanup(func() { v6Prefixes, v6Reach, v6Confirm = oldP, oldR, oldC })
	v6Confirm = 0
	v6Prefixes = func(string) []string { return []string{"2a02:ff0:1::"} }
	v6Reach = func(context.Context, []string) bool { r.probes++; return r.reach(r.probes) }
	return r
}

// look ages the cached answer past every wait and asks again.
func (r *v6Rig) look() bool {
	r.d.v6.mu.Lock()
	r.d.v6.at = time.Time{}
	r.d.v6.mu.Unlock()
	return r.d.ipv6Works("en0")
}

// The hotspot of 2026-11-12: an address on the interface, a default route,
// and nothing behind them. The capture must not take IPv6 there.
func TestIPv6AddressWithoutConnectivityIsNotCaptured(t *testing.T) {
	r := newV6Rig(t)
	if r.d.ipv6Works("en0") {
		t.Fatal("an address alone counted as working IPv6")
	}
	if r.d.ipv6Works("en0"); r.probes != 1 {
		t.Fatalf("probed %d times within the wait, want 1", r.probes)
	}
	// No routable address: no probe at all.
	n := r.probes
	v6Prefixes = func(string) []string { return nil }
	if r.d.ipv6Works("en0") || r.probes != n {
		t.Fatalf("no address, yet probes %d -> %d", n, r.probes)
	}
}

// A network that has IPv6 gets it in the capture's first build: the first
// look is two probes, and both must succeed.
func TestIPv6FirstLookNeedsTwoSuccesses(t *testing.T) {
	r := newV6Rig(t)
	r.reach = func(int) bool { return true }
	if !r.d.ipv6Works("en0") || r.probes != 2 {
		t.Fatalf("working IPv6 not taken at the first look (probes %d)", r.probes)
	}
	r = newV6Rig(t)
	r.reach = func(n int) bool { return n == 1 } // one lucky probe
	if r.d.ipv6Works("en0") {
		t.Fatal("one lucky probe turned IPv6 on")
	}
}

// The answer changes only when two looks in a row say the opposite, in
// either direction.
func TestIPv6AnswerNeedsTwoLooksToChange(t *testing.T) {
	r := newV6Rig(t)
	answer := false
	r.reach = func(int) bool { return answer }
	r.d.ipv6Works("en0") // first look: does not work
	answer = true
	if r.look() {
		t.Fatal("one success turned IPv6 on")
	}
	if !r.look() {
		t.Fatal("two successes in a row did not")
	}
	answer = false
	if !r.look() {
		t.Fatal("one failed look dropped a network that worked")
	}
	answer = true
	r.look() // the doubt is gone again
	answer = false
	if !r.look() {
		t.Fatal("a failure after a success in between counted as the second")
	}
	if r.look() {
		t.Fatal("still counted as working after two failed looks in a row")
	}
}

// A line that carries IPv6 one time in three: it used to be captured most of
// the hour and rebuild the capture fifteen times in it.
func TestIPv6OnAMostlyDeadLineStaysOff(t *testing.T) {
	r := newV6Rig(t)
	r.reach = func(n int) bool { return n%3 == 1 } // S F F S F F ...
	on, flips, last := 0, 0, false
	for i := 0; i < 300; i++ {
		got := r.look()
		if got {
			on++
		}
		if got != last {
			flips++
		}
		last = got
	}
	if on != 0 || flips != 0 {
		t.Fatalf("IPv6 captured in %d of 300 looks, the answer changed %d times", on, flips)
	}
}

// Another network: asked again at once, whatever was known.
func TestIPv6NewPrefixIsLookedAtAfresh(t *testing.T) {
	r := newV6Rig(t)
	r.d.ipv6Works("en0")
	r.reach = func(int) bool { return true }
	v6Prefixes = func(string) []string { return []string{"2a02:ff0:2::"} }
	if !r.d.ipv6Works("en0") {
		t.Fatal("a new prefix was answered from the old network's result")
	}
}

func TestV6Targets(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, "[2606:4700:4700::1111]:443"},
		{[]string{"9.9.9.9"}, "[2620:fe::fe]:443"},
		{[]string{"2001:4860:4860::8888"}, "[2001:4860:4860::8888]:443"},
		{[]string{"192.0.2.7"}, "[2606:4700:4700::1111]:443"}, // unknown: the defaults
	} {
		got := v6Targets(c.in)
		if len(got) == 0 || got[0] != c.want {
			t.Errorf("v6Targets(%v) = %v, want first %s", c.in, got, c.want)
		}
	}
}
