package daemon

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/netx"
)

// An IPv6 address on the interface does not mean the network carries IPv6: a
// phone hotspot hands out a prefix and a default route whether or not its
// uplink has any. The capture must take IPv6 only where it really works.
// Captured IPv6 that goes nowhere is worse than none: the TUN accepts the
// connection at once, the outbound then fails, and the application sees a
// connection that opened and died, so it never falls back to IPv4. Left
// alone, the same connection fails before it opens and the application moves
// on by itself.
//
// So the address is only the reason to look: a TCP connection over the
// physical interface to the IPv6 address of a configured resolver decides.
const (
	v6Recheck = 5 * time.Minute // how long "works" is trusted
	v6Retry   = 2 * time.Minute // how long "does not work" is
	v6Dial    = 2 * time.Second
)

// Variables so that tests need not wait.
var (
	v6Soon    = 30 * time.Second // the next look while an answer is in doubt
	v6Soonest = 5 * time.Second  // ... in the first v6Soon on a network
	v6Confirm = time.Second      // between the two probes of a first look
)

// v6Siblings are the IPv6 addresses of the resolvers known by their IPv4 one.
var v6Siblings = map[string][]string{
	"1.1.1.1":         {"2606:4700:4700::1111", "2606:4700:4700::1001"},
	"1.0.0.1":         {"2606:4700:4700::1001", "2606:4700:4700::1111"},
	"8.8.8.8":         {"2001:4860:4860::8888", "2001:4860:4860::8844"},
	"8.8.4.4":         {"2001:4860:4860::8844", "2001:4860:4860::8888"},
	"9.9.9.9":         {"2620:fe::fe", "2620:fe::9"},
	"149.112.112.112": {"2620:fe::9", "2620:fe::fe"},
}

// v6Targets are the addresses the IPv6 check connects to: the configured
// resolvers' own IPv6 addresses, so it talks to nobody the service does not
// talk to anyway. Resolvers it knows no IPv6 address for fall back to the
// default ones.
func v6Targets(servers []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(ip string) {
		if a := net.JoinHostPort(ip, "443"); !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, s := range servers {
		ip, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		if ip.Is6() && !ip.Is4In6() {
			add(ip.String())
			continue
		}
		for _, sib := range v6Siblings[ip.Unmap().String()] {
			add(sib)
		}
	}
	if len(out) == 0 {
		for _, sib := range v6Siblings[netx.DefaultDoHServers[0]] {
			add(sib)
		}
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

// v6Reach reports whether any target accepts a TCP connection over the
// physical interface within v6Dial. A variable so that tests need no network.
var v6Reach = func(ctx context.Context, targets []string) bool {
	ctx, cancel := context.WithTimeout(ctx, v6Dial)
	defer cancel()
	dial := &netx.Dialer{Timeout: v6Dial}
	res := make(chan bool, len(targets))
	for _, t := range targets {
		go func() {
			c, err := dial.DialContext(ctx, "tcp6", t)
			if err == nil {
				c.Close()
			}
			res <- err == nil
		}()
	}
	for range targets {
		if <-res {
			return true
		}
	}
	return false
}

// v6Prefixes lists an interface's routable IPv6 prefixes. A variable so that
// tests need no interface.
var v6Prefixes = netx.GlobalIPv6Prefixes

type v6State struct {
	mu     sync.Mutex
	key    string    // interface and its routable prefixes the answer is for
	works  bool      // the answer in force
	at     time.Time // when it was last looked at
	first  time.Time // when this key was first seen
	doubts int       // looks in a row that said the opposite of works
}

// ipv6Works is system.hasIPv6: iface has a routable IPv6 address and IPv6
// connections really leave through it.
//
// The answer is kept per set of prefixes and changes only when two looks in a
// row say the opposite, in either direction: every change rebuilds the
// capture, which drops every open connection. It used to take one success to
// turn IPv6 on and two failures to turn it off, the wrong way round for a
// line that mostly does not carry IPv6: one lucky probe captured IPv6 for
// five minutes, and a line that worked one time in three was captured most
// of the hour and rebuilt fifteen times in it.
//
// The first look at a new set of prefixes is two probes a moment apart, so a
// network that does have IPv6 gets it in the capture's first build. While an
// answer waits for its second look, the next one comes soon (v6Soon, and
// sooner in the first half minute on a network, when an address may simply
// not have been ready).
func (d *Daemon) ipv6Works(iface string) bool {
	prefixes := v6Prefixes(iface)
	s := &d.v6
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(prefixes) == 0 {
		s.key, s.works, s.doubts = "", false, 0
		return false
	}
	key := iface + "|" + strings.Join(prefixes, ",")
	same := key == s.key
	if same {
		keep := v6Retry
		if s.works {
			keep = v6Recheck
		}
		if s.doubts > 0 || (!s.works && wallSince(s.first) < 2*v6Soon) {
			keep = v6Soon
			if age := wallSince(s.first); age >= 0 && age < v6Soon {
				keep = v6Soonest
			}
		}
		if age := wallSince(s.at); age >= 0 && age < keep {
			return s.works
		}
	}
	ctx := d.runCtx
	if ctx == nil {
		ctx = context.Background()
	}
	targets := v6Targets(d.cfg.DoHServers)
	ok := v6Reach(ctx, targets)
	if !same && ok {
		// Twice before a new network's IPv6 is believed.
		select {
		case <-time.After(v6Confirm):
		case <-ctx.Done():
		}
		ok = v6Reach(ctx, targets)
	}
	if ctx.Err() != nil {
		return same && s.works // shutting down: a check cut short says nothing
	}
	now := time.Now()
	switch {
	case !same:
		s.key, s.works, s.first, s.doubts = key, ok, now, 0
		d.v6Log(iface, prefixes, ok)
	case ok == s.works:
		s.doubts = 0
	default:
		if s.doubts++; s.doubts >= 2 {
			s.works, s.doubts = ok, 0
			d.v6Log(iface, prefixes, ok)
		}
	}
	s.at = now
	return s.works
}

func (d *Daemon) v6Log(iface string, prefixes []string, ok bool) {
	what := "IPv6 does not work here although the interface has an address; leaving it alone"
	if ok {
		what = "IPv6 works here"
	}
	d.log.Info("network IPv6", "iface", iface, "prefixes", strings.Join(prefixes, " "), "result", what)
}

// expire makes the next look probe again (the network came back).
func (s *v6State) expire() {
	s.mu.Lock()
	s.at = time.Time{}
	s.mu.Unlock()
}

// wallSince is time.Since by the wall clock. The monotonic clock stops while
// the machine sleeps (darwin), so a wait measured with it lasts a night longer
// than it says; these waits are about how long ago something was, asleep or
// not. A clock set back gives a negative answer, which callers treat as "long
// ago" or "just now" as suits them.
func wallSince(t time.Time) time.Duration { return time.Now().Round(0).Sub(t.Round(0)) }

// waitLeft is how long is left until *at, for a wait that was scheduled most
// ahead. More than that left means the clock was set back since (a time
// correction, a dual-boot machine): the wait then starts over at its own
// length instead of growing by the size of the step, which left the service
// idle for an hour after the clock went back an hour.
func waitLeft(at *time.Time, most time.Duration) time.Duration {
	left := wallUntil(*at)
	if most > 0 && left > most {
		*at = time.Now().Round(0).Add(most)
		left = most
	}
	return left
}

// wallUntil is time.Until by the wall clock (see wallSince).
func wallUntil(t time.Time) time.Duration { return t.Round(0).Sub(time.Now().Round(0)) }
