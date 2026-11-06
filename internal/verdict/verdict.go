// Package verdict decides whether a destination that failed on the real path
// is really blocked, and by what kind of block, before it may enter the list.
package verdict

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/probe"
)

type Kind int

const (
	Clean       Kind = iota // the real path works: nothing to bypass
	Blocked                 // real path fails, an engine opens it
	Unfixed                 // server reachable under another name, but no engine helps
	Unreachable             // nothing answers: server down or IP-level block
	Unknown                 // could not test (no addresses, network changed)
	// Suspect: the real path failed only by timeout or silence (no reset, no
	// injected reply), yet the neutral-SNI control answers and an engine opens
	// the target. That is what a DPI that drops packets looks like, but also
	// what a stalling link looks like, so it is not enough to list: the daemon
	// lists only when a second look, at least 5 minutes later, says the same.
	Suspect
)

func (k Kind) String() string {
	return [...]string{"clean", "blocked", "unfixed", "unreachable", "unknown", "suspect"}[k]
}

type Verdict struct {
	Kind    Kind
	Engine  string            // first engine that opened the target (Blocked)
	Direct  []probe.Result    // real-path attempts
	Control probe.Result      // same address, neutral name
	Engines map[string]string // per-engine outcome
}

func (v Verdict) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s", v.Kind)
	if v.Engine != "" {
		fmt.Fprintf(&b, " via %s", v.Engine)
	}
	return b.String()
}

// IsBlockEvidence reports whether a failed real-path attempt looks like what a
// DPI does: reset the connection, or answer with something that is not TLS. A
// timeout, a refusal or any other error is also what a stalling or broken
// link produces, so on its own it proves nothing.
func IsBlockEvidence(r probe.Result) bool {
	return r.Outcome == probe.Reset || r.Outcome == probe.Injected
}

// NeutralSNI is offered on the control probe: any valid TLS answer to it shows
// the address itself is reachable.
const NeutralSNI = "www.example.com"

type Validator struct {
	Direct  *probe.Prober
	Engines func() []observer.Engine
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Same reports whether the network is still the one we started on.
	Same func() bool
}

// A target is Blocked only when a direct attempt was reset or answered with
// non-TLS bytes. If every direct failure is a timeout or other silence, an
// open engine and a live control make it Suspect (re-check later), and a dead
// control makes it Unknown.
//
// Check tests host (offered at ips, plus whatever it resolves to). With all
// set it asks every engine instead of stopping at the first that works.
func (v *Validator) Check(ctx context.Context, host string, ips []netip.Addr, all bool) Verdict {
	out := Verdict{Kind: Unknown, Engines: map[string]string{}}
	cand := append([]netip.Addr(nil), ips...)
	if v.Resolve != nil {
		if rs, err := v.Resolve(ctx, host); err == nil {
			cand = append(cand, rs...)
		}
	}
	cand = dedupe(cand)
	if len(cand) == 0 {
		return out
	}
	addr := func(i int) string { return net.JoinHostPort(cand[i%len(cand)].String(), "443") }

	// Two tries on the real path, on different addresses when we have them.
	for i := 0; i < 2; i++ {
		r := v.Direct.TLS(ctx, addr(i), host)
		out.Direct = append(out.Direct, r)
		if r.Outcome == probe.OK {
			if v.Same != nil && !v.Same() {
				return out // clean here, but "here" is no longer that network
			}
			out.Kind = Clean
			return out
		}
	}
	if v.Same != nil && !v.Same() {
		return out
	}

	// The control and the engines go to the address that showed the block: with
	// two addresses, one may be dead and the other blocked, and probing only the
	// first would call a blocked site unreachable.
	target := 0
	for i, r := range out.Direct {
		if IsBlockEvidence(r) {
			target = i
			break
		}
	}
	out.Control = v.Direct.TLS(ctx, addr(target), NeutralSNI)
	if !out.Control.Outcome.Responded() && len(cand) > 1 && !IsBlockEvidence(out.Direct[target]) {
		// Silence everywhere so far: give the other address a chance to show it is alive.
		if alt := v.Direct.TLS(ctx, addr(1-target), NeutralSNI); alt.Outcome.Responded() {
			target, out.Control = 1-target, alt
		}
	}

	for _, e := range v.Engines() {
		p := &probe.Prober{Dial: probe.ViaSocks(e.Addr), Roots: v.Direct.Roots, Timeout: v.Direct.Timeout}
		r := p.TLS(ctx, addr(target), host)
		out.Engines[e.Name] = r.String()
		if r.Outcome == probe.OK && out.Engine == "" {
			out.Engine = e.Name
			if !all {
				break
			}
		}
	}
	hard := false
	for _, r := range out.Direct {
		hard = hard || IsBlockEvidence(r)
	}
	switch {
	case out.Engine != "" && hard:
		out.Kind = Blocked
	case out.Engine != "" && out.Control.Outcome.Responded():
		out.Kind = Suspect // only timeouts/silence on the real path
	case out.Engine != "":
		out.Kind, out.Engine = Unknown, "" // silence on the real path and on the control: the link, not a DPI
	case out.Control.Outcome.Responded():
		out.Kind = Unfixed
	default:
		out.Kind = Unreachable
	}
	if v.Same != nil && !v.Same() {
		out.Kind, out.Engine = Unknown, ""
	}
	return out
}

func dedupe(in []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range in {
		a = a.Unmap()
		if a.IsValid() && !seen[a] && len(out) < 4 {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}
