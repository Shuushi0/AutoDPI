// Package domain normalises host names and groups them by registrable domain.
package domain

import (
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var localSuffixes = []string{".local", ".localhost", ".lan", ".home.arpa", ".internal", ".test", ".invalid", ".example",
	".localdomain", ".home", ".corp", ".intranet", ".private"}

// LocalSuffixes are the suffixes of names that only the local network can
// answer (mDNS, home routers, company networks), without the leading dot.
func LocalSuffixes() []string {
	out := make([]string, len(localSuffixes))
	for i, s := range localSuffixes {
		out[i] = strings.TrimPrefix(s, ".")
	}
	return out
}

// Normalize lower-cases s, strips a leading "*." and trailing dot, and reports
// whether the result is a public host name worth listing.
func Normalize(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	for _, suf := range localSuffixes {
		if strings.HasSuffix(s, suf) {
			return "", false
		}
	}
	return s, true
}

// Registrable returns the registrable domain (public suffix plus one label) of
// host, e.g. cdn.discordapp.com -> discordapp.com. A host that is itself a
// public suffix (github.io) is returned unchanged.
func Registrable(host string) (string, bool) {
	h, ok := Normalize(host)
	if !ok {
		return "", false
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return d, true
	}
	return h, true
}

// Covers reports whether suffix matches host the way sing-box's domain_suffix
// does: the host itself or any subdomain of it.
func Covers(suffix, host string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}
