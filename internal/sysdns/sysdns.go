// Package sysdns points the system resolver at an address the TUN captures
// while the capture runs, and puts the user's own settings back afterwards.
//
// sing-box's hijack-dns only sees queries that enter the TUN. A resolver on the
// local subnet (the usual router or hotspot address) is reached through the
// connected route on the physical interface, so its (possibly poisoned)
// answers would bypass DoH entirely. sing-box 1.13 cannot re-resolve a sniffed
// domain for a flow whose destination is already an IP, so the queries
// themselves have to come our way.
package sysdns

// Capture is the resolver the system is pointed at. It is public so that, if
// we die without restoring, plain DNS still works and nothing goes dark; while
// the TUN is up its port-53 traffic is hijacked into DoH. On Windows the
// system is not repointed (see sysdns_windows.go), but the daemon still
// probes this address through the TUN.
const Capture = "1.1.1.1"
