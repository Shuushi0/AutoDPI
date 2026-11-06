package singbox

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ParseWgcf reads a profile produced by `wgcf generate` (WireGuard INI) into
// the settings the sing-box wireguard endpoint needs.
func ParseWgcf(r io.Reader) (*WireGuardProfile, error) {
	p := &WireGuardProfile{MTU: 1280}
	section := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.HasPrefix(ln, "[") {
			section = strings.ToLower(strings.Trim(ln, "[]"))
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch section + "." + k {
		case "interface.privatekey":
			p.PrivateKey = v
		case "interface.address":
			for _, a := range strings.Split(v, ",") {
				if a = strings.TrimSpace(a); a != "" {
					p.Addresses = append(p.Addresses, a)
				}
			}
		case "interface.mtu":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				p.MTU = n
			}
		case "peer.publickey":
			p.PublicKey = v
		case "peer.endpoint":
			host, port, ok := cutHostPort(v)
			if !ok {
				return nil, fmt.Errorf("wgcf: bad endpoint %q", v)
			}
			p.Endpoint, p.Port = host, port
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if p.PrivateKey == "" || p.PublicKey == "" || len(p.Addresses) == 0 || p.Endpoint == "" {
		return nil, fmt.Errorf("wgcf: profile is missing PrivateKey, Address, PublicKey or Endpoint")
	}
	return p, nil
}

func cutHostPort(s string) (string, int, bool) {
	i := strings.LastIndex(s, ":")
	if i <= 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	return strings.Trim(s[:i], "[]"), port, true
}
