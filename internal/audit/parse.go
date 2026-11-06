package audit

import (
	"bufio"
	"net"
	"slices"
	"strconv"
	"strings"
)

// defaultHosts are the names a stock hosts file carries.
var defaultHosts = []string{"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "ip6-allnodes", "ip6-allrouters"}

// parseHosts reads a hosts file, leaving out comments and the stock entries.
func parseHosts(text string) []HostsEntry {
	var out []HostsEntry
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
			continue
		}
		for _, name := range fields[1:] {
			name = strings.ToLower(name)
			if !slices.Contains(defaultHosts, name) {
				out = append(out, HostsEntry{IP: fields[0], Name: name})
			}
		}
	}
	return out
}

// normalizeNames turns rule namespaces into plain names: an NRPT rule usually
// has both "discord.com" and ".discord.com". "." (every name) stays.
func normalizeNames(in []string) []string {
	var out []string
	for _, n := range in {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if n != "." {
			n = strings.TrimPrefix(n, ".")
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// splitServers reads a server list as the NRPT stores it (; or , separated).
func splitServers(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == ' ' })
}

// parseNetstat reads `netstat -ano`, whose words are translated but whose columns
// are not, for sockets serving port 53. A TCP socket counts only while listening:
// its foreign address then has port 0. names maps process IDs to image names.
func parseNetstat(text string, names map[uint32]string) []Listener {
	var out []Listener
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		proto := strings.ToUpper(f[0])
		if !strings.HasPrefix(proto, "TCP") && !strings.HasPrefix(proto, "UDP") {
			continue
		}
		host, port, err := net.SplitHostPort(f[1])
		if err != nil || port != "53" {
			continue
		}
		if strings.HasPrefix(proto, "TCP") {
			if _, remote, err := net.SplitHostPort(f[2]); err != nil || remote != "0" {
				continue
			}
		}
		pid, err := strconv.ParseUint(f[len(f)-1], 10, 32)
		if err != nil {
			continue
		}
		if i := strings.IndexByte(host, '%'); i >= 0 {
			host = host[:i]
		}
		out = append(out, Listener{Addr: host, Proto: proto, PID: int(pid), Process: names[uint32(pid)]})
	}
	return out
}

// parseLsof reads `lsof -nP -Fpcn` for sockets serving port 53: p and c start a
// process, each n is one of its sockets. A socket talking to a remote port 53 has
// "->" and is a client, not a server.
func parseLsof(text string) []Listener {
	var out []Listener
	var pid int
	var cmd string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		v := line[1:]
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(v)
		case 'c':
			cmd = v
		case 'n':
			if strings.Contains(v, "->") {
				continue
			}
			host, port, err := net.SplitHostPort(v)
			if err != nil || port != "53" {
				continue
			}
			if host == "*" {
				host = "0.0.0.0"
			}
			out = append(out, Listener{Addr: host, Proto: "", PID: pid, Process: cmd})
		}
	}
	return out
}

// parseResolverFile reads the name servers of a file in /etc/resolver.
func parseResolverFile(text string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}
