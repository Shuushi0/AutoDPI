package audit

import "testing"

// The parsers read other programs' output and files anybody may have edited.
func FuzzParsers(f *testing.F) {
	f.Add("127.0.0.1 localhost\n0.0.0.0 a.com b.com # c\n")
	f.Add("  TCP    0.0.0.0:53   0.0.0.0:0   LISTENING   1234\r\n  UDP    [::]:53   *:*   4\r\n")
	f.Add("TCP :53 :0 00")
	f.Add("p12\ncnamed\nn*:53\nn127.0.0.1:53\n")
	f.Add("nameserver 127.0.0.1\nport 5353\n")
	f.Fuzz(func(t *testing.T, s string) {
		for _, h := range parseHosts(s) {
			if h.Name == "" || h.IP == "" {
				t.Fatalf("hosts entry with an empty field from %q", s)
			}
		}
		for _, l := range parseNetstat(s, map[uint32]string{4: "System", 1234: "tool.exe"}) {
			if l.Addr == "" {
				t.Fatalf("listener without an address from %q", s)
			}
		}
		_ = parseLsof(s)
		_ = parseResolverFile(s)
		_ = normalizeNames([]string{s})
	})
}
