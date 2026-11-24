package netid

import "testing"

// The origin record is a DNS answer; its number becomes the network's key.
func FuzzParseOrigin(f *testing.F) {
	f.Add("9121 | 88.240.0.0/13 | TR | ripencc | 2007-01-01")
	f.Add("9121 | TR | ripencc | 1996-12-02 | TTNET, TR")
	f.Add("-1")
	f.Add("|||||")
	f.Fuzz(func(t *testing.T, s string) {
		if n, err := parseOrigin(s); err == nil && (n < 1 || n > 4294967295) {
			t.Fatalf("AS number %d from %q", n, s)
		}
		_ = parseASName(s)
	})
}
