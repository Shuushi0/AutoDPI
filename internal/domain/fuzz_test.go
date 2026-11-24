package domain

import (
	"strings"
	"testing"
)

// Names come from ClientHellos and from what the user types; what Normalize
// lets through ends up in sing-box rule files and in the list.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"Discord.com", "*.a.b.", "a..b", "1.2.3.4", "x.local", "xn--bcher-kva.de", "a_b.c-d.io", " a.b ", "a.b\x00", "ａ.com", "İ.com", "a.b.c.github.io"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := Normalize(s)
		if !ok {
			if n != "" {
				t.Fatalf("refused %q but returned %q", s, n)
			}
			return
		}
		if n2, ok2 := Normalize(n); !ok2 || n2 != n {
			t.Fatalf("not stable: %q -> %q -> %q, %v", s, n, n2, ok2)
		}
		if strings.Trim(n, "abcdefghijklmnopqrstuvwxyz0123456789.-_") != "" {
			t.Fatalf("%q -> %q keeps a character no host name has", s, n)
		}
		r, ok := Registrable(s)
		if !ok || !Covers(r, n) {
			t.Fatalf("Registrable(%q) = %q, %v does not cover %q", s, r, ok, n)
		}
		if r2, ok2 := Registrable(r); !ok2 || r2 != r {
			t.Fatalf("Registrable is not stable: %q -> %q -> %q, %v", s, r, r2, ok2)
		}
	})
}
