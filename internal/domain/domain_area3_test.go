package domain

import (
	"math/rand"
	"strings"
	"testing"
)

func TestA3NormalizeEdgeCases(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"*.discord.com", "discord.com", true},
		{"*.discord.com.", "discord.com", true},
		{"DISCORD.Com", "discord.com", true},
		{"\tdiscord.com\n", "discord.com", true},
		{"xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai", true},
		{"a_b.example.com", "a_b.example.com", true},
		{"latest.com", "latest.com", true},   // ends in "test" but not ".test"
		{"example.com", "example.com", true}, // not the ".example" TLD
		{"my.planlan.com", "my.planlan.com", true},
		{"foo.plan", "foo.plan", true}, // ".lan" must match on a label boundary
		{"mydomain.test.com", "mydomain.test.com", true},
		{"foo.local", "", false},
		{"foo.local.", "", false},
		{"a.b.localhost", "", false},
		{"nas.home.arpa", "", false},
		{"x.internal", "", false},
		{"x.test", "", false},
		{"x.example", "", false},
		{"x.invalid", "", false},
		{"*.", "", false},
		{"*.*.a.com", "", false},
		{"..", "", false},
		{"a.com..", "", false},
		{".a.com", "", false},
		{"a.com:443", "", false},
		{"[::1]", "", false},
		{"::ffff:1.2.3.4", "", false},
		{"fe80::1%en0", "", false},
		{"127.0.0.1", "", false},
		{"127.0.0.1.", "", false},
		{"a.b-.com", "", false},
		{"a.-b.com", "", false},
		{"é.com", "", false},
		{strings.Repeat("a", 64) + ".com", "", false},
		{strings.Repeat("a", 63) + ".com", strings.Repeat("a", 63) + ".com", true},
		{strings.Repeat(strings.Repeat("a", 60)+".", 5) + "com", "", false}, // > 253
		{"com", "", false},
	}
	for _, c := range cases {
		got, ok := Normalize(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Normalize(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestA3NormalizeIdempotent(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alpha := "abcXYZ019-_.*: "
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(24))
		for j := range b {
			b[j] = alpha[rng.Intn(len(alpha))]
		}
		s := string(b)
		n, ok := Normalize(s)
		if !ok {
			if n != "" {
				t.Fatalf("Normalize(%q) = %q with ok=false", s, n)
			}
			continue
		}
		n2, ok2 := Normalize(n)
		if !ok2 || n2 != n {
			t.Fatalf("Normalize not idempotent: %q -> %q -> %q,%v", s, n, n2, ok2)
		}
		if n != strings.ToLower(n) || strings.HasSuffix(n, ".") || strings.HasPrefix(n, "*") {
			t.Fatalf("Normalize(%q) = %q is not canonical", s, n)
		}
		r, rok := Registrable(n)
		if !rok || !Covers(r, n) {
			t.Fatalf("Registrable(%q) = %q,%v does not cover its input", n, r, rok)
		}
		r2, _ := Registrable(r)
		if r2 != r {
			t.Fatalf("Registrable not idempotent: %q -> %q -> %q", n, r, r2)
		}
	}
}

func TestA3RegistrableEdgeCases(t *testing.T) {
	cases := map[string]string{
		"WWW.Discord.COM.":          "discord.com",
		"a.b.c.d.discordapp.com":    "discordapp.com",
		"gateway.discord.gg":        "discord.gg",
		"foo.blogspot.com":          "foo.blogspot.com", // private PSL suffix
		"a.foo.blogspot.com":        "foo.blogspot.com",
		"x.s3.amazonaws.com":        "x.s3.amazonaws.com",
		"d111.cloudfront.net":       "d111.cloudfront.net",
		"www.example.co.uk":         "example.co.uk",
		"something.unknowntld":      "something.unknowntld",
		"a.something.unknowntld":    "something.unknowntld",
		"xn--e1afmkfd.xn--p1ai":     "xn--e1afmkfd.xn--p1ai",
		"www.xn--e1afmkfd.xn--p1ai": "xn--e1afmkfd.xn--p1ai",
	}
	for in, want := range cases {
		if got, ok := Registrable(in); !ok || got != want {
			t.Errorf("Registrable(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "localhost", "x.local", "1.2.3.4", "a..b.com"} {
		if got, ok := Registrable(bad); ok || got != "" {
			t.Errorf("Registrable(%q) = %q,%v want rejection", bad, got, ok)
		}
	}
	// Documented behaviour: a bare public suffix is returned unchanged, i.e. an
	// automatic listing of such a name would cover every site below it.
	for _, ps := range []string{"co.uk", "com.tr", "github.io"} {
		if got, ok := Registrable(ps); !ok || got != ps {
			t.Errorf("Registrable(%q) = %q,%v", ps, got, ok)
		}
	}
}

func TestA3CoversBoundaries(t *testing.T) {
	yes := [][2]string{{"discord.com", "discord.com"}, {"discord.com", "a.b.discord.com"}}
	no := [][2]string{
		{"ord.com", "discord.com"}, {"discord.com", "ord.com"}, {"discord.com", "discord.com.tr"},
		{"discord.com", "xdiscord.com"}, {"discord.com", "discord.com-evil.net"}, {"a.discord.com", "discord.com"},
		{"discord.com", ""}, {"discord.com", ".discord.com"}, {"cdn.discord.com", "discord.com"},
	}
	for _, c := range yes {
		if !Covers(c[0], c[1]) {
			t.Errorf("Covers(%q,%q) = false", c[0], c[1])
		}
	}
	for _, c := range no {
		if c[1] == ".discord.com" { // not a valid host; only make sure it does not panic
			_ = Covers(c[0], c[1])
			continue
		}
		if Covers(c[0], c[1]) {
			t.Errorf("Covers(%q,%q) = true", c[0], c[1])
		}
	}
	// Covers does not normalise: a mixed-case host is not covered (callers must
	// normalise first). Documented here so a regression in callers shows up.
	if Covers("discord.com", "CDN.Discord.com") {
		t.Error("Covers unexpectedly case-insensitive")
	}
}
