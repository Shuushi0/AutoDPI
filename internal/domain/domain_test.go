package domain

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Discord.COM", "discord.com", true},
		{"*.discordapp.com.", "discordapp.com", true},
		{" gateway.discord.gg ", "gateway.discord.gg", true},
		{"localhost", "", false},
		{"printer.lan", "", false},
		{"1.2.3.4", "", false},
		{"2001:db8::1", "", false},
		{"bad..name.com", "", false},
		{"-bad.com", "", false},
		{"sp ace.com", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := Normalize(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Normalize(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestRegistrable(t *testing.T) {
	cases := map[string]string{
		"cdn.discordapp.com": "discordapp.com",
		"gateway.discord.gg": "discord.gg",
		"discord.com":        "discord.com",
		"www.bbc.co.uk":      "bbc.co.uk",
		"foo.com.tr":         "foo.com.tr",
		"api.foo.com.tr":     "foo.com.tr",
		"user.github.io":     "user.github.io",
		"a.b.user.github.io": "user.github.io",
		"static.rbxcdn.com":  "rbxcdn.com",
		"github.io":          "github.io",
		"cloudflare-ech.com": "cloudflare-ech.com",
	}
	for in, want := range cases {
		if got, ok := Registrable(in); !ok || got != want {
			t.Errorf("Registrable(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}

func TestCovers(t *testing.T) {
	if !Covers("discord.com", "discord.com") || !Covers("discord.com", "cdn.discord.com") {
		t.Error("expected coverage")
	}
	if Covers("discord.com", "notdiscord.com") || Covers("discord.com", "discord.com.evil.net") {
		t.Error("unexpected coverage")
	}
}
