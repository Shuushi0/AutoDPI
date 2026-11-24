package config

import (
	"slices"
	"strings"
	"testing"
)

// sing-box matches a configured suffix as it is written; "CORP" and " .corp"
// were accepted and then matched nothing.
func TestLocalDomainsAreNormalised(t *testing.T) {
	c, err := Parse([]byte(`{"local_domains": ["CORP", " .Office.Example ", "lan"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"corp", "office.example", "lan"}; !slices.Equal(c.LocalDomains, want) {
		t.Fatalf("local_domains = %q, want %q", c.LocalDomains, want)
	}
}

// A file an earlier version accepted must never be thrown away as a whole:
// the service then runs on every default, DNS takeover switched back on
// included, with nothing on screen. Each of these was refused for a few days;
// they are repaired one value at a time, with a warning, and the rest of the
// file stands.
func TestAFileFromAnEarlierVersionIsRepairedNotRefused(t *testing.T) {
	for _, tc := range []struct {
		in    string
		check func(Config) bool
		warn  bool
	}{
		{`"local_domains": ["home.arpa"]`, func(c Config) bool { return slices.Equal(c.LocalDomains, []string{"home.arpa"}) }, false},
		{`"local_domains": ["office", "edu.tr", "com"]`, func(c Config) bool { return len(c.LocalDomains) == 3 }, true},
		{`"spoof_sni": " www.google.com. "`, func(c Config) bool { return c.SpoofSNI == "www.google.com" }, false},
		{`"spoof_sni": "localhost"`, func(c Config) bool { return c.SpoofSNI == "localhost" }, false},
		{`"spoof_sni": "my_host.example.com"`, func(c Config) bool { return c.SpoofSNI == "my_host.example.com" }, false},
		{`"spoof_sni": "example.org:443"`, func(c Config) bool { return c.SpoofSNI == Default().SpoofSNI }, true},
		{`"spoof_sni": "a b.example"`, func(c Config) bool { return c.SpoofSNI == Default().SpoofSNI }, true},
		{`"doh_servers": ["0.0.0.0", "9.9.9.9"]`, func(c Config) bool { return slices.Equal(c.DoHServers, []string{"9.9.9.9"}) }, true},
		{`"doh_servers": ["::", "::ffff:0.0.0.0", "224.0.0.1"]`, func(c Config) bool { return len(c.DoHServers) == 0 }, true},
	} {
		c, err := Parse([]byte(`{"dns_takeover": false, "engines": ["ciadpi", "tlsrec"], ` + tc.in + `}`))
		if err != nil {
			t.Errorf("%s: the whole file is refused: %v", tc.in, err)
			continue
		}
		if c.DNSTakeover || !slices.Equal(c.Engines, []string{"ciadpi", "tlsrec"}) {
			t.Errorf("%s: the user's other settings were lost: %+v", tc.in, c)
		}
		if !tc.check(c) {
			t.Errorf("%s: got spoof_sni=%q doh=%q local=%q", tc.in, c.SpoofSNI, c.DoHServers, c.LocalDomains)
		}
		if tc.warn != (len(c.Warnings) > 0) {
			t.Errorf("%s: warnings = %q", tc.in, c.Warnings)
		}
	}
}

// What the settings page refuses when the user ADDS it.
func TestCheckLocalDomain(t *testing.T) {
	for _, bad := range []string{"com", "com.tr", "co.uk", "net", "a b"} {
		if CheckLocalDomain(bad) == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, good := range []string{"corp", "company.local", "home.arpa", "lan", "internal", "10.in-addr.arpa", "example.com.tr"} {
		if err := CheckLocalDomain(good); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
	if err := CheckLocalDomain("com"); err == nil || !strings.Contains(err.Error(), "com") {
		t.Errorf("the refusal does not name the entry: %v", err)
	}
}
