package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	if got := Default().Engines[0]; got != "tlsrec" {
		t.Fatalf("ladder should lead with tlsrec, got %q", got)
	}
}

func TestLoadOverlaysDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if c, err := Load(p); err != nil || c.MaxConn != Default().MaxConn {
		t.Fatalf("missing file must yield defaults: %v", err)
	}
	if err := os.WriteFile(p, []byte(`{"engines":["ciadpi"],"hedge_ms":500}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Engines) != 1 || c.HedgeMS != 500 || c.MaxConn != Default().MaxConn || !c.BlockQUIC {
		t.Fatalf("overlay wrong: %+v", c)
	}
}

func TestValidateRejects(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"no engines":     func(c *Config) { c.Engines = nil },
		"unknown engine": func(c *Config) { c.Engines = []string{"zapret"} },
		"duplicate":      func(c *Config) { c.Engines = []string{"ciadpi", "ciadpi"} },
		"warp w/o file":  func(c *Config) { c.Engines = []string{"warp"} },
		"tiny hedge":     func(c *Config) { c.HedgeMS = 1 },
		// time.Duration(3000000)*time.Hour wraps negative: the re-test timer
		// would fire at once, over and over.
		"overflowing retest": func(c *Config) { c.RetestHours = 3_000_000 },
		"huge retest":        func(c *Config) { c.RetestHours = 24*365 + 1 },
		"huge hedge":         func(c *Config) { c.HedgeMS = 60_001 },
		"huge max_conn":      func(c *Config) { c.MaxConn = MaxConnLimit + 1 },
		"doh hostname":       func(c *Config) { c.DoHServers = []string{"dns.google"} },
		"doh with port":      func(c *Config) { c.DoHServers = []string{"1.1.1.1:443"} },
		"doh bracketed v6":   func(c *Config) { c.DoHServers = []string{"[2606:4700:4700::1111]"} },
		"doh v6 zone":        func(c *Config) { c.DoHServers = []string{"fe80::1%en0"} },
		"doh newline":        func(c *Config) { c.DoHServers = []string{"1.1.1.1\n"} },
		"huge first byte":    func(c *Config) { c.FirstByteMS = 60_001 },
		"doh with a path":    func(c *Config) { c.DoHServers = []string{"1.1.1.1/dns-query"} },
		"blank doh":          func(c *Config) { c.DoHServers = []string{"1.1.1.1", " "} },
	} {
		c := Default()
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// The language is read with i18n.Normalize everywhere else (the CLI, the
// macOS app): a tag it accepts must not make the daemon drop the whole file.
func TestLanguageTags(t *testing.T) {
	for in, want := range map[string]string{"tr": "tr", "TR": "tr", "tr-TR": "tr", "tr_TR.UTF-8": "tr", "EN": "en", "en-US": "en", "": ""} {
		c, err := Load(writeCfg(t, `{"language": "`+in+`", "retest_hours": 5}`))
		if err != nil || c.Language != want || c.RetestHours != 5 {
			t.Errorf("language %q: %q, retest_hours %d, %v", in, c.Language, c.RetestHours, err)
		}
	}
	for _, in := range []string{"fr", "turkish", " "} {
		if _, err := Load(writeCfg(t, `{"language": "`+in+`"}`)); err == nil {
			t.Errorf("language %q accepted", in)
		}
	}
}

func TestBrokenFileIsAnError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(p, []byte("{nope"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateAcceptsUpperBounds(t *testing.T) {
	c := Default()
	c.RetestHours, c.HedgeMS, c.FirstByteMS = 24*365, 60_000, 60_000
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDoHServersDefaultAndOverride(t *testing.T) {
	if got := Default().DoHServers; len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "1.0.0.1" {
		t.Fatalf("default resolvers = %v", got)
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"doh_servers":["9.9.9.9","149.112.112.112"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || len(c.DoHServers) != 2 || c.DoHServers[0] != "9.9.9.9" {
		t.Fatalf("override = %v, %v", c.DoHServers, err)
	}
}

func TestIPv6DoHServerIsAccepted(t *testing.T) {
	c := Default()
	c.DoHServers = []string{"2606:4700:4700::1111", "1.0.0.1"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.MaxConn = MaxConnLimit
	if err := c.Validate(); err != nil {
		t.Fatalf("max_conn at the limit: %v", err)
	}
}

// clean_days belonged to the retired persistent clean list. A config that
// still has it loads, the value is ignored, and Load says so once.
func TestRetiredCleanDaysIsIgnoredWithAWarning(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"clean_days": 0, "max_conn": 99}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c.MaxConn != 99 {
		t.Fatalf("Load: %+v, %v", c, err)
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "clean_days") {
		t.Fatalf("warnings = %v", c.Warnings)
	}
	if err := os.WriteFile(p, []byte(`{"max_conn": 99}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if c, _ = Load(p); len(c.Warnings) != 0 {
		t.Fatalf("warning without the key: %v", c.Warnings)
	}
}
