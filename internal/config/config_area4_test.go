package config

import (
	"bytes"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shuushi0/AutoDPI/internal/netx"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
)

func writeCfg(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// BUG (low): doh_servers accepts an IPv6 literal, but the daemon builds the
// resolver URL as "https://"+entry, which is not a valid URL for a bare IPv6
// address (it needs brackets). Validate says OK, the daemon's own lookups then
// fail against that server. Either Validate must reject it or the URL builder
// must bracket it.
func TestArea4_DoHServerIPv6LiteralUsable(t *testing.T) {
	c := Default()
	c.DoHServers = []string{"2606:4700:4700::1111"}
	if err := c.Validate(); err != nil {
		return // rejected up front: acceptable
	}
	if _, err := url.Parse("https://" + netx.HostForURL(c.DoHServers[0]) + "/dns-query"); err != nil {
		t.Errorf("Validate accepts doh_servers entry %q but netx builds an unparsable URL from it: %v", c.DoHServers[0], err)
	}
}

// BUG (low): control characters other than space/tab pass the doh_servers check
// (it only forbids " \t/?#@"), so a newline gets through to the URL and to the
// sing-box server address.
func TestArea4_DoHServerControlCharsRejected(t *testing.T) {
	for _, h := range []string{"1.1.1.1\n", "1.1.1.1\r", "1.1\x00.1.1", "one.one.one.one ", "a b", "1.1.1.1:99999999", "host:name:x"} {
		c := Default()
		c.DoHServers = []string{h}
		if err := c.Validate(); err == nil {
			if _, uerr := url.Parse("https://" + h + "/dns-query"); uerr != nil {
				t.Errorf("doh_servers entry %q accepted by Validate but %v", h, uerr)
			}
		}
	}
}

// BUG (low/medium): max_conn has no upper bound; it is passed verbatim to
// ciadpi's -c, and the bundled ciadpi (17.3) exits with "invalid value: -c N"
// for N >= 32768 (measured: 16384 starts, 32768 and everything above do not).
// So a config that Validate blesses silently kills the ciadpi engine.
func TestArea4_MaxConnUpperBound(t *testing.T) {
	c := Default()
	c.MaxConn = 65536
	if err := c.Validate(); err == nil {
		t.Errorf("max_conn=%d accepted (handed to `ciadpi -c`; the process limit is 16384 fds)", c.MaxConn)
	}
}

// Documented behaviour: one bad field discards the WHOLE file, including the
// good engine order. Load reports it; the daemon logs and uses defaults.
func TestArea4_OneBadFieldDiscardsTheWholeFile(t *testing.T) {
	p := writeCfg(t, `{"engines":["ciadpi"],"hedge_ms":"fast"}`)
	c, err := Load(p)
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(c.Engines) != 3 {
		t.Errorf("on a type error Load returns defaults, got %v", c.Engines)
	}
}

func TestArea4_LoadEdgeFiles(t *testing.T) {
	cases := map[string]struct {
		content string
		wantErr bool
	}{
		"empty":            {"", true},
		"spaces":           {" \n\t ", true},
		"null":             {"null", false},
		"empty object":     {"{}", false},
		"BOM":              {"\xef\xbb\xbf{}", true},
		"array":            {"[]", true},
		"trailing garbage": {`{} x`, true},
		"two objects":      {`{}{}`, true},
		"comment":          {"// hi\n{}", true},
		"trailing comma":   {`{"engines":["tlsrec"],}`, true},
		"engines null":     {`{"engines":null}`, true},
		"engines empty":    {`{"engines":[]}`, true},
		"upper-case key":   {`{"ENGINES":["ciadpi"]}`, false},
		"float for int":    {`{"retest_hours":3.0}`, true},
		"exp for int":      {`{"retest_hours":1e1}`, true},
		"string for bool":  {`{"block_quic":"true"}`, true},
		"int overflow":     {`{"max_conn":99999999999999999999}`, true},
		"negative":         {`{"max_conn":-1}`, true},
		"dup key last win": {`{"hedge_ms":1,"hedge_ms":500}`, false},
		"doh empty list":   {`{"doh_servers":[]}`, false},
		"doh null":         {`{"doh_servers":null}`, false},
		"doh blank":        {`{"doh_servers":[""]}`, true},
		"doh scheme":       {`{"doh_servers":["https://1.1.1.1"]}`, true},
		"warp w profile":   {`{"engines":["warp"],"warp_profile":"/x"}`, false},
		"first byte low":   {`{"first_byte_ms":499}`, true},
		"first byte edge":  {`{"first_byte_ms":500}`, false},
		"hedge edge lo":    {`{"hedge_ms":50}`, false},
		"hedge edge hi":    {`{"hedge_ms":60000}`, false},
		"max_conn 16":      {`{"max_conn":16}`, false},
		"max_conn 15":      {`{"max_conn":15}`, true},
		"clean_days gone":  {`{"clean_days":0}`, false},
		"doh v6":           {`{"doh_servers":["2606:4700:4700::1111"]}`, false},
		"doh hostname":     {`{"doh_servers":["dns.google"]}`, true},
		"max_conn 16384":   {`{"max_conn":16384}`, false},
		"max_conn 16385":   {`{"max_conn":16385}`, true},
		"retest 8760":      {`{"retest_hours":8760}`, false},
	}
	for name, tc := range cases {
		c, err := Load(writeCfg(t, tc.content))
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", name, err, tc.wantErr)
		}
		if err == nil {
			if verr := c.Validate(); verr != nil {
				t.Errorf("%s: Load ok but Validate fails: %v", name, verr)
			}
		}
	}
	// the duplicate key case really takes the last value
	if c, _ := Load(writeCfg(t, `{"hedge_ms":1,"hedge_ms":500}`)); c.HedgeMS != 500 {
		t.Errorf("duplicate key: %d", c.HedgeMS)
	}
	// directory / unreadable path: error, defaults returned, no panic
	if c, err := Load(t.TempDir()); err == nil || len(c.Engines) == 0 {
		t.Errorf("directory path: %v %v", err, c.Engines)
	}
}

// Typos in key names are silently ignored (json.Unmarshal without
// DisallowUnknownFields): "engine" instead of "engines" changes nothing and
// reports nothing. Logged, not asserted: it is a design choice.
func TestArea4_UnknownKeysAreIgnored(t *testing.T) {
	c, err := Load(writeCfg(t, `{"engine":["ciadpi"],"hedgems":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Engines) == 3 {
		t.Log("unknown keys ('engine', 'hedgems') are silently ignored: a typo gives no feedback")
	}
}

func TestArea4_ValidateIsNotMutatingAndDefaultsAreIndependent(t *testing.T) {
	a, b := Default(), Default()
	a.Engines[0] = "ciadpi"
	a.DoHServers[0] = "9.9.9.9"
	if b.Engines[0] != "tlsrec" || b.DoHServers[0] != "1.1.1.1" {
		t.Errorf("Default() shares slices between calls: %v %v", b.Engines, b.DoHServers)
	}
	// a Load overlay of a short engine list must replace, not merge into, the default slice
	c, _ := Load(writeCfg(t, `{"engines":["ciadpi"]}`))
	if len(c.Engines) != 1 {
		t.Errorf("engines merged with defaults: %v", c.Engines)
	}
	if d := Default(); len(d.Engines) != 3 || d.Engines[0] != "tlsrec" {
		t.Errorf("Load mutated shared defaults: %v", d.Engines)
	}
}

func TestArea4_CiadpiFields(t *testing.T) {
	c := Default()
	c.CiadpiArgs = "  -r  1+s\t--oob 1 \n -A torst "
	got := strings.Join(c.CiadpiFields(), "|")
	if got != "-r|1+s|--oob|1|-A|torst" {
		t.Errorf("fields %q", got)
	}
	c.CiadpiArgs = ""
	if len(c.CiadpiFields()) != 0 {
		t.Error("empty args must yield no fields")
	}
	// quotes are NOT shell-parsed: a quoted argument with a space splits
	c.CiadpiArgs = `--fake "a b"`
	if len(c.CiadpiFields()) != 3 {
		t.Log("ciadpi_args is split on whitespace; quoting is not supported")
	}
}

// Entries that Validate accepts are written into the sing-box DNS server list.
// If sing-box refuses the resulting file, the daemon cannot bring the capture
// up at all after the next restart, which is much worse than one bad resolver.
func TestArea4_ValidatedDoHEntriesProduceAConfigSingBoxAccepts(t *testing.T) {
	bin, _ := filepath.Abs(filepath.Join("..", "..", "bin", "sing-box"))
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no sing-box binary")
	}
	for _, h := range []string{"1.1.1.1", "dns.google", "2606:4700:4700::1111", "1.1.1.1:443", "1.1.1.1\n", "host:name:x", "UPPER.Example.COM", "xn--bcher-kva.de", "-", "1.1.1.1.", "1"} {
		c := Default()
		c.DoHServers = []string{h, "1.0.0.1"}
		if c.Validate() != nil {
			continue
		}
		dir := t.TempDir()
		if err := singbox.WriteRuleSet(dir, "tlsrec", []string{"discord.com"}); err != nil {
			t.Fatal(err)
		}
		cfg, err := singbox.Build(singbox.Options{
			Engines:      []singbox.Engine{{Name: "tlsrec", Kind: singbox.TLSRecord, Port: 21083}},
			ObserverPort: 21082, RuleDir: dir, Tun: true, IPv4Only: true, DoH: c.DoHServers,
		})
		if err != nil {
			t.Errorf("doh %q: build: %v", h, err)
			continue
		}
		f := filepath.Join(dir, "sb.json")
		os.WriteFile(f, cfg, 0o600)
		var out bytes.Buffer
		cmd := exec.Command(bin, "check", "-c", f)
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			t.Errorf("doh_servers entry %q passes config.Validate but `sing-box check` fails: %s", h, strings.TrimSpace(out.String()))
		}
	}
}
