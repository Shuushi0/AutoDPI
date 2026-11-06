// Package config holds the few tunables, with defaults that need no file.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/Shuushi0/AutoDPI/internal/i18n"
)

type Config struct {
	// Engines is the ladder, tried in order. Known: tlsrec (sing-box TLS record
	// fragmentation), ciadpi, tlsfrag (sing-box TCP fragmentation), tlsspoof
	// (sing-box decoy ClientHello; needs root, skipped otherwise), warp.
	// tlsrec leads because it was the technique that opened Discord/Roblox on
	// the measured network, and it works on sing-box's own interface-bound
	// sockets, so the TUN cannot flatten it the way it flattens packet tricks.
	Engines []string `json:"engines"`
	// CiadpiArgs is the desync strategy (everything after the listen options).
	CiadpiArgs string `json:"ciadpi_args"`
	MaxConn    int    `json:"max_conn"`
	// HedgeMS starts the next engine alongside a slow real-path attempt.
	HedgeMS int `json:"hedge_ms"`
	// FirstByteMS bounds how long one attempt may wait for the server.
	FirstByteMS int `json:"first_byte_ms"`
	// BlockQUIC refuses QUIC (UDP/443) to listed domains so they use TCP,
	// where the engines apply. Other destinations keep QUIC.
	BlockQUIC bool `json:"block_quic"`
	// EscalateOnSilence lets a flow that only times out (a DPI that drops the
	// ClientHello silently) climb the whole engine ladder instead of trying the
	// first engine alone. Off by default: a stalled link or server also only
	// times out, and every engine against it multiplies the wait and traffic.
	EscalateOnSilence bool `json:"escalate_on_silence"`
	// LocalDomains are extra domain suffixes (company or campus names such as
	// corp.example.com) whose DNS questions go to the network's own resolver,
	// on top of the built-in local suffixes (.local, .lan, .corp, ...).
	LocalDomains []string `json:"local_domains"`
	// IPv4Only suppresses AAAA answers so every flow is captured by the v4 TUN.
	IPv4Only bool `json:"ipv4_only"`
	// RetestHours is how often listed domains are re-checked for lifted blocks.
	RetestHours int `json:"retest_hours"`
	// DNSTakeover points the active network service's resolver at 1.1.1.1
	// while the TUN is up (see sysdns). sing-box 1.14 also sets per-interface
	// DNS on its utun; turn this off once that alone proves enough.
	DNSTakeover bool `json:"dns_takeover"`
	// SpoofSNI is the decoy server name tlsspoof sends ahead of the real one; it
	// must be a name the DPI lets through.
	SpoofSNI string `json:"spoof_sni"`
	// DoHServers are the DNS-over-HTTPS resolvers, IP literals only (IPv4 or
	// IPv6; sing-box has no resolver to look a resolver's name up with, and a
	// name would be resolved by the very system DNS we capture). Used both by
	// sing-box (it races them) and by the daemon's own lookups (it fails over).
	// Two addresses of one service by default, so a stall at one is harmless.
	DoHServers []string `json:"doh_servers"`
	// WarpProfile is the path of a wgcf profile; setting it enables the warp tier.
	WarpProfile string `json:"warp_profile"`
	// AutoUpdate installs a newer release by itself, at a quiet moment; off,
	// the apps only announce it. UpdateCheckHours is how often GitHub is asked
	// (0: only when the user asks). The daemon reads both afresh before every
	// look, so a change needs no restart.
	AutoUpdate       bool `json:"auto_update"`
	UpdateCheckHours int  `json:"update_check_hours"`
	// Language of the command line, the apps and the web page: "tr", "en", or
	// "" for the system's (internal/i18n reads it). Load accepts any tag
	// i18n.Normalize maps to one of them and stores the short form.
	Language string `json:"language"`

	// Warnings are things Load noticed in the file that do not stop it from
	// being used (a retired key); the caller logs them once.
	Warnings []string `json:"-"`
}

// DefaultCiadpiArgs is the chain that opened discord.com, gateway.discord.gg
// and roblox.com on the measured network (oob, then disorder, then split).
const DefaultCiadpiArgs = "-r 1+s --oob 1 -A torst,ssl_err -r 1+s --disorder 1 -A torst,ssl_err -r 1+s --split 1+s"

func Default() Config {
	return Config{
		Engines:     []string{"tlsrec", "ciadpi", "tlsspoof"},
		CiadpiArgs:  DefaultCiadpiArgs,
		MaxConn:     8192,
		HedgeMS:     1200,
		FirstByteMS: 6000,
		BlockQUIC:   true,
		IPv4Only:    true,
		RetestHours: 3,
		SpoofSNI:    "www.google.com",
		DNSTakeover: true,
		DoHServers:  []string{"1.1.1.1", "1.0.0.1"},
		AutoUpdate:  true,

		UpdateCheckHours: 24,
	}
}

// Load reads path over the defaults; a missing file is not an error.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Default(), err
	}
	return parse(b, path)
}

// Parse reads the contents of a config file over the defaults and validates
// the result, as Load does.
func Parse(b []byte) (Config, error) { return parse(b, "") }

// parse is Parse; name, when set, prefixes a JSON error.
func parse(b []byte, name string) (Config, error) {
	c := Default()
	if err := json.Unmarshal(b, &c); err != nil {
		if name != "" {
			err = fmt.Errorf("%s: %w", name, err)
		}
		return Default(), err
	}
	if l := i18n.Normalize(c.Language); l != "" {
		c.Language = l // "TR", "tr-TR", "en_US.UTF-8": what the language choice accepts
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(b, &keys) == nil {
		if _, ok := keys["clean_days"]; ok {
			c.Warnings = append(c.Warnings, "clean_days is ignored: names that open directly are remembered in memory only now, with no expiry setting")
		}
	}
	return c, c.Validate()
}

var knownEngines = map[string]bool{"ciadpi": true, "tlsrec": true, "tlsfrag": true, "tlsspoof": true, "warp": true}

// MaxConnLimit is the largest max_conn that works: ciadpi exits at -c 32768
// and above, and the process fd limit is far lower anyway.
const MaxConnLimit = 16384

// MaxUpdateCheckHours is the longest update_check_hours: a month.
const MaxUpdateCheckHours = 24 * 30

func (c Config) Validate() error {
	if len(c.Engines) == 0 {
		return errors.New(i18n.T("config: engines (motor sırası) boş olamaz", "config: engines must not be empty"))
	}
	seen := map[string]bool{}
	for _, e := range c.Engines {
		if !knownEngines[e] {
			return fmt.Errorf(i18n.T("config: bilinmeyen motor %q", "config: unknown engine %q"), e)
		}
		if seen[e] {
			return fmt.Errorf(i18n.T("config: %q motoru iki kez yazılmış", "config: engine %q listed twice"), e)
		}
		seen[e] = true
		if e == "warp" && c.WarpProfile == "" {
			return errors.New(i18n.T("config: warp motoru warp_profile ister", "config: engine warp needs warp_profile"))
		}
	}
	if c.MaxConn < 16 || c.HedgeMS < 50 || c.FirstByteMS < 500 || c.RetestHours < 1 {
		return errors.New(i18n.T("config: değer aralık dışında (max_conn en az 16, hedge_ms en az 50, first_byte_ms en az 500, retest_hours en az 1)",
			"config: value out of range (max_conn at least 16, hedge_ms at least 50, first_byte_ms at least 500, retest_hours at least 1)"))
	}
	// Upper bounds keep the time.Duration products from overflowing: a huge
	// retest_hours wrapped negative and made the re-test timer fire at once,
	// re-testing the whole list back to back.
	if c.HedgeMS > 60_000 || c.FirstByteMS > 60_000 || c.RetestHours > 24*365 {
		return errors.New(i18n.T("config: değer aralık dışında (hedge_ms ve first_byte_ms en çok 60000, retest_hours en çok 8760)",
			"config: value out of range (hedge_ms and first_byte_ms at most 60000, retest_hours at most 8760)"))
	}
	if c.MaxConn > MaxConnLimit {
		return fmt.Errorf(i18n.T("config: max_conn en çok %d (gömülü ciadpi -c 32768 ve üstünü reddeder)", "config: max_conn at most %d (the bundled ciadpi refuses -c 32768 and above)"), MaxConnLimit)
	}
	if c.UpdateCheckHours < 0 || c.UpdateCheckHours > MaxUpdateCheckHours {
		return fmt.Errorf(i18n.T("config: update_check_hours 0 ile %d arasında olmalı (0: yalnızca istenince)", "config: update_check_hours must be 0 to %d (0: only when asked)"), MaxUpdateCheckHours)
	}
	for _, d := range c.LocalDomains {
		if !validSuffix(d) {
			return fmt.Errorf(i18n.T("config: local_domains içindeki %q bir alan adı değil", "config: local_domains entry %q is not a domain name"), d)
		}
	}
	if c.Language != "" && i18n.Normalize(c.Language) == "" {
		return errors.New(i18n.T(`config: language "tr", "en" ya da boş (sistemin dili) olmalı`, `config: language must be "tr", "en" or empty (the system's)`))
	}
	for _, h := range c.DoHServers {
		// They become https://<h>/dns-query and a sing-box server address: a
		// bare IP literal, no port, no zone, nothing else.
		if a, err := netip.ParseAddr(h); err != nil || a.Zone() != "" {
			return fmt.Errorf(i18n.T("config: doh_servers girdisi %q bir IP adresi değil (IPv4 ya da IPv6; port ve köşeli parantez olmadan)",
				"config: doh_servers entry %q is not an IP address (IPv4 or IPv6, without port or brackets)"), h)
		}
	}
	return nil
}

// CiadpiFields splits the strategy into arguments.
func (c Config) CiadpiFields() []string { return strings.Fields(c.CiadpiArgs) }

// validSuffix reports whether s is a domain name (a leading dot is allowed):
// dot-separated labels of letters, digits, '-' and '_'.
func validSuffix(s string) bool {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
