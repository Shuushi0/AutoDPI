package netx

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultDoHServers are the resolvers used when none are configured. They are
// two addresses of the same service on purpose: either one answers for the
// other, so a stall at one address (seen live: 1.1.1.1 timing out briefly)
// does not take DNS down.
var DefaultDoHServers = []string{"1.1.1.1", "1.0.0.1"}

// DoH is a tiny DNS-over-HTTPS client speaking Cloudflare's JSON dialect. It
// dials through the physical interface, so it keeps working while our TUN is up
// and never loops back into sing-box.
//
// Every request fails over per query: the servers are tried in order, each for
// at most Attempt, and the one that last answered goes first, so a stalled
// resolver costs one timeout and is then skipped until it recovers.
type DoH struct {
	Client  *http.Client
	Bases   []string      // https://1.1.1.1, https://1.0.0.1
	Attempt time.Duration // per-server limit, default 4s

	mu    sync.Mutex
	last  int                   // index into Bases of the server that answered last
	conns map[*dohConn]struct{} // every connection the transport has open
}

// dohConn is a connection of the DoH transport that Reset can close.
type dohConn struct {
	net.Conn
	d    *DoH
	once sync.Once
}

func (c *dohConn) Close() error {
	c.once.Do(func() {
		c.d.mu.Lock()
		delete(c.d.conns, c)
		c.d.mu.Unlock()
	})
	return c.Conn.Close()
}

// NewDoH returns a client over the default servers.
func NewDoH(d *Dialer) *DoH { return NewDoHServers(d, DefaultDoHServers) }

// NewDoHServers returns a client over the given resolver hosts or IPs
// (blanks and duplicates dropped; none given means the defaults).
func NewDoHServers(d *Dialer, servers []string) *DoH {
	doh := &DoH{conns: map[*dohConn]struct{}{}}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tc := &dohConn{Conn: c, d: doh}
			doh.mu.Lock()
			doh.conns[tc] = struct{}{}
			doh.mu.Unlock()
			return tc, nil
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		MaxIdleConns:          4,
		// Longer than the daemon's 30s health period, so a check reuses the
		// HTTP/2 connection instead of a new TLS handshake each time.
		IdleConnTimeout: 90 * time.Second,
		// A connection whose far end went away without a word (the link
		// dropped, the machine slept, a NAT forgot it) looks alive until
		// something is written to it, and HTTP/2 then waits on it instead of
		// opening a new one: every query failed for as long as the daemon
		// kept asking (measured: over 30 s). A ping after a while without a
		// frame, and 3 s for its reply, ends such a connection; and a lookup
		// that failed on every server closes the connections at once (each,
		// Reset). Not a short interval: the health check keeps the
		// connection in use, so a 5 s ping went out every few seconds for as
		// long as the service ran, and a phone sharing its line never got to
		// put its radio to sleep.
		HTTP2: &http.HTTP2Config{SendPingTimeout: 45 * time.Second, PingTimeout: 3 * time.Second},
	}
	var bases []string
	for _, s := range CleanServers(servers) {
		bases = append(bases, "https://"+HostForURL(s))
	}
	doh.Client = &http.Client{Transport: tr}
	doh.Bases = bases
	return doh
}

// Reset closes the connections, so the next query opens a new one. For the
// moment the network comes back, and for a lookup that failed on every
// server: what was open is dead, and nothing has said so yet.
//
// Closing only the idle ones is not enough. HTTP/2 counts a connection as in
// use until the query that just timed out has let go of it, which is a
// moment after that query returned, and with lookups coming one after another
// it is never idle at all: the dead connection was kept and every lookup
// failed until the ping gave up on it (measured: 8 lookups in a row, 32 s).
func (d *DoH) Reset() {
	if d == nil || d.Client == nil {
		return
	}
	d.mu.Lock()
	open := make([]*dohConn, 0, len(d.conns))
	for c := range d.conns {
		open = append(open, c)
	}
	d.mu.Unlock()
	for _, c := range open {
		_ = c.Close()
	}
	d.Client.CloseIdleConnections()
}

// HostForURL brackets an IPv6 literal for use as the host of a URL.
func HostForURL(s string) string {
	if a, err := netip.ParseAddr(s); err == nil && a.Is6() {
		return "[" + s + "]"
	}
	return s
}

// CleanServers trims, drops blanks and duplicates and falls back to
// DefaultDoHServers when nothing is left.
func CleanServers(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultDoHServers...)
	}
	return out
}

type dohAnswer struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}

// definitive marks an answer from a resolver that is final (NXDOMAIN, no
// records): asking another server would only repeat it, so it ends failover.
type definitive struct{ error }

func (e definitive) Unwrap() error { return e.error }

func (d *DoH) attempt() time.Duration {
	if d.Attempt > 0 {
		return d.Attempt
	}
	return 4 * time.Second
}

// each runs fn against the servers until one gives a final result. It
// returns every server's error when all fail.
func (d *DoH) each(ctx context.Context, fn func(ctx context.Context, base string) error) error {
	n := len(d.Bases)
	if n == 0 {
		return errors.New("doh: no servers configured")
	}
	d.mu.Lock()
	first := d.last % n
	d.mu.Unlock()
	var errs []error
	for i := 0; i < n; i++ {
		idx := (first + i) % n
		actx, cancel := context.WithTimeout(ctx, d.attempt())
		err := fn(actx, d.Bases[idx])
		cancel()
		var def definitive
		if err == nil || errors.As(err, &def) {
			d.mu.Lock()
			d.last = idx
			d.mu.Unlock()
			if def.error != nil {
				return def.error
			}
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", strings.TrimPrefix(d.Bases[idx], "https://"), err))
		if ctx.Err() != nil { // the caller gave up; trying more is pointless
			break
		}
	}
	// Every server failed: if that was a connection gone dead without a
	// word, the next lookup must not be handed the same one. Not when it was
	// the caller that gave up: that says nothing about the connections, and
	// other lookups may be using them.
	if ctx.Err() == nil {
		d.Reset()
	}
	return errors.Join(errs...)
}

func (d *DoH) query(ctx context.Context, name, typ string) ([]dohAnswer, error) {
	var ans []dohAnswer
	err := d.each(ctx, func(ctx context.Context, base string) error {
		var err error
		ans, err = d.queryOne(ctx, base, name, typ)
		return err
	})
	return ans, err
}

func (d *DoH) queryOne(ctx context.Context, base, name, typ string) ([]dohAnswer, error) {
	q := url.Values{"name": {name}, "type": {typ}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/dns-query?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Status int         `json:"Status"`
		Answer []dohAnswer `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	switch body.Status {
	case 0:
	case 3: // NXDOMAIN: the name does not exist, whoever is asked
		return nil, definitive{fmt.Errorf("doh: rcode %d for %s", body.Status, name)}
	default: // SERVFAIL, REFUSED...: another resolver may do better
		return nil, fmt.Errorf("doh: rcode %d for %s", body.Status, name)
	}
	return body.Answer, nil
}

// LookupIPv4 returns the A records for name.
func (d *DoH) LookupIPv4(ctx context.Context, name string) ([]netip.Addr, error) {
	ans, err := d.query(ctx, name, "A")
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range ans {
		if a.Type != 1 {
			continue
		}
		if ip, err := netip.ParseAddr(a.Data); err == nil {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("doh: no A records for %s", name)
	}
	return out, nil
}

// LookupTXT returns the TXT strings for name with their quotes removed.
func (d *DoH) LookupTXT(ctx context.Context, name string) ([]string, error) {
	ans, err := d.query(ctx, name, "TXT")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range ans {
		if a.Type == 16 {
			out = append(out, strings.Trim(a.Data, `"`))
		}
	}
	return out, nil
}

// PublicIP asks Cloudflare's trace endpoint which address the world sees.
func (d *DoH) PublicIP(ctx context.Context) (netip.Addr, error) {
	var ip netip.Addr
	err := d.each(ctx, func(ctx context.Context, base string) error {
		var err error
		ip, err = d.publicIPOne(ctx, base)
		return err
	})
	return ip, err
}

func (d *DoH) publicIPOne(ctx context.Context, base string) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/cdn-cgi/trace", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("trace: HTTP %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ip="); ok {
			return netip.ParseAddr(strings.TrimSpace(v))
		}
	}
	return netip.Addr{}, errors.New("trace: no ip field")
}
