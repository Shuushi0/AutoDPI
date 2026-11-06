// Package netid names the network we are on, because what a DPI box blocks is a
// property of the ISP, not of the Mac. The stable name is the public address's
// AS number; until that is known a gateway-based name stands in.
package netid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/netx"
)

type Info struct {
	Key         string // asn:9121 or gw:<hash>
	Label       string
	Iface       string
	Gateway     string
	ASN         int
	Provisional bool // gateway-based key, ASN lookup still pending
	Online      bool
	// GatewayKey is this attachment's gateway-based key; while Provisional it
	// equals Key. A stable key whose GatewayKey is an earlier provisional
	// Key is that same network, identified.
	GatewayKey string
}

type Monitor struct {
	DoH      *netx.DoH
	Interval time.Duration
	// Idle, when set, replaces Interval as the time between polls: the caller
	// promises to Poke the monitor whenever the routing table changes, so the
	// timer is only a safety net.
	Idle time.Duration
	// OnChange fires when the key changes, including provisional -> ASN.
	OnChange func(old, cur Info)
	Log      *slog.Logger

	// route, mac and lookup reach the system and the network; nil means the
	// real thing. Tests replace them.
	route  func() (iface, gateway string, err error)
	mac    func(gateway string) string
	lookup func(ctx context.Context) (asn int, name string, err error)

	mu     sync.RWMutex
	cur    Info
	fp     string // iface|gateway|mac at the last real change; keys cache
	attach string // iface|gateway
	gwMAC  string // the gateway's MAC once it was seen (it may show up late)
	// epoch counts the attachments polled so far. An AS lookup speaks for the
	// attachment of the epoch it was started in, and for no other: fp alone
	// cannot tell, since a network left and joined again has the same fp.
	epoch      uint64
	cache      map[string]Info
	downLogged time.Time // poll goroutine only

	wakeOnce sync.Once
	wake     chan struct{}

	readyOnce, readyClose sync.Once
	ready                 chan struct{}
}

func (m *Monitor) wakeCh() chan struct{} {
	m.wakeOnce.Do(func() { m.wake = make(chan struct{}, 1) })
	return m.wake
}

func (m *Monitor) readyCh() chan struct{} {
	m.readyOnce.Do(func() { m.ready = make(chan struct{}) })
	return m.ready
}

// Ready is closed once Run has looked at the routing table for the first time.
// Until then Current is the zero Info: offline, without anybody having looked.
func (m *Monitor) Ready() <-chan struct{} { return m.readyCh() }

// Poke asks for a poll now (the routing table changed); bursts coalesce.
func (m *Monitor) Poke() {
	select {
	case m.wakeCh() <- struct{}{}:
	default:
	}
}

func (m *Monitor) Current() Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cur
}

func (m *Monitor) logger() *slog.Logger {
	if m.Log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return m.Log
}

// Run polls until ctx ends.
func (m *Monitor) Run(ctx context.Context) {
	if m.Interval == 0 {
		m.Interval = 4 * time.Second
	}
	every := m.Interval
	if m.Idle > 0 {
		every = m.Idle
	}
	m.cache = map[string]Info{}
	m.poll(ctx)
	m.readyClose.Do(func() { close(m.readyCh()) })
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			m.poll(ctx)
		case <-m.wakeCh():
			m.poll(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (m *Monitor) set(cur Info) (old Info) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, m.cur = m.cur, cur
	return old
}

func (m *Monitor) defaultRoute() (string, string, error) {
	if m.route != nil {
		return m.route()
	}
	return netx.DefaultRoute()
}

func (m *Monitor) gatewayMAC(gw string) string {
	if m.mac != nil {
		return m.mac(gw)
	}
	return gatewayMAC(gw)
}

func (m *Monitor) lookupASN(ctx context.Context) (int, string, error) {
	if m.lookup != nil {
		return m.lookup(ctx)
	}
	return lookupASN(ctx, m.DoH)
}

func (m *Monitor) poll(ctx context.Context) {
	iface, gw, err := m.defaultRoute()
	if err != nil {
		cur := m.Current()
		if cur.Online {
			cur.Online = false
			m.set(cur)
		}
		if time.Since(m.downLogged) > 10*time.Minute { // say why, not just once (a long sleep is offline for hours)
			m.downLogged = time.Now()
			m.logger().Warn("no default route", "err", err)
		}
		return
	}
	m.downLogged = time.Time{}
	attach, mac := iface+"|"+gw, m.gatewayMAC(gw)
	m.mu.Lock()
	// The same attachment is the same network. Its gateway's MAC is only a
	// tie-breaker: the ARP entry may be missing at first sight and appear
	// later (or expire), which is not a change; two different MACs are.
	same := attach == m.attach && (mac == "" || m.gwMAC == "" || mac == m.gwMAC)
	if same {
		if m.gwMAC == "" {
			m.gwMAC = mac
		}
	} else {
		m.attach, m.gwMAC = attach, mac
		m.fp = attach + "|" + mac
		m.epoch++
	}
	fp, epoch := m.fp, m.epoch
	known, cached := m.cache[fp] // resolve goroutines write it under mu
	m.mu.Unlock()
	if same {
		if cur := m.Current(); !cur.Online {
			cur.Online = true
			m.set(cur)
		}
		return
	}

	netx.InvalidatePhysical()
	if cached {
		known.Online = true // we have a default route right now
		old := m.set(known)
		m.notify(old, known)
		return
	}
	key := "gw:" + shortHash(fp)
	prov := Info{
		Key: key, Label: fmt.Sprintf("%s via %s", iface, gw),
		Iface: iface, Gateway: gw, Provisional: true, Online: true, GatewayKey: key,
	}
	old := m.set(prov)
	m.logger().Info("network changed", "iface", iface, "gateway", gw, "key", prov.Key)
	m.notify(old, prov)
	go m.resolve(ctx, fp, epoch, prov)
}

func (m *Monitor) notify(old, cur Info) {
	if old.Key != cur.Key && m.OnChange != nil {
		m.OnChange(old, cur)
	}
}

// resolve learns the AS number, retrying with backoff, and swaps the key once.
//
// The lookup asks whichever network carries traffic while it runs, which need
// not be prov's: the route may have moved and not been polled yet. Its answer
// counts only if no poll has seen another attachment since prov's (epoch) and
// the route is still prov's attachment once the answer is in. Anything else may
// be the other network's AS, which the cache would keep under prov's
// fingerprint until a restart; it is dropped and asked again while prov's
// attachment stays current.
func (m *Monitor) resolve(ctx context.Context, fp string, epoch uint64, prov Info) {
	for _, wait := range []time.Duration{0, 2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute} {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
		m.mu.RLock()
		stale := m.epoch != epoch
		m.mu.RUnlock()
		if stale {
			return
		}
		lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		asn, name, err := m.lookupASN(lctx)
		cancel()
		if err != nil {
			m.logger().Debug("asn lookup failed", "err", err)
			continue
		}
		info := prov
		info.Key, info.ASN, info.Provisional = fmt.Sprintf("asn:%d", asn), asn, false
		info.Label = fmt.Sprintf("AS%d", asn)
		if name != "" {
			info.Label += " " + name
		}
		iface, gw, rerr := m.defaultRoute()
		mac := ""
		if rerr == nil {
			mac = m.gatewayMAC(gw)
		}
		m.mu.Lock()
		if m.epoch != epoch {
			m.mu.Unlock()
			return
		}
		if rerr != nil || iface+"|"+gw != m.attach || (mac != "" && m.gwMAC != "" && mac != m.gwMAC) {
			m.mu.Unlock()
			m.logger().Debug("asn lookup raced a route change; asking again", "asn", asn)
			continue
		}
		cached := info
		cached.Online = true
		m.cache[fp] = cached
		old := m.cur
		info.Online = old.Online // whether the route is up is the poll's to say
		m.cur = info
		m.mu.Unlock()
		m.logger().Info("network identified", "key", info.Key, "label", info.Label)
		m.notify(old, info)
		return
	}
}

func lookupASN(ctx context.Context, doh *netx.DoH) (int, string, error) {
	ip, err := doh.PublicIP(ctx)
	if err != nil {
		return 0, "", err
	}
	name, err := originName(ip)
	if err != nil {
		return 0, "", err
	}
	txt, err := doh.LookupTXT(ctx, name)
	if err != nil {
		return 0, "", err
	}
	if len(txt) == 0 {
		return 0, "", errors.New("no origin record")
	}
	asn, err := parseOrigin(txt[0])
	if err != nil {
		return 0, "", err
	}
	label := ""
	if rec, err := doh.LookupTXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com", asn)); err == nil && len(rec) > 0 {
		label = parseASName(rec[0])
	}
	return asn, label, nil
}

func originName(ip netip.Addr) (string, error) {
	ip = ip.Unmap()
	if !ip.Is4() {
		return "", errors.New("IPv4 public address required")
	}
	b := ip.As4()
	return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0]), nil
}

// parseOrigin reads Team Cymru's "9121 | 88.240.0.0/13 | TR | ripencc | 2007-.."
func parseOrigin(txt string) (int, error) {
	first := strings.TrimSpace(strings.SplitN(txt, "|", 2)[0])
	f := strings.Fields(first)
	if len(f) == 0 {
		return 0, errors.New("empty origin record")
	}
	return strconv.Atoi(f[0])
}

// parseASName reads "9121 | TR | ripencc | 1996-12-02 | TTNET, TR".
func parseASName(txt string) string {
	parts := strings.Split(txt, "|")
	if len(parts) < 5 {
		return ""
	}
	return strings.TrimSpace(parts[4])
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}
