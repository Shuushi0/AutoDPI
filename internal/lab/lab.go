// Package lab measures which evasion techniques open a set of hosts on the
// network you are on right now. It needs no root and no TUN: every technique
// runs as a local SOCKS endpoint and is probed with a real TLS handshake, next
// to a plain "direct" column. Run it with no VPN (WARP, ...) connected.
package lab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/embedded"
	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/netx"
	"github.com/Shuushi0/AutoDPI/internal/probe"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
	"github.com/Shuushi0/AutoDPI/internal/supervise"
	"github.com/Shuushi0/AutoDPI/internal/sysx"
)

type variant struct {
	name string
	args string
}

// Single techniques plus the production chain, so a result shows *which part*
// of the chain does the work.
var ciadpiVariants = []variant{
	{"chain", config.DefaultCiadpiArgs},
	{"tlsrec", "-r 1+s"},
	{"split", "--split 1+s"},
	{"split-1", "--split 1"},
	{"oob", "--oob 1"},
	{"disorder", "--disorder 1"},
	{"rec+split", "-r 1+s --split 1+s"},
}

type Options struct {
	Hosts []string
	Bins  embedded.Bins
	Self  string
	Out   io.Writer
	Force bool // measure even though a VPN seems to own the traffic
}

type column struct {
	name string
	dial probe.Dial
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func waitListening(port int) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for i := 0; i < 80; i++ {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf(i18n.T("%s adresinde dinleyen yok", "nothing listening on %s"), addr)
}

func Run(ctx context.Context, o Options) error {
	if !o.Force {
		if ifc, found := netx.ForeignTunnel(singbox.TunIP); found {
			return fmt.Errorf(i18n.T("başka bir tünel (%s) trafiği yakalıyor (WARP/VPN?). Bu bağlıyken ölçüm anlamsız; kapatıp tekrar deneyin (ya da --force)", "another tunnel (%s) captures the traffic (WARP/VPN?). Measuring through it means nothing; turn it off and try again (or --force)"), ifc)
		}
	}
	dial := &netx.Dialer{Timeout: 6 * time.Second}
	doh := netx.NewDoH(dial)

	type target struct {
		host string
		ip   netip.Addr
	}
	var targets []target
	for _, h := range o.Hosts {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ips, err := doh.LookupIPv4(rctx, h)
		cancel()
		if err != nil {
			fmt.Fprintf(o.Out, i18n.T("! %s çözümlenemedi (DoH): %v\n", "! %s did not resolve (DoH): %v\n"), h, err)
			continue
		}
		targets = append(targets, target{h, ips[0]})
	}
	if len(targets) == 0 {
		return errors.New(i18n.T("çözümlenebilen hedef yok", "no target resolved"))
	}

	cols := []column{{"direct", dial.DialContext}}
	var procs []*supervise.Proc
	defer func() {
		var wg sync.WaitGroup
		for _, p := range procs {
			wg.Add(1)
			go func() { defer wg.Done(); p.Stop(6 * time.Second) }()
		}
		wg.Wait()
	}()

	for _, v := range ciadpiVariants {
		port, err := freePort()
		if err != nil {
			return err
		}
		args := append([]string{"-i", "127.0.0.1", "-p", strconv.Itoa(port)}, strings.Fields(v.args)...)
		p, err := supervise.Start(supervise.Spec{Name: "ciadpi-" + v.name, Path: o.Bins.Ciadpi, Args: args, Self: o.Self, HardKill: true})
		if err != nil {
			return err
		}
		procs = append(procs, p)
		if err := waitListening(port); err != nil {
			return fmt.Errorf("ciadpi %s: %w", v.name, err)
		}
		cols = append(cols, column{v.name, probe.ViaSocks(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))})
	}

	// sing-box's own fragmenters, as plain SOCKS inbounds.
	dir, err := os.MkdirTemp("", "autodpi-lab-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	recPort, _ := freePort()
	segPort, _ := freePort()
	spoofPort, _ := freePort()
	obsPort, _ := freePort()
	testPort, _ := freePort()
	engines := []singbox.Engine{
		{Name: "tlsrec", Kind: singbox.TLSRecord, Port: recPort},
		{Name: "tlsfrag", Kind: singbox.TLSSegment, Port: segPort},
	}
	if sysx.IsRoot() { // the decoy is injected through a raw socket (WinDivert on Windows)
		engines = append(engines, singbox.Engine{Name: "tlsspoof", Kind: singbox.TLSSpoof, Port: spoofPort})
	}
	for _, e := range engines {
		if err := singbox.WriteRuleSet(dir, e.Name, nil); err != nil {
			return err
		}
	}
	cfg, err := singbox.Build(singbox.Options{Engines: engines, ObserverPort: obsPort, RuleDir: dir, TestPort: testPort})
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return err
	}
	sb, err := supervise.Start(supervise.Spec{Name: "sing-box", Path: o.Bins.SingBox, Self: o.Self,
		Args: []string{"--disable-color", "run", "-c", cfgPath}})
	if err != nil {
		return err
	}
	procs = append(procs, sb)
	for _, e := range engines {
		if err := waitListening(e.Port); err != nil {
			return fmt.Errorf("sing-box %s: %w", e.Name, err)
		}
		cols = append(cols, column{"sb:" + e.Name, probe.ViaSocks(e.Addr())})
	}

	// The measurement: two handshakes per cell, columns in parallel.
	cell := make([][]string, len(targets))
	for i := range cell {
		cell[i] = make([]string, len(cols))
	}
	works := make([][]bool, len(targets))
	for i := range works {
		works[i] = make([]bool, len(cols))
	}
	var wg sync.WaitGroup
	for ti, t := range targets {
		for ci, c := range cols {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p := &probe.Prober{Dial: c.dial, Timeout: 6 * time.Second}
				ok, haveFail, fail := 0, false, probe.Result{}
				for try := 0; try < 2; try++ {
					r := p.TLS(ctx, net.JoinHostPort(t.ip.String(), "443"), t.host)
					if r.Outcome == probe.OK {
						ok++
					} else if !haveFail {
						haveFail, fail = true, r
					}
				}
				works[ti][ci] = ok == 2
				switch ok {
				case 2:
					cell[ti][ci] = "ok"
				case 1:
					cell[ti][ci] = "1/2"
				default:
					cell[ti][ci] = short(fail.Outcome)
				}
			}()
		}
	}
	wg.Wait()

	tw := tabwriter.NewWriter(o.Out, 0, 0, 2, ' ', 0)
	fmt.Fprint(tw, i18n.T("HEDEF", "TARGET"), "\tIP")
	for _, c := range cols {
		fmt.Fprint(tw, "\t", c.name)
	}
	fmt.Fprintln(tw)
	for ti, t := range targets {
		fmt.Fprintf(tw, "%s\t%s", t.host, t.ip)
		for ci := range cols {
			fmt.Fprint(tw, "\t", cell[ti][ci])
		}
		fmt.Fprintln(tw)
	}
	tw.Flush()
	fmt.Fprintln(o.Out, i18n.T("\nok = iki el sıkışma da geçti · 1/2 = biri geçti · rst = reset · tmo = zaman aşımı · inj = sahte yanıt · cert = sertifika uyuşmadı · ref = reddedildi", "\nok = both handshakes passed · 1/2 = one passed · rst = reset · tmo = timeout · inj = injected reply · cert = certificate mismatch · ref = refused"))

	// Verdict: which columns open every host that direct cannot.
	var blocked []int
	for ti := range targets {
		if !works[ti][0] {
			blocked = append(blocked, ti)
		}
	}
	if len(blocked) == 0 {
		fmt.Fprintln(o.Out, i18n.T("\nSonuç: direkt yol hepsini açıyor; bu ağda engel görünmüyor (ya da bir VPN trafiği sarıyor).", "\nResult: the direct path opens them all; nothing looks blocked on this network (or a VPN wraps the traffic)."))
		return nil
	}
	fmt.Fprintf(o.Out, i18n.T("\nDirekt yolun açamadığı %d hedef var. Hepsini açan teknikler:\n", "\n%d targets do not open directly. Techniques that open all of them:\n"), len(blocked))
	any := false
	for ci := 1; ci < len(cols); ci++ {
		all := true
		for _, ti := range blocked {
			all = all && works[ti][ci]
		}
		if all {
			fmt.Fprintf(o.Out, "  ✓ %s\n", cols[ci].name)
			any = true
		}
	}
	if !any {
		fmt.Fprintln(o.Out, i18n.T("  (hiçbiri tek başına hepsini açmadı; tabloya bakın)", "  (none opens all of them alone; see the table)"))
	}
	return nil
}

func short(o probe.Outcome) string {
	switch o {
	case probe.Reset:
		return "rst"
	case probe.Timeout:
		return "tmo"
	case probe.Refused:
		return "ref"
	case probe.Injected:
		return "inj"
	case probe.Alert:
		return "alrt"
	case probe.CertMismatch:
		return "cert"
	}
	return "err"
}
