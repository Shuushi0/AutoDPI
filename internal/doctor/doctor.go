// Package doctor runs the pre-flight checks that explain most "it does nothing"
// reports, without needing the daemon.
package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/audit"
	"github.com/Shuushi0/AutoDPI/internal/embedded"
	"github.com/Shuushi0/AutoDPI/internal/i18n"
	"github.com/Shuushi0/AutoDPI/internal/netx"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/service"
	"github.com/Shuushi0/AutoDPI/internal/singbox"
	"github.com/Shuushi0/AutoDPI/internal/sysx"
)

type Check struct {
	Name   string
	OK     bool
	Detail string
	Info   bool // informational: a "no" is not a failure
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

func Run(p paths.Set) []Check {
	var cs []Check
	add := func(c Check) { cs = append(cs, c) }

	root := sysx.IsRoot()
	add(Check{Name: i18n.T("root yetkisi", "root privileges"), OK: root, Info: true,
		Detail: map[bool]string{true: i18n.T("evet", "yes"), false: i18n.T("hayır (kurulum ve TUN için "+sysx.AdminHint()+" gerekir)", "no (installing and the TUN need "+sysx.AdminHint()+")")}[root]})

	bins, err := embedded.Prepare(embedded.UserDir(p.Bin))
	if err != nil {
		add(Check{Name: i18n.T("yardımcı ikili dosyalar", "helper binaries"), Detail: err.Error()})
	} else {
		src := i18n.T("geliştirme dizininden", "from the development directory")
		if embedded.Embedded() {
			src = i18n.T("binary'nin içinden", "embedded in the binary")
		}
		add(Check{Name: i18n.T("yardımcı ikili dosyalar", "helper binaries"), OK: true, Detail: src})
		if out, err := run(bins.SingBox, "version"); err != nil {
			add(Check{Name: i18n.T("sing-box çalışıyor", "sing-box runs"), Detail: err.Error()})
		} else {
			add(Check{Name: i18n.T("sing-box çalışıyor", "sing-box runs"), OK: true, Detail: firstLine(out)})
		}
		out, _ := run(bins.Ciadpi, "--version")
		add(Check{Name: i18n.T("ciadpi çalışıyor", "ciadpi runs"), OK: out != "", Detail: firstLine(out)})
	}

	if ifc, found := netx.ForeignTunnel(singbox.TunIP); found {
		add(Check{Name: i18n.T("başka tünel (WARP/VPN)", "another tunnel (WARP/VPN)"), Detail: fmt.Sprintf(i18n.T("%s trafiği yakalıyor: servis bekleme modunda kalır, ölçümler anlamsız", "%s captures the traffic: the service stays in standby, measurements mean nothing"), ifc)})
	} else {
		add(Check{Name: i18n.T("başka tünel (WARP/VPN)", "another tunnel (WARP/VPN)"), OK: true, Detail: i18n.T("yok", "none")})
	}
	warp := "CloudflareWARP"
	if runtime.GOOS == "windows" {
		warp = "warp-svc.exe"
	}
	if sysx.ProcessRunning(warp) {
		add(Check{Name: i18n.T("Cloudflare WARP süreci", "Cloudflare WARP process"), OK: true, Info: true, Detail: i18n.T("çalışıyor (bağlıysa yukarıdaki uyarı da çıkar)", "running (if connected, the warning above shows too)")})
	}
	if name, found := sysx.ConflictingTool(); found {
		add(Check{Name: i18n.T("çakışan DPI aracı", "conflicting DPI tool"), Detail: name + i18n.T(" çalışıyor: aynı paketleri değiştiriyor, kapatın (servis o kapanana kadar bekleme modunda kalır)", " is running: it rewrites the same packets, close it (the service stays in standby until it is gone)")})
	} else if runtime.GOOS == "windows" {
		add(Check{Name: i18n.T("çakışan DPI aracı", "conflicting DPI tool"), OK: true, Detail: i18n.T("yok (GoodbyeDPI, zapret)", "none (GoodbyeDPI, zapret)")})
	}

	if ifc, err := netx.Physical(); err != nil {
		add(Check{Name: i18n.T("varsayılan arayüz", "default interface"), Detail: err.Error()})
	} else {
		add(Check{Name: i18n.T("varsayılan arayüz", "default interface"), OK: true, Detail: ifc.Name})
	}

	if state := service.Describe(); state == "" {
		add(Check{Name: service.Kind(), OK: true, Info: true, Detail: i18n.T("kurulu değil (", "not installed (") + service.InstallHint() + ")"})
	} else {
		add(Check{Name: service.Kind(), OK: true, Detail: state})
	}
	if _, err := os.Stat(p.Sock); err != nil {
		add(Check{Name: i18n.T("kontrol soketi", "control socket"), Info: true, Detail: i18n.T("yok (servis çalışmıyor)", "missing (the service is not running)")})
	} else {
		add(Check{Name: i18n.T("kontrol soketi", "control socket"), OK: true, Detail: p.Sock})
	}
	cs = append(cs, auditChecks()...)
	return cs
}

// auditChecks reports what else on the machine decides where names resolve.
func auditChecks() []Check {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	facts := audit.Collect(ctx)
	findings := audit.Evaluate(facts, nil)
	doh := netx.NewDoH(&netx.Dialer{Timeout: 6 * time.Second})
	findings = append(findings, audit.Probe(ctx, audit.ProbeNames(facts, nil), audit.SystemLookup, doh.LookupIPv4)...)

	name := i18n.T("sistem DNS denetimi", "system DNS audit")
	if len(findings) == 0 {
		return []Check{{Name: name, OK: true, Detail: i18n.T("temiz", "clean")}}
	}
	var out []Check
	for _, f := range findings {
		out = append(out, Check{Name: name + " [" + f.Code + "]", Info: f.Severity != audit.Problem, Detail: f.Title + " — " + f.Detail})
	}
	return out
}
