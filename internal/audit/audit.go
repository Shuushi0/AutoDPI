// Package audit looks for what else on the machine decides where names resolve:
// per-domain DNS rules, local DNS servers, hosts entries. Another tool's rules
// can break a site while every check of our own passes, because those checks do
// not ask the system resolver. The findings go to doctor, to the status line
// and to the log, so a report shows them even when the user does not know the
// tool is there.
package audit

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/domain"
	"github.com/Shuushi0/AutoDPI/internal/i18n"
)

type Severity string

const (
	Problem Severity = "problem" // breaks sites: shown on the status line
	Warn    Severity = "warn"    // may break sites: doctor and the log
	Info    Severity = "info"    // context for a report: doctor and the log
)

// Finding is one thing the audit noticed. Code stays the same in every language
// and is what a report is searched for.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`  // one line, short enough for a status line
	Detail   string   `json:"detail"` // what it means and what to do
}

// Policy is a rule sending some names to chosen DNS servers: an NRPT rule on
// Windows, a file in /etc/resolver on macOS.
type Policy struct {
	Names   []string // normalized; "." means every name
	Servers []string
}

// Listener is a process serving DNS on this machine.
type Listener struct {
	Addr    string
	Proto   string
	Process string // empty when it cannot be told
	PID     int
}

type HostsEntry struct{ IP, Name string }

// AdapterDNS is the resolver list of a network adapter.
type AdapterDNS struct {
	Name    string
	Servers []string
}

// Facts is what Collect read. Unreadable sources are named in Errors: "no rules"
// must not be claimed for a registry that could not be opened.
type Facts struct {
	Policies  []Policy
	Listeners []Listener
	Hosts     []HostsEntry
	Adapters  []AdapterDNS
	Errors    []string
}

// loopbackDNSBlocked says the capture cuts a resolver on this machine: on
// Windows sing-tun's strict_route blocks remote port 53 outside the TUN, with no
// exception for loopback.
var loopbackDNSBlocked = runtime.GOOS == "windows"

func isLoopback(addr string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	return err == nil && a.Unmap().IsLoopback()
}

func isWildcard(addr string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	return err == nil && a.Unmap().IsUnspecified()
}

// ownProcess is a process of ours; it is no finding to see them.
func ownProcess(name string) bool {
	switch strings.TrimSuffix(strings.ToLower(name), ".exe") {
	case "autodpi", "sing-box", "ciadpi":
		return true
	}
	return false
}

// sample names up to n names, the shortest first, and how many there are.
func sample(names []string, n int) string {
	s := slices.Clone(names)
	slices.SortFunc(s, func(a, b string) int {
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		return strings.Compare(a, b)
	})
	s = slices.Compact(s)
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:n], ", ") + fmt.Sprintf(" +%d", len(s)-n)
}

func uniqueNames(ps []Policy) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Names...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func listenerNames(ls []Listener) string {
	var out []string
	for _, l := range ls {
		name := l.Process
		if name == "" {
			name = "pid " + strconv.Itoa(l.PID)
		}
		out = append(out, name)
	}
	slices.Sort(out)
	return strings.Join(slices.Compact(out), ", ")
}

// Evaluate turns the facts into findings. watched are the names the user cares
// about on this network: hosts entries for them are not just context.
func Evaluate(f Facts, watched []string) []Finding {
	var out []Finding

	var local, foreign []Listener
	for _, l := range f.Listeners {
		switch {
		case ownProcess(l.Process):
		case isLoopback(l.Addr) || isWildcard(l.Addr):
			local = append(local, l)
		default:
			foreign = append(foreign, l)
		}
	}

	var toLoopback, toOther []Policy
	for _, p := range f.Policies {
		if slices.ContainsFunc(p.Servers, isLoopback) {
			toLoopback = append(toLoopback, p)
		} else {
			toOther = append(toOther, p)
		}
	}

	if names := uniqueNames(toLoopback); len(names) > 0 {
		owner := i18n.T("bu adresi kullanan aracı bulun", "find the tool that uses this address")
		if len(local) > 0 {
			owner = i18n.T("53. portu dinleyen: ", "listening on port 53: ") + listenerNames(local)
		}
		sev := Warn
		title := fmt.Sprintf(i18n.T("%d alan adı başka bir DNS aracına bağlı: %s", "%d names are tied to another DNS tool: %s"), len(names), sample(names, 3))
		detail := i18n.T("Bu adlar için DNS kuralı var, sorgular bilgisayardaki başka bir araca gidiyor (", "A DNS rule sends these names to another tool on this computer (") + owner + "). "
		if loopbackDNSBlocked {
			sev = Problem
			title = fmt.Sprintf(i18n.T("%d alan adı tünel açıkken çözülmez (başka DNS aracı): %s", "%d names do not resolve while the tunnel is up (another DNS tool): %s"), len(names), sample(names, 3))
			detail += i18n.T("Tünel açıkken bu sorgular kesilir ve bu siteler açılmaz. O aracı kapatıp kaldırın; kural kalırsa Remove-DnsClientNrptRule ile silin.",
				"While the tunnel is up these queries are cut and those sites do not open. Close and remove that tool; if the rules stay, delete them with Remove-DnsClientNrptRule.")
		} else {
			detail += i18n.T("Bu adlar AutoDPI'ın DNS'ini kullanmaz.", "These names do not use AutoDPI's DNS.")
		}
		out = append(out, Finding{Code: "dns-rule-loopback", Severity: sev, Title: title, Detail: detail})
	}

	if names := uniqueNames(toOther); len(names) > 0 {
		out = append(out, Finding{Code: "dns-rule-other", Severity: Warn,
			Title:  fmt.Sprintf(i18n.T("%d alan adı için özel DNS kuralı var: %s", "%d names have their own DNS rule: %s"), len(names), sample(names, 3)),
			Detail: i18n.T("Bu adlar AutoDPI'ın DNS'ini kullanmayabilir. Kuralı siz eklemediyseniz bu sitelerde sorun olduğunda önce buna bakın.", "These names may not use AutoDPI's DNS. If you did not add the rule, look here first when those sites fail.")})
	}

	for _, a := range f.Adapters {
		if !slices.ContainsFunc(a.Servers, isLoopback) {
			continue
		}
		sev, what := Warn, i18n.T("Başka bir araç DNS'i üzerine almış olabilir.", "Another tool may have taken over DNS.")
		if loopbackDNSBlocked {
			sev, what = Problem, i18n.T("Tünel açıkken bu DNS sunucusuna gidilemez. Bu ayarı yapan aracı kapatın veya ağ ayarını otomatiğe alın.", "This DNS server cannot be reached while the tunnel is up. Close the tool that set it, or set the adapter's DNS back to automatic.")
		}
		out = append(out, Finding{Code: "adapter-dns-loopback", Severity: sev,
			Title:  fmt.Sprintf(i18n.T("%s bağdaştırıcısının DNS'i bu bilgisayarı gösteriyor (%s)", "The DNS of adapter %s points at this computer (%s)"), a.Name, strings.Join(a.Servers, ", ")),
			Detail: what})
	}

	if len(local) > 0 {
		out = append(out, Finding{Code: "dns-listener", Severity: Warn,
			Title:  i18n.T("Bu bilgisayarda başka bir DNS sunucusu çalışıyor: ", "Another DNS server runs on this computer: ") + listenerNames(local),
			Detail: i18n.T("DNS veya engel aşma aracıysa AutoDPI ile çakışabilir.", "If it is a DNS or unblocking tool, it can conflict with AutoDPI.")})
	}
	if len(foreign) > 0 {
		out = append(out, Finding{Code: "dns-listener-lan", Severity: Info,
			Title:  i18n.T("Yerel ağa DNS sunan süreç: ", "A process serves DNS to the local network: ") + listenerNames(foreign),
			Detail: i18n.T("Çoğunlukla Windows internet paylaşımı veya sanal makine ağıdır.", "Usually Windows internet sharing or a virtual machine network.")})
	}

	var pinned, other []string
	for _, h := range f.Hosts {
		if slices.ContainsFunc(watched, func(w string) bool { return domain.Covers(w, h.Name) }) {
			pinned = append(pinned, h.Name+" → "+h.IP)
		} else {
			other = append(other, h.Name)
		}
	}
	if len(pinned) > 0 {
		out = append(out, Finding{Code: "hosts-watched", Severity: Warn,
			Title:  i18n.T("hosts dosyası listedeki adları sabitliyor: ", "The hosts file pins names on the list: ") + sample(pinned, 3),
			Detail: i18n.T("Bu adlar DNS'e sorulmaz. Adres eskiyse site açılmaz.", "These names never reach DNS. If the address is stale, the site does not open.")})
	}
	if len(other) > 0 {
		out = append(out, Finding{Code: "hosts-entries", Severity: Info,
			Title:  fmt.Sprintf(i18n.T("hosts dosyasında %d kayıt var: %s", "The hosts file has %d entries: %s"), len(other), sample(other, 3)),
			Detail: i18n.T("Bu adlar DNS'e sorulmaz.", "These names never reach DNS.")})
	}

	for _, e := range f.Errors {
		out = append(out, Finding{Code: "audit-error", Severity: Info,
			Title:  i18n.T("Denetimin bir kısmı okunamadı: ", "Part of the audit could not be read: ") + e,
			Detail: i18n.T("Bu kaynak için sonuç yok; temiz sayılmamalı.", "There is no result for this source; it must not be taken as clean.")})
	}
	return out
}

// Lookup resolves a name to addresses.
type Lookup func(ctx context.Context, name string) ([]netip.Addr, error)

// SystemLookup asks the system resolver, the path applications use. On Windows
// that is the DNS Client service, with its rules; nslookup and our own DoH go
// around it, which is why they are no evidence of what a browser gets.
func SystemLookup(ctx context.Context, name string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
}

const (
	probeControl  = "example.com"
	maxProbeNames = 12
	probeTimeout  = 6 * time.Second
)

// ProbeNames picks what to resolve: the names rules or hosts entries touch and
// the names on the list, and one name nothing should touch.
func ProbeNames(f Facts, watched []string) []string {
	out := []string{probeControl}
	add := func(n string) {
		n = strings.TrimPrefix(n, "*.")
		if n == "" || n == "." || len(out) >= maxProbeNames || slices.Contains(out, n) || !strings.Contains(n, ".") {
			return
		}
		out = append(out, n)
	}
	names := uniqueNames(f.Policies)
	// A rule's namespace can be a very long host: the short ones are the sites.
	slices.SortStableFunc(names, func(a, b string) int { return len(a) - len(b) })
	for i, n := range names {
		if i >= maxProbeNames/2 {
			break
		}
		add(n)
	}
	for _, n := range watched {
		add(n)
	}
	return out
}

// unusable says an answer is a sinkhole: an address no site is at.
func unusable(addrs []netip.Addr) bool {
	if len(addrs) == 0 {
		return true
	}
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsLoopback() && !a.IsUnspecified() {
			return false
		}
	}
	return true
}

// Probe compares the system resolver with DoH, name by name. Only a name DoH
// resolves counts: when neither answers, the network is down or the name does
// not exist, and that is not the system's doing. A name is asked twice before it
// counts, so one slow answer on a bad link raises nothing.
func Probe(ctx context.Context, names []string, system, doh Lookup) []Finding {
	ask := func(l Lookup, name string) ([]netip.Addr, error) {
		c, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		return l(c, name)
	}
	var mu sync.Mutex
	var failed, sinkholed []string
	var wg sync.WaitGroup
	limit := make(chan struct{}, 4)
	for _, name := range names {
		wg.Add(1)
		limit <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-limit }()
			addrs, err := ask(system, name)
			if err == nil && !unusable(addrs) {
				return
			}
			if answer, derr := ask(doh, name); derr != nil || unusable(answer) {
				return
			}
			if addrs, err = ask(system, name); err == nil && !unusable(addrs) {
				return
			}
			if ctx.Err() != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, name)
			} else {
				sinkholed = append(sinkholed, name)
			}
		}()
	}
	wg.Wait()

	var out []Finding
	if len(failed) > 0 {
		out = append(out, Finding{Code: "dns-system-fails", Severity: Problem,
			Title:  i18n.T("Windows/macOS bu adları çözemiyor, siteler açılmaz: ", "The system cannot resolve these names, the sites do not open: ") + sample(failed, 3),
			Detail: i18n.T("Şifreli DNS aynı adları çözüyor; sorun sistemin DNS yolunda. Başka bir DNS aracı, VPN veya güvenlik yazılımına bakın.", "Encrypted DNS resolves the same names, so the fault is on the system's DNS path. Look for another DNS tool, a VPN or security software.")})
	}
	if len(sinkholed) > 0 {
		out = append(out, Finding{Code: "dns-system-sinkhole", Severity: Problem,
			Title:  i18n.T("Sistem bu adlara sahte adres veriyor, siteler açılmaz: ", "The system gives these names a fake address, the sites do not open: ") + sample(sinkholed, 3),
			Detail: i18n.T("Şifreli DNS gerçek adresi veriyor. hosts dosyasına veya bir engelleme aracına bakın.", "Encrypted DNS gives a real address. Look at the hosts file or a blocking tool.")})
	}
	return out
}

// Headline is what the status line shows: the first problem, if any.
func Headline(fs []Finding) string {
	for _, f := range fs {
		if f.Severity == Problem {
			return f.Title
		}
	}
	return ""
}
