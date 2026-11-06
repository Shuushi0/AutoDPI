package audit

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func codes(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Code)
	}
	return out
}

func find(t *testing.T, fs []Finding, code string) Finding {
	t.Helper()
	for _, f := range fs {
		if f.Code == code {
			return f
		}
	}
	t.Fatalf("no %s in %v", code, codes(fs))
	return Finding{}
}

func withLoopbackBlocked(t *testing.T, v bool) {
	t.Helper()
	old := loopbackDNSBlocked
	loopbackDNSBlocked = v
	t.Cleanup(func() { loopbackDNSBlocked = old })
}

// The machine this audit exists for: rules of another tool send Discord and
// Roblox to a DNS server on loopback, and the tunnel cuts that port.
func TestRulesToLoopbackAreAProblemWhereTheTunnelCutsThem(t *testing.T) {
	withLoopbackBlocked(t, true)
	fs := Evaluate(Facts{
		Policies: []Policy{
			{Names: normalizeNames([]string{"discord.com", ".discord.com"}), Servers: []string{"127.0.0.1"}},
			{Names: normalizeNames([]string{"roblox.com", ".roblox.com"}), Servers: []string{"127.0.0.1"}},
		},
		Listeners: []Listener{{Addr: "127.0.0.1", Proto: "UDP", PID: 40, Process: "someproxy.exe"}},
	}, nil)
	f := find(t, fs, "dns-rule-loopback")
	if f.Severity != Problem {
		t.Fatalf("severity %s", f.Severity)
	}
	for _, want := range []string{"2 ", "discord.com", "roblox.com"} {
		if !strings.Contains(f.Title, want) {
			t.Errorf("title %q lacks %q", f.Title, want)
		}
	}
	if !strings.Contains(f.Detail, "someproxy.exe") {
		t.Errorf("detail does not name the tool: %q", f.Detail)
	}
	if Headline(fs) != f.Title {
		t.Errorf("headline %q", Headline(fs))
	}
}

func TestRulesToLoopbackAreOnlyAWarningWhereTheyStillWork(t *testing.T) {
	withLoopbackBlocked(t, false)
	fs := Evaluate(Facts{Policies: []Policy{{Names: []string{"a.test"}, Servers: []string{"::1"}}}}, nil)
	if f := find(t, fs, "dns-rule-loopback"); f.Severity != Warn {
		t.Fatalf("severity %s", f.Severity)
	}
	if Headline(fs) != "" {
		t.Fatalf("a warning reached the status line: %q", Headline(fs))
	}
}

func TestRulesToOtherServersAreAWarning(t *testing.T) {
	fs := Evaluate(Facts{Policies: []Policy{{Names: []string{"corp.test"}, Servers: []string{"10.0.0.2"}}}}, nil)
	if f := find(t, fs, "dns-rule-other"); f.Severity != Warn {
		t.Fatalf("severity %s", f.Severity)
	}
}

func TestListeners(t *testing.T) {
	fs := Evaluate(Facts{Listeners: []Listener{
		{Addr: "127.0.0.1", PID: 1, Process: "sing-box.exe"},
		{Addr: "0.0.0.0", PID: 2, Process: "tool.exe"},
		{Addr: "192.168.137.1", PID: 3, Process: "svchost.exe"},
	}}, nil)
	if f := find(t, fs, "dns-listener"); !strings.Contains(f.Title, "tool.exe") || strings.Contains(f.Title, "sing-box") {
		t.Errorf("local listener: %q", f.Title)
	}
	if f := find(t, fs, "dns-listener-lan"); f.Severity != Info || !strings.Contains(f.Title, "svchost.exe") {
		t.Errorf("lan listener: %+v", f)
	}
}

func TestAdapterDNSOnLoopback(t *testing.T) {
	withLoopbackBlocked(t, true)
	fs := Evaluate(Facts{Adapters: []AdapterDNS{
		{Name: "Wi-Fi", Servers: []string{"127.0.0.1"}},
		{Name: "tun0", Servers: []string{"172.19.0.2"}},
	}}, nil)
	if f := find(t, fs, "adapter-dns-loopback"); f.Severity != Problem || !strings.Contains(f.Title, "Wi-Fi") {
		t.Errorf("%+v", f)
	}
	if n := len(fs); n != 1 {
		t.Errorf("%d findings: %v", n, codes(fs))
	}
}

func TestHostsEntriesCountMoreForNamesOnTheList(t *testing.T) {
	fs := Evaluate(Facts{Hosts: []HostsEntry{
		{IP: "0.0.0.0", Name: "cdn.listed.test"},
		{IP: "10.0.0.5", Name: "nas.local.test"},
	}}, []string{"listed.test"})
	if f := find(t, fs, "hosts-watched"); f.Severity != Warn || !strings.Contains(f.Title, "cdn.listed.test") {
		t.Errorf("%+v", f)
	}
	if f := find(t, fs, "hosts-entries"); f.Severity != Info || strings.Contains(f.Title, "cdn.listed.test") {
		t.Errorf("%+v", f)
	}
}

func TestNothingFoundIsNoFinding(t *testing.T) {
	if fs := Evaluate(Facts{Adapters: []AdapterDNS{{Name: "Wi-Fi", Servers: []string{"10.1.1.1"}}}}, nil); len(fs) != 0 {
		t.Fatalf("%v", codes(fs))
	}
}

func TestAnUnreadableSourceIsReportedNotHidden(t *testing.T) {
	f := find(t, Evaluate(Facts{Errors: []string{"NRPT: denied"}}, nil), "audit-error")
	if !strings.Contains(f.Title, "denied") {
		t.Errorf("%+v", f)
	}
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func lookups(m map[string]func() ([]netip.Addr, error)) Lookup {
	return func(_ context.Context, name string) ([]netip.Addr, error) {
		if f, ok := m[name]; ok {
			return f()
		}
		return addrs("93.184.216.34"), nil
	}
}

func fail() ([]netip.Addr, error) { return nil, errors.New("timeout") }

func TestProbeFlagsANameOnlyTheSystemCannotResolve(t *testing.T) {
	sys := lookups(map[string]func() ([]netip.Addr, error){"blocked.test": fail})
	fs := Probe(context.Background(), []string{"ok.test", "blocked.test"}, sys, lookups(nil))
	f := find(t, fs, "dns-system-fails")
	if f.Severity != Problem || !strings.Contains(f.Title, "blocked.test") || strings.Contains(f.Title, "ok.test") {
		t.Errorf("%+v", f)
	}
}

func TestProbeFlagsASinkhole(t *testing.T) {
	sys := lookups(map[string]func() ([]netip.Addr, error){"sunk.test": func() ([]netip.Addr, error) { return addrs("0.0.0.0"), nil }})
	f := find(t, Probe(context.Background(), []string{"sunk.test"}, sys, lookups(nil)), "dns-system-sinkhole")
	if !strings.Contains(f.Title, "sunk.test") {
		t.Errorf("%+v", f)
	}
}

// With the network down neither path answers: that is no fault of the system.
func TestProbeIsQuietWhenDoHFailsToo(t *testing.T) {
	sys := lookups(map[string]func() ([]netip.Addr, error){"a.test": fail})
	doh := lookups(map[string]func() ([]netip.Addr, error){"a.test": fail})
	if fs := Probe(context.Background(), []string{"a.test"}, sys, doh); len(fs) != 0 {
		t.Fatalf("%v", codes(fs))
	}
}

func TestProbeForgivesOneSlowAnswer(t *testing.T) {
	var n atomic.Int32
	sys := lookups(map[string]func() ([]netip.Addr, error){"slow.test": func() ([]netip.Addr, error) {
		if n.Add(1) == 1 {
			return fail()
		}
		return addrs("93.184.216.34"), nil
	}})
	if fs := Probe(context.Background(), []string{"slow.test"}, sys, lookups(nil)); len(fs) != 0 {
		t.Fatalf("%v", codes(fs))
	}
}

func TestProbeNames(t *testing.T) {
	f := Facts{Policies: []Policy{{Names: []string{".", "very-long-namespace.storage.example.test", "x.test"}}}}
	got := ProbeNames(f, []string{"listed.test", "x.test", "single"})
	for _, want := range []string{probeControl, "x.test", "listed.test"} {
		if !slices.Contains(got, want) {
			t.Errorf("%v lacks %s", got, want)
		}
	}
	for _, not := range []string{".", "single"} {
		if slices.Contains(got, not) {
			t.Errorf("%v has %s", got, not)
		}
	}
	if len(slices.Compact(slices.Sorted(slices.Values(got)))) != len(got) {
		t.Errorf("duplicate: %v", got)
	}
	var many []string
	for _, c := range "abcdefghijklmnopqrstuvwxyz" {
		many = append(many, string(c)+".test")
	}
	if n := len(ProbeNames(Facts{}, many)); n != maxProbeNames {
		t.Errorf("%d names", n)
	}
}

func TestParseHosts(t *testing.T) {
	got := parseHosts("# comment\n127.0.0.1 localhost\n::1 localhost\n10.0.0.5  nas.test files.test # mine\nnot-an-ip host.test\n")
	want := []HostsEntry{{"10.0.0.5", "nas.test"}, {"10.0.0.5", "files.test"}}
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestNormalizeNames(t *testing.T) {
	got := normalizeNames([]string{".Discord.com", "discord.com", ".", " "})
	if !slices.Equal(got, []string{".", "discord.com"}) {
		t.Fatalf("%v", got)
	}
}

func TestParseNetstat(t *testing.T) {
	text := `
Etkin Bağlantılar

  Proto  Yerel Adres          Yabancı Adres        Durum           PID
  TCP    0.0.0.0:135          0.0.0.0:0            DİNLENİYOR      900
  TCP    127.0.0.1:53         0.0.0.0:0            DİNLENİYOR      40
  TCP    10.0.0.2:51000       1.1.1.1:53           KURULDU         77
  TCP    [::1]:53             [::]:0               DİNLENİYOR      40
  UDP    127.0.0.1:53         *:*                                  41
  UDP    192.168.137.1:53     *:*                                  42
  UDP    [fe80::1%12]:53      *:*                                  43
  UDP    0.0.0.0:5353         *:*                                  44
`
	got := parseNetstat(text, map[uint32]string{40: "tool.exe"})
	want := []Listener{
		{Addr: "127.0.0.1", Proto: "TCP", PID: 40, Process: "tool.exe"},
		{Addr: "::1", Proto: "TCP", PID: 40, Process: "tool.exe"},
		{Addr: "127.0.0.1", Proto: "UDP", PID: 41},
		{Addr: "192.168.137.1", Proto: "UDP", PID: 42},
		{Addr: "fe80::1", Proto: "UDP", PID: 43},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestParseLsof(t *testing.T) {
	got := parseLsof("p100\ncdnsmasq\nf5\nn127.0.0.1:53\nf6\nn*:53\np200\ncclient\nf7\nn10.0.0.2:5000->1.1.1.1:53\n")
	want := []Listener{{Addr: "127.0.0.1", PID: 100, Process: "dnsmasq"}, {Addr: "0.0.0.0", PID: 100, Process: "dnsmasq"}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestParseResolverFile(t *testing.T) {
	got := parseResolverFile("# x\nnameserver 127.0.0.1\nport 5353\nnameserver ::1\n")
	if !slices.Equal(got, []string{"127.0.0.1", "::1"}) {
		t.Fatalf("%v", got)
	}
}

func TestSample(t *testing.T) {
	got := sample([]string{"long-name.test", "a.test", "a.test", "bb.test", "cc.test"}, 2)
	if got != "a.test, bb.test +2" {
		t.Fatalf("%q", got)
	}
}
