package netx

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
)

// Area 2 review tests for netx. TestArea2Bug_* fail today and reproduce a
// confirmed finding.

// config.Validate promises "hosts or IPs" for doh_servers and accepts an IPv6
// literal; the daemon's own DoH client then builds "https://2606:4700:...",
// which is not a valid URL, so every daemon DoH query fails, the health check
// never passes and the daemon never engages.
func TestArea2Bug_IPv6LiteralDoHServerIsAcceptedButUnusable(t *testing.T) {
	c := config.Default()
	c.DoHServers = []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}
	if err := c.Validate(); err != nil {
		t.Skipf("config rejects IPv6 literals now (fine): %v", err)
	}
	d := NewDoHServers(&Dialer{Timeout: time.Second}, c.DoHServers)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := d.LookupIPv4(ctx, "example.com")
	if err != nil && strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("config accepted the IPv6 DoH server but the daemon's client cannot even form the URL: %v", err)
	}
}

// A server given with a port works for the daemon's client only if the URL is
// built as https://host:port; check that at least the request is formed.
func TestArea2_DoHServerWithPortFormsValidURL(t *testing.T) {
	srv := newFakeDoH(t, answerA("192.0.2.7"))
	host := strings.TrimPrefix(srv.URL, "http://")
	d := &DoH{Client: &http.Client{}, Bases: []string{"http://" + host}}
	ips, err := d.LookupIPv4(context.Background(), "example.com")
	if err != nil || len(ips) != 1 {
		t.Fatalf("%v %v", ips, err)
	}
}

func TestArea2_DoHBadBodiesFailOver(t *testing.T) {
	for name, h := range map[string]func(http.ResponseWriter, *http.Request){
		"garbage":    func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "<html>captive portal</html>") },
		"empty":      func(w http.ResponseWriter, _ *http.Request) {},
		"truncated":  func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"Status":0,"Answer":[{"type":1,"da`) },
		"wrong type": func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"Status":"0"}`) },
		"http 500":   func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
		"servfail":   rcode(2),
		"refused":    rcode(5),
	} {
		t.Run(name, func(t *testing.T) {
			bad, good := newFakeDoH(t, h), newFakeDoH(t, answerA("192.0.2.9"))
			d := client(300*time.Millisecond, bad, good)
			ips, err := d.LookupIPv4(context.Background(), "example.com")
			if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.9" {
				t.Fatalf("%v %v", ips, err)
			}
			if good.hits.Load() != 1 {
				t.Fatalf("good server hits %d", good.hits.Load())
			}
		})
	}
}

// SERVFAIL on the first, NXDOMAIN on the second: final answer, and the second is
// remembered as the one to ask first.
func TestArea2_DoHServfailThenNXDOMAIN(t *testing.T) {
	a, b := newFakeDoH(t, rcode(2)), newFakeDoH(t, rcode(3))
	d := client(time.Second, a, b)
	_, err := d.LookupIPv4(context.Background(), "nope.invalid")
	if err == nil || !strings.Contains(err.Error(), "rcode 3") {
		t.Fatalf("err = %v", err)
	}
	_, _ = d.LookupIPv4(context.Background(), "nope.invalid")
	if a.hits.Load() != 1 {
		t.Fatalf("first server asked again (%d) although the second answered finally", a.hits.Load())
	}
}

// NOERROR with no answer (NODATA) is a final answer, not a reason to try the
// next server; the error text must say why.
func TestArea2_DoHNoDataIsFinal(t *testing.T) {
	a, b := newFakeDoH(t, rcode(0)), newFakeDoH(t, answerA("192.0.2.1"))
	d := client(time.Second, a, b)
	_, err := d.LookupIPv4(context.Background(), "v6only.example")
	if err == nil || !strings.Contains(err.Error(), "no A records") {
		t.Fatalf("err = %v", err)
	}
	if b.hits.Load() != 0 {
		t.Fatal("NODATA treated as failure")
	}
}

func TestArea2_DoHExpiredContextReturnsPromptly(t *testing.T) {
	a := newFakeDoH(t, stall)
	d := client(time.Second, a, a)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := d.LookupIPv4(ctx, "example.com"); err == nil {
		t.Fatal("expected an error")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("took %v with a cancelled context", time.Since(start))
	}
	if a.hits.Load() > 1 {
		t.Fatalf("kept trying after cancellation: %d hits", a.hits.Load())
	}
}

// Overall deadline shorter than one attempt: bounded by the deadline.
func TestArea2_DoHDeadlineShorterThanAttempt(t *testing.T) {
	a := newFakeDoH(t, stall)
	d := client(5*time.Second, a)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := d.LookupIPv4(ctx, "example.com")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
}

// All servers stalled: worst case is n*Attempt, errors name every server.
func TestArea2_DoHAllStallBoundedByAttempts(t *testing.T) {
	a, b, c := newFakeDoH(t, stall), newFakeDoH(t, stall), newFakeDoH(t, stall)
	d := client(120*time.Millisecond, a, b, c)
	start := time.Now()
	_, err := d.LookupIPv4(context.Background(), "example.com")
	el := time.Since(start)
	if err == nil || el < 300*time.Millisecond || el > 2*time.Second {
		t.Fatalf("err=%v after %v", err, el)
	}
	for _, s := range []*fakeDoH{a, b, c} {
		if !strings.Contains(err.Error(), strings.TrimPrefix(s.URL, "http://")) {
			t.Fatalf("error does not name %s: %v", s.URL, err)
		}
	}
}

// d.last is shared between goroutines.
func TestArea2_DoHConcurrentFailoverIsRaceFree(t *testing.T) {
	a, b := newFakeDoH(t, stall), newFakeDoH(t, answerA("192.0.2.5"))
	d := client(80*time.Millisecond, a, b)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if _, err := d.LookupIPv4(context.Background(), "example.com"); err != nil {
					t.Error(err)
					return
				}
				if _, err := d.PublicIP(context.Background()); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestArea2_DoHNoServers(t *testing.T) {
	d := &DoH{Client: &http.Client{}}
	if _, err := d.LookupIPv4(context.Background(), "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestArea2_PublicIPParsing(t *testing.T) {
	for name, body := range map[string]string{
		"no ip":     "fl=1\nh=cloudflare\n",
		"bad ip":    "ip=not-an-ip\n",
		"empty":     "",
		"ipv6":      "ip=2606:4700::1\n",
		"with crlf": "ip=203.0.113.9\r\n",
	} {
		srv := newFakeDoH(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) })
		d := client(time.Second, srv)
		ip, err := d.PublicIP(context.Background())
		switch name {
		case "ipv6", "with crlf":
			if err != nil || !ip.IsValid() {
				t.Errorf("%s: %v %v", name, ip, err)
			}
		default:
			if err == nil {
				t.Errorf("%s: accepted %v", name, ip)
			}
		}
	}
}

func TestArea2_ForeignRouteEdgeCases(t *testing.T) {
	cases := []struct {
		name, table, own, want string
	}{
		{"header and blanks only", "Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\n\n", "", ""},
		{"short lines", "default\n1 2\n0/1 x y\n", "", ""},
		{"host route of a foreign utun is not a takeover", "10.8.0.1 10.8.0.1 UH utun5\n100.64/10 link#18 UCS utun5\n", "", ""},
		{"scoped default on a foreign utun", "default link#17 UCSIg utun3 !\n", "own", "utun3"},
		{"default on a physical interface", "default 10.0.0.1 UGScg en0\ndefault link#9 UCSIg en5 !\n", "", ""},
		{"own routes plus foreign split", "1 172.19.0.1 UGSc utun8\n2/7 172.19.0.1 UGSc utun8\n128.0/1 10.9.0.1 UGSc utun9\n", "utun8", "utun9"},
		{"first foreign wins", "0/1 a UGSc utun2\n128.0/1 a UGSc utun3\n", "", "utun2"},
		{"bridge or ppp are not utun", "default 10.0.0.1 UGSc ppp0\n0/1 10.0.0.1 UGSc bridge100\n", "", ""},
		{"own empty makes every utun foreign", "0/1 172.19.0.1 UGSc utun8\n", "", "utun8"},
	}
	for _, c := range cases {
		if got := foreignRoute(c.table, c.own); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestArea2_LoopbackClassification(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:80": true, "127.8.9.1:1": true, "[::1]:443": true, "[::ffff:127.0.0.1]:80": true,
		"10.0.0.1:80": false, "1.1.1.1:443": false, "localhost:80": false, "nonsense": false, "[fe80::1]:80": false,
	} {
		if got := loopback(addr); got != want {
			t.Errorf("loopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

// Read-only look at the real machine: the helpers the daemon relies on return
// something coherent (no process is started that changes anything).
func TestArea2_RealRouteHelpersAreCoherent(t *testing.T) {
	iface, gw, err := DefaultRoute()
	if err != nil {
		t.Skipf("no default route here: %v", err)
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		t.Fatalf("default route names unknown interface %q: %v", iface, err)
	}
	if gw != "" {
		if _, err := netip.ParseAddr(gw); err != nil {
			t.Fatalf("gateway %q is not an address", gw)
		}
	}
	if HasGlobalIPv6("lo0") || HasGlobalIPv6("no-such-if") || HasGlobalIPv6("") {
		t.Fatal("HasGlobalIPv6 true for lo0/unknown")
	}
	if got := InterfaceWithIP("::1"); got == "" {
		t.Log("::1 is on no interface (IPv6 turned off here)")
	}
	// A network reached only through a tunnel (a VPN taking the default
	// route) has no physical interface to bind to: nothing to check then.
	if _, err := Physical(); err != nil {
		t.Skipf("no physical interface here: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if i%3 == 0 {
					InvalidatePhysical()
				}
				if _, err := Physical(); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
