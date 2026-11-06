package netx

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDoH answers the JSON dialect. mode picks the behaviour; hits counts requests.
type fakeDoH struct {
	*httptest.Server
	hits atomic.Int32
}

func newFakeDoH(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *fakeDoH {
	t.Helper()
	f := &fakeDoH{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func answerA(ip string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cdn-cgi/trace") {
			fmt.Fprintf(w, "fl=1\nip=%s\n", ip)
			return
		}
		fmt.Fprintf(w, `{"Status":0,"Answer":[{"type":1,"data":%q}]}`, ip)
	}
}

// stall holds the request until the client gives up (or the server closes).
func stall(w http.ResponseWriter, r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(5 * time.Second):
	}
}

func rcode(code int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintf(w, `{"Status":%d}`, code) }
}

func client(attempt time.Duration, servers ...*fakeDoH) *DoH {
	d := &DoH{Client: &http.Client{}, Attempt: attempt}
	for _, s := range servers {
		d.Bases = append(d.Bases, s.URL)
	}
	return d
}

func TestDoHFailsOverWhenFirstServerStalls(t *testing.T) {
	a, b := newFakeDoH(t, stall), newFakeDoH(t, answerA("192.0.2.1"))
	d := client(150*time.Millisecond, a, b)
	start := time.Now()
	ips, err := d.LookupIPv4(context.Background(), "example.com")
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.1" {
		t.Fatalf("lookup = %v, %v", ips, err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("failover took %v", el)
	}
	if a.hits.Load() != 1 || b.hits.Load() != 1 {
		t.Fatalf("hits a=%d b=%d", a.hits.Load(), b.hits.Load())
	}
}

func TestDoHRemembersTheServerThatAnswered(t *testing.T) {
	a, b := newFakeDoH(t, stall), newFakeDoH(t, answerA("192.0.2.1"))
	d := client(150*time.Millisecond, a, b)
	for i := 0; i < 4; i++ {
		if _, err := d.LookupIPv4(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	// The stalled server paid one timeout; later queries start at the good one.
	if a.hits.Load() != 1 || b.hits.Load() != 4 {
		t.Fatalf("stalled server asked %d times, good one %d (want 1 and 4)", a.hits.Load(), b.hits.Load())
	}
	// When the preferred one fails, it is demoted again and the other tried.
	b.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	a.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answerA("192.0.2.9")(w, r) })
	ips, err := d.LookupIPv4(context.Background(), "example.com")
	if err != nil || ips[0].String() != "192.0.2.9" {
		t.Fatalf("after recovery: %v, %v", ips, err)
	}
}

func TestDoHFailsOverOnHTTPErrorAndServfail(t *testing.T) {
	for name, bad := range map[string]func(http.ResponseWriter, *http.Request){
		"http 502": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(502) },
		"servfail": rcode(2),
		"refused":  rcode(5),
		"garbage":  func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "<html>") },
	} {
		a, b := newFakeDoH(t, bad), newFakeDoH(t, answerA("192.0.2.2"))
		d := client(time.Second, a, b)
		ips, err := d.LookupIPv4(context.Background(), "example.com")
		if err != nil || ips[0].String() != "192.0.2.2" {
			t.Errorf("%s: %v, %v", name, ips, err)
		}
	}
}

func TestDoHNXDOMAINIsFinal(t *testing.T) {
	a, b := newFakeDoH(t, rcode(3)), newFakeDoH(t, answerA("192.0.2.3"))
	d := client(time.Second, a, b)
	if _, err := d.LookupIPv4(context.Background(), "nope.invalid"); err == nil || !strings.Contains(err.Error(), "rcode 3") {
		t.Fatalf("err = %v", err)
	}
	if b.hits.Load() != 0 {
		t.Fatal("NXDOMAIN must not be retried at the other resolver")
	}
}

func TestDoHAllServersFail(t *testing.T) {
	a, b := newFakeDoH(t, stall), newFakeDoH(t, rcode(2))
	d := client(100*time.Millisecond, a, b)
	_, err := d.LookupIPv4(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, s := range []string{strings.TrimPrefix(a.URL, "https://"), strings.TrimPrefix(b.URL, "https://"), "rcode 2"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q does not mention %q", err, s)
		}
	}
}

func TestDoHStopsWhenCallerGivesUp(t *testing.T) {
	a, b := newFakeDoH(t, stall), newFakeDoH(t, answerA("192.0.2.1"))
	d := client(5*time.Second, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := d.LookupIPv4(ctx, "example.com"); err == nil {
		t.Fatal("expected failure")
	}
	if b.hits.Load() != 0 {
		t.Fatal("kept trying after the caller's context ended")
	}
}

func TestDoHTXTAndPublicIPFailOver(t *testing.T) {
	txt := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cdn-cgi/trace") {
			fmt.Fprint(w, "ip=198.51.100.4\n")
			return
		}
		fmt.Fprint(w, `{"Status":0,"Answer":[{"type":16,"data":"\"hello\""}]}`)
	}
	a, b := newFakeDoH(t, stall), newFakeDoH(t, txt)
	d := client(100*time.Millisecond, a, b)
	got, err := d.LookupTXT(context.Background(), "x.example")
	if err != nil || len(got) != 1 || got[0] != "hello" {
		t.Fatalf("txt = %v, %v", got, err)
	}
	ip, err := d.PublicIP(context.Background())
	if err != nil || ip.String() != "198.51.100.4" {
		t.Fatalf("ip = %v, %v", ip, err)
	}
	// And a trace endpoint answering 404 at the first server counts as failure.
	c := newFakeDoH(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })
	d = client(time.Second, c, b)
	if ip, err = d.PublicIP(context.Background()); err != nil || ip.String() != "198.51.100.4" {
		t.Fatalf("ip after 404 = %v, %v", ip, err)
	}
}

func TestDefaultsAndCleanServers(t *testing.T) {
	d := NewDoH(&Dialer{})
	if len(d.Bases) != 2 || d.Bases[0] != "https://1.1.1.1" || d.Bases[1] != "https://1.0.0.1" {
		t.Fatalf("default bases = %v", d.Bases)
	}
	if got := CleanServers([]string{" 9.9.9.9 ", "", "9.9.9.9", "dns.example"}); len(got) != 2 || got[0] != "9.9.9.9" {
		t.Fatalf("CleanServers = %v", got)
	}
	if got := CleanServers([]string{" "}); len(got) != 2 {
		t.Fatalf("blank list must give defaults, got %v", got)
	}
	if _, err := (&DoH{Client: &http.Client{}}).LookupIPv4(context.Background(), "x"); err == nil {
		t.Fatal("no servers must be an error")
	}
}
