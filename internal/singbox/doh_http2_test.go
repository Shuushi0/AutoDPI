package singbox_test

// The DoH path every user takes is HTTP/2: 1.1.1.1 and the other public
// resolvers negotiate it. The other tests' resolvers (httptest without
// EnableHTTP2) speak HTTP/1.1 only, and sing-box then uses its HTTP/1.1
// client, so the code that carries everybody's DNS was never run by a test.
// It is not upstream's either: this build uses a newer Go than sing-box's
// own releases, in which x/net's HTTP/2 client hands over to net/http's. A
// change there that breaks DoH would otherwise pass every guard and take all
// DNS down. Here the resolvers speak HTTP/2, and the test says so.

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/singbox"
	"golang.org/x/net/dns/dnsmessage"
)

type h2Resolver struct {
	srv          *httptest.Server
	port         int
	h2, h1, hits atomic.Int64
}

func newH2Resolver(t *testing.T, ip string, stall bool, http2 bool) *h2Resolver {
	t.Helper()
	f := &h2Resolver{}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if r.ProtoMajor == 2 {
			f.h2.Add(1)
		} else {
			f.h1.Add(1)
		}
		var raw []byte
		if r.Method == http.MethodGet {
			raw, _ = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		} else {
			raw, _ = io.ReadAll(r.Body)
		}
		var m dnsmessage.Message
		if err := m.Unpack(raw); err != nil || len(m.Questions) == 0 {
			w.WriteHeader(400)
			return
		}
		q := m.Questions[0]
		if stall {
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		resp := dnsmessage.Message{Header: dnsmessage.Header{ID: m.ID, Response: true, RecursionAvailable: true}, Questions: m.Questions}
		if strings.HasSuffix(q.Name.String(), ".nx.test.") {
			resp.Header.RCode = dnsmessage.RCodeNameError
		} else if q.Type == dnsmessage.TypeA {
			a := net.ParseIP(ip).To4()
			resp.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1},
				Body:   &dnsmessage.AResource{A: [4]byte(a)},
			}}
		}
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.port = l.Addr().(*net.TCPAddr).Port
	f.srv.Listener.Close()
	f.srv.Listener = l
	f.srv.EnableHTTP2 = http2
	f.srv.TLS = &tls.Config{}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func h2Start(t *testing.T, resolvers []*h2Resolver) (probe int) {
	t.Helper()
	dir := t.TempDir()
	if err := singbox.WriteRuleSet(dir, "tlsrec", nil); err != nil {
		t.Fatal(err)
	}
	doh := []string{}
	for i := range resolvers {
		doh = append(doh, fmt.Sprintf("127.0.0.%d", i+1))
	}
	testPort := freePort(t)
	cfg, err := singbox.Build(singbox.Options{
		Engines:      []singbox.Engine{{Name: "tlsrec", Kind: singbox.TLSRecord, Port: freePort(t)}},
		ObserverPort: freePort(t), RuleDir: dir, TestPort: testPort, LogLevel: "debug", DoH: doh,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(cfg, &m)
	servers := m["dns"].(map[string]any)["servers"].([]any)
	for i, f := range resolvers {
		s := servers[i].(map[string]any)
		s["server"], s["server_port"] = "127.0.0.1", f.port
		s["tls"] = map[string]any{"insecure": true}
	}
	probe = freePort(t)
	m["inbounds"] = append(m["inbounds"].([]any), map[string]any{
		"type": "direct", "tag": "dns-probe", "network": "udp",
		"listen": "127.0.0.1", "listen_port": probe,
		"override_address": "192.0.2.53", "override_port": 53,
	})
	cfg, _ = json.MarshalIndent(m, "", "  ")
	if _, err := startBox(t, area2Bin(t), dir, "h2", cfg, answers(testPort)); err != nil {
		t.Fatal(err)
	}
	return probe
}

// One resolver, speaking h2: answers arrive, and over HTTP/2.
func TestDoHOverHTTP2(t *testing.T) {
	r := newH2Resolver(t, "192.0.2.10", false, true)
	probe := h2Start(t, []*h2Resolver{r})
	for i := 0; i < 20; i++ {
		start := time.Now()
		ans := probeQuery(t, probe, fmt.Sprintf("q%d.example.test", i), 5*time.Second)
		if len(ans.Answer) != 1 || ans.Answer[0] != "192.0.2.10" {
			t.Fatalf("query %d: %+v after %v", i, ans, time.Since(start))
		}
	}
	t.Logf("h2 requests %d, http/1.1 requests %d", r.h2.Load(), r.h1.Load())
	if r.h2.Load() == 0 {
		t.Errorf("no request came over HTTP/2 (h1=%d)", r.h1.Load())
	}
}

// Two resolvers over h2, the first stalls: the race still answers fast.
func TestDoHRaceOverHTTP2(t *testing.T) {
	for _, tc := range []struct {
		name           string
		stallA, stallB bool
	}{{"first stalls", true, false}, {"second stalls", false, true}, {"none", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			a := newH2Resolver(t, "192.0.2.10", tc.stallA, true)
			b := newH2Resolver(t, "192.0.2.20", tc.stallB, true)
			probe := h2Start(t, []*h2Resolver{a, b})
			for i := 0; i < 30; i++ {
				start := time.Now()
				ans := probeQuery(t, probe, fmt.Sprintf("r%d.example.test", i), 12*time.Second)
				took := time.Since(start)
				if len(ans.Answer) != 1 || took > 2*time.Second {
					t.Fatalf("query %d: %+v after %v (h2 a=%d b=%d)", i, ans, took, a.h2.Load(), b.h2.Load())
				}
			}
			ans := probeQuery(t, probe, "gone.nx.test", 5*time.Second)
			if ans.Status != int(dnsmessage.RCodeNameError) {
				t.Fatalf("NXDOMAIN: %+v", ans)
			}
			if a.h2.Load()+b.h2.Load() == 0 || a.h1.Load()+b.h1.Load() != 0 {
				t.Errorf("the queries did not go over HTTP/2: h2 a=%d b=%d, http/1.1 a=%d b=%d", a.h2.Load(), b.h2.Load(), a.h1.Load(), b.h1.Load())
			}
		})
	}
}
