package singbox_test

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Shuushi0/AutoDPI/internal/singbox"
)

// fakeResolver is a DoH endpoint (RFC 8484, TLS) that answers every A query
// with ip, NXDOMAIN for names under ".nx.test.", or never answers (stall).
type fakeResolver struct {
	srv  *httptest.Server
	port int
	hits chan string
}

func newFakeResolver(t *testing.T, ip string, stall bool) *fakeResolver {
	t.Helper()
	f := &fakeResolver{hits: make(chan string, 256)}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		select {
		case f.hits <- q.Name.String():
		default:
		}
		if stall {
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: m.ID, Response: true, RecursionAvailable: true, RCode: dnsmessage.RCodeSuccess},
			Questions: m.Questions,
		}
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
	f.srv.TLS = &tls.Config{}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	_, p, _ := net.SplitHostPort(f.srv.Listener.Addr().String())
	f.port, _ = strconv.Atoi(p)
	return f
}

// Real sing-box with the configuration Build generates for two resolvers, its
// DNS servers repointed at local fake DoH endpoints. One of them stalls
// forever; queries must still be answered at once, from the other.
func TestSingBoxRacesTwoResolvers(t *testing.T) {
	name := "sing-box"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(os.Getenv("AUTODPI_BINDIR"), name)
	if _, err := os.Stat(bin); err != nil {
		bin, _ = filepath.Abs(filepath.Join("..", "..", "bin", name))
		if _, err := os.Stat(bin); err != nil {
			t.Skip("sing-box binary not available")
		}
	}
	for _, tc := range []struct {
		name         string
		stallFirst   bool
		stallSecond  bool
		wantFailures bool
	}{
		{"first stalls", true, false, false},
		{"second stalls", false, true, false},
		{"none stalls", false, false, false},
		{"both stall", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newFakeResolver(t, "192.0.2.10", tc.stallFirst)
			b := newFakeResolver(t, "192.0.2.20", tc.stallSecond)

			dir := t.TempDir()
			if err := singbox.WriteRuleSet(dir, "tlsrec", nil); err != nil {
				t.Fatal(err)
			}
			cfg, err := singbox.Build(singbox.Options{
				Engines:      []singbox.Engine{{Name: "tlsrec", Kind: singbox.TLSRecord, Port: freePort(t)}},
				ObserverPort: freePort(t), RuleDir: dir, TestPort: freePort(t), LogLevel: "debug",
				DoH: []string{"127.0.0.1", "127.0.0.2"},
			})
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(cfg, &m); err != nil {
				t.Fatal(err)
			}
			servers := m["dns"].(map[string]any)["servers"].([]any)
			for i, f := range []*fakeResolver{a, b} {
				s := servers[i].(map[string]any)
				s["server"], s["server_port"] = "127.0.0.1", f.port
				s["tls"] = map[string]any{"insecure": true}
			}
			probe := addDNSProbe(t, m)
			cfg, _ = json.MarshalIndent(m, "", "  ")
			cfgPath := filepath.Join(dir, "config.json")
			if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			cmd := exec.Command(bin, "run", "-c", cfgPath)
			cmd.Stdout, cmd.Stderr = &logs, &logs
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				if t.Failed() {
					t.Logf("sing-box log tail:\n%s", tail(logs.String(), 3000))
				}
			}()
			waitListening(t, fmt.Sprintf("127.0.0.1:%d", tcpPort(m)))

			query := func(host string) (probeAnswer, time.Duration) {
				start := time.Now()
				return probeQuery(t, probe, host, 12*time.Second), time.Since(start)
			}

			if tc.wantFailures {
				ans, _ := query("both-stall.example")
				if len(ans.Answer) != 0 || ans.Message == "" {
					t.Fatalf("with every resolver stalled the query must fail, got %+v", ans)
				}
				return
			}
			for i := 0; i < 3; i++ { // distinct names: no cache help
				ans, took := query(fmt.Sprintf("h%d.example.test", i))
				if len(ans.Answer) != 1 {
					t.Fatalf("query %d: %+v", i, ans)
				}
				if took > 2*time.Second {
					t.Fatalf("query %d took %v despite a healthy resolver", i, took)
				}
				if !tc.stallFirst && !tc.stallSecond {
					continue
				}
				want := "192.0.2.20"
				if tc.stallSecond {
					want = "192.0.2.10"
				}
				if ans.Answer[0] != want {
					t.Fatalf("answer %q, want %q", ans.Answer[0], want)
				}
			}
			// NXDOMAIN from the live resolver is final even though the other stalls.
			ans, took := query("gone.nx.test")
			if ans.Status != int(dnsmessage.RCodeNameError) || took > 2*time.Second {
				t.Fatalf("NXDOMAIN: %+v after %v", ans, took)
			}
		})
	}
}
