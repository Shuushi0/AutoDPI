package singbox_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/singbox"
)

func wgKeyPair(t *testing.T) (private, public string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// The warp engine's WireGuard endpoint carries traffic: a second sing-box on
// loopback plays the WireGuard server, and a request through the endpoint
// Build writes reaches a local web server through it. `sing-box check` only
// proves the endpoint's shape is accepted; sing-box 1.15 rewrote much of
// transport/wireguard, and a tunnel that never completes a handshake, or
// completes it and carries nothing, passes every other test.
func TestWireGuardEndpointCarriesTraffic(t *testing.T) {
	bin := area2Bin(t)
	// The web server listens on a LAN address, not loopback: a loopback
	// destination arriving over the tunnel is the netstack's to refuse, and
	// that would be a test of gVisor, not of the endpoint. Nothing leaves the
	// machine: the address is this host's own.
	ip, ok := lanIPv4()
	if !ok {
		t.Skip("no non-loopback IPv4 address on this machine to serve the test page from")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", ip, err)
	}
	token := fmt.Sprintf("through the tunnel %d", time.Now().UnixNano())
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, token) })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	target := "http://" + ln.Addr().String() + "/"

	aPriv, aPub := wgKeyPair(t)
	bPriv, bPub := wgKeyPair(t)
	dir := t.TempDir()

	// B: the WireGuard server, sending what arrives through the tunnel out
	// direct.
	var wgPort int
	b := startRetrying(t, bin, dir, "server", func() ([]byte, func(*boxProc) bool) {
		wgPort = freeUDPPort(t)
		cfg, _ := json.MarshalIndent(map[string]any{
			"log": map[string]any{"level": "debug", "timestamp": true},
			"endpoints": []any{map[string]any{
				"type": "wireguard", "tag": "wg-server", "address": []string{"10.9.0.1/32"},
				"private_key": bPriv, "listen_port": wgPort, "mtu": 1280,
				"peers": []any{map[string]any{"public_key": aPub, "allowed_ips": []string{"10.9.0.2/32"}}},
			}},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
			"route":     map[string]any{"final": "direct"},
		}, "", "  ")
		return cfg, func(p *boxProc) bool { return strings.Contains(p.logs.String(), "sing-box started") }
	})

	// A: the endpoint exactly as Build writes it for the warp engine, with
	// only the peer pointed at B instead of Cloudflare.
	if err := singbox.WriteRuleSet(dir, "warp", nil); err != nil {
		t.Fatal(err)
	}
	built, err := singbox.Build(singbox.Options{
		Engines:      []singbox.Engine{{Name: "warp", Kind: singbox.WireGuard, Port: 1}},
		ObserverPort: 1, RuleDir: dir, TestPort: 1,
		WireGuard: &singbox.WireGuardProfile{
			PrivateKey: aPriv, PublicKey: bPub, Addresses: []string{"10.9.0.2/32"}, MTU: 1280,
			Endpoint: "engage.cloudflareclient.com", Port: 2408,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(built, &m); err != nil {
		t.Fatal(err)
	}
	eps, _ := m["endpoints"].([]any)
	if len(eps) != 1 {
		t.Fatalf("Build wrote %d endpoints for one warp engine", len(eps))
	}
	ep := eps[0].(map[string]any)
	peer := ep["peers"].([]any)[0].(map[string]any)
	if peer["address"] != "engage.cloudflareclient.com" || peer["port"] != float64(2408) {
		t.Fatalf("the peer is not where this test expects to repoint it: %v", peer)
	}
	var mixedPort int
	startRetrying(t, bin, dir, "client", func() ([]byte, func(*boxProc) bool) {
		mixedPort = freePort(t)
		peer["address"], peer["port"] = "127.0.0.1", wgPort
		cfg, _ := json.MarshalIndent(map[string]any{
			"log":       map[string]any{"level": "debug", "timestamp": true},
			"inbounds":  []any{map[string]any{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": mixedPort}},
			"endpoints": []any{ep},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
			// Everything from the inbound goes to the endpoint; there is no
			// rule that could send it direct.
			"route": map[string]any{"rules": []any{map[string]any{"inbound": []string{"in"}, "outbound": ep["tag"]}}, "final": ep["tag"]},
		}, "", "  ")
		return cfg, answers(mixedPort)
	})

	proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", mixedPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	// The first request may wait out the WireGuard handshake; give it time
	// rather than retrying, so a slow handshake is not hidden.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s through the WireGuard endpoint: %v", target, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != token {
		t.Fatalf("got %q, want %q", body, token)
	}
	// The page alone could have come by another road; B's log says it came
	// out of the tunnel, from A's tunnel address, to the page's address.
	// The log comes through a pipe and can trail the response a little.
	for _, want := range []string{
		"endpoint/wireguard[wg-server]: inbound connection from 10.9.0.2:",
		"endpoint/wireguard[wg-server]: inbound connection to " + ln.Addr().String(),
	} {
		deadline := time.Now().Add(3 * time.Second)
		for !strings.Contains(b.logs.String(), want) {
			if time.Now().After(deadline) {
				t.Fatalf("the page arrived, but the WireGuard server's log has no %q", want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}
