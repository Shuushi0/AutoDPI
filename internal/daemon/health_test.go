package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/config"
	"github.com/Shuushi0/AutoDPI/internal/netx"
	"github.com/Shuushi0/AutoDPI/internal/paths"
	"github.com/Shuushi0/AutoDPI/internal/probe"
)

func quickDoH(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s.URL
}

func okDNS(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, `{"Status":0,"Answer":[{"type":1,"data":"192.0.2.1"}]}`)
}

func stallDNS(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }

func healthDaemon(bases ...string) *Daemon {
	d := New(config.Default(), paths.Set{}, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.doh = &netx.DoH{Client: &http.Client{}, Bases: bases, Attempt: 150 * time.Millisecond}
	d.obsPort = 1 // nothing listens: the observer self-test fails after DoH passed
	return d
}

// One stalled resolver must not fail the health check: DoH passes, and the
// check moves on to the observer self-test (which fails here only because
// no observer runs in this test).
func TestHealthyToleratesOneStalledResolver(t *testing.T) {
	d := healthDaemon(quickDoH(t, stallDNS), quickDoH(t, okDNS))
	err := d.healthy(context.Background())
	if err == nil || !strings.Contains(err.Error(), "observer self-test") {
		t.Fatalf("err = %v, want the DoH step to pass and the observer step to be reached", err)
	}
}

func TestHealthyFailsOnlyWhenAllResolversFail(t *testing.T) {
	d := healthDaemon(quickDoH(t, stallDNS), quickDoH(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	err := d.healthy(context.Background())
	if err == nil || !strings.Contains(err.Error(), "DoH (all resolvers)") {
		t.Fatalf("err = %v", err)
	}
}

func selfSigned(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// The TLS probes try both resolver addresses: the first stalling is not a failure.
func TestAnyTLSTriesTheOtherAddress(t *testing.T) {
	cert, pool := selfSigned(t, "one.one.one.one")
	good, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	go func() {
		for {
			c, err := good.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	hole, err := net.Listen("tcp", "127.0.0.1:0") // accepts, never speaks TLS
	if err != nil {
		t.Fatal(err)
	}
	defer hole.Close()
	go func() {
		for {
			c, err := hole.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	p := &probe.Prober{Dial: (&net.Dialer{}).DialContext, Roots: pool, Timeout: 300 * time.Millisecond}
	at := func(addrs ...string) []probeTarget {
		var out []probeTarget
		for _, a := range addrs {
			out = append(out, probeTarget{a, "one.one.one.one"})
		}
		return out
	}

	if r := anyTLS(context.Background(), p, at(hole.Addr().String(), good.Addr().String())); r.Outcome != probe.OK {
		t.Fatalf("first stalls, second works: %v", r)
	}
	if r := anyTLS(context.Background(), p, at(hole.Addr().String(), hole.Addr().String())); r.Outcome == probe.OK {
		t.Fatalf("every target stalls but the probe passed: %v", r)
	}
}

func TestProbeTargetsFollowTheConfiguredResolvers(t *testing.T) {
	got := probeTargetsFor([]string{"9.9.9.9", "2606:4700:4700::1111", "203.0.113.5", "not-an-ip"})
	want := []probeTarget{
		{"9.9.9.9:443", "dns.quad9.net"},
		{"[2606:4700:4700::1111]:443", "one.one.one.one"},
		{"203.0.113.5:443", "203.0.113.5"},
	}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%d: %v, want %v", i, got[i], want[i])
		}
	}
	if d := probeTargetsFor(nil); len(d) != 2 || d[0].addr != "1.1.1.1:443" {
		t.Fatalf("default %v", d)
	}
}
