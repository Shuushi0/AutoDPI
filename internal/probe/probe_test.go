package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fakenet"
)

func origin(t *testing.T) (addr string, roots *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	t.Cleanup(srv.Close)
	roots = x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv.Listener.Addr().String(), roots
}

func prober(roots *x509.CertPool, timeout time.Duration) *Prober {
	return &Prober{Dial: (&net.Dialer{}).DialContext, Roots: roots, Timeout: timeout}
}

func TestOKAndCertMismatch(t *testing.T) {
	addr, roots := origin(t)
	p := prober(roots, 2*time.Second)
	if r := p.TLS(context.Background(), addr, "example.com"); r.Outcome != OK {
		t.Fatalf("want ok, got %v", r)
	}
	if r := p.TLS(context.Background(), addr, "wrong.test"); r.Outcome != CertMismatch || !r.Outcome.Responded() {
		t.Fatalf("want cert-mismatch, got %v", r)
	}
}

func TestResetAndDrop(t *testing.T) {
	addr, roots := origin(t)
	all := func(string) bool { return true }

	rst, err := fakenet.NewCensor(addr, fakenet.Reset, all)
	if err != nil {
		t.Fatal(err)
	}
	defer rst.Close()
	if r := prober(roots, 2*time.Second).TLS(context.Background(), rst.Addr(), "example.com"); r.Outcome != Reset {
		t.Fatalf("want reset, got %v", r)
	}

	drop, err := fakenet.NewCensor(addr, fakenet.Drop, all)
	if err != nil {
		t.Fatal(err)
	}
	defer drop.Close()
	if r := prober(roots, 300*time.Millisecond).TLS(context.Background(), drop.Addr(), "example.com"); r.Outcome != Timeout {
		t.Fatalf("want timeout, got %v", r)
	}
}

func TestAlertInjectedRefused(t *testing.T) {
	// Server that refuses every ClientHello with a TLS alert.
	cert := httptest.NewUnstartedServer(nil)
	cert.StartTLS()
	defer cert.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:       cert.TLS.Certificates,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, errors.New("no") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.(*tls.Conn).Handshake() }()
		}
	}()
	if r := prober(nil, 2*time.Second).TLS(context.Background(), ln.Addr().String(), "example.com"); r.Outcome != Alert {
		t.Fatalf("want alert, got %v", r)
	}

	// Server that answers plain HTTP to a ClientHello (an injecting middlebox).
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
			}()
		}
	}()
	if r := prober(nil, 2*time.Second).TLS(context.Background(), raw.Addr().String(), "example.com"); r.Outcome != Injected {
		t.Fatalf("want injected, got %v", r)
	}

	// Nothing listening.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()
	if r := prober(nil, 2*time.Second).TLS(context.Background(), addr, "example.com"); r.Outcome != Refused {
		t.Fatalf("want refused, got %v", r)
	}
}
