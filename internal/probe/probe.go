// Package probe performs one TLS handshake over a given path and classifies
// what came back, which is how we tell a DPI reset from a dead server.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/socks"
)

type Outcome int

const (
	OK           Outcome = iota // handshake completed, certificate valid for the name
	CertMismatch                // handshake completed but the certificate is wrong (block page, MITM)
	Alert                       // the server answered with a TLS alert: it is reachable
	Reset                       // reset or closed before any server data
	Timeout
	Refused  // connect refused / unreachable
	Injected // non-TLS bytes where a TLS reply belongs
	Other
)

func (o Outcome) String() string {
	return [...]string{"ok", "cert-mismatch", "alert", "reset", "timeout", "refused", "injected", "error"}[o]
}

// Responded reports whether something spoke valid TLS back, i.e. the network
// path to a TLS endpoint exists.
func (o Outcome) Responded() bool { return o == OK || o == Alert || o == CertMismatch }

type Result struct {
	Outcome Outcome
	Err     string
	Took    time.Duration
}

func (r Result) String() string {
	if r.Err == "" {
		return r.Outcome.String()
	}
	return r.Outcome.String() + " (" + r.Err + ")"
}

type Dial func(ctx context.Context, network, addr string) (net.Conn, error)

type Prober struct {
	Dial    Dial
	Roots   *x509.CertPool // nil = system roots
	Timeout time.Duration
}

// ViaSocks returns a Dial that tunnels through a SOCKS5 proxy.
func ViaSocks(proxy string) Dial {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		p, err := net.LookupPort("tcp", port)
		if err != nil {
			return nil, err
		}
		return socks.Dial(ctx, nil, proxy, host, p)
	}
}

// TLS handshakes with addr (ip:port) offering sni.
func (p *Prober) TLS(ctx context.Context, addr, sni string) Result {
	t0 := time.Now()
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 6 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := func(o Outcome, err error) Result {
		r := Result{Outcome: o, Took: time.Since(t0)}
		if err != nil {
			r.Err = err.Error()
		}
		return r
	}

	conn, err := p.Dial(ctx, "tcp", addr)
	if err != nil {
		return res(classify(err), err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	tc := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // verified by hand below so a bad cert is a result, not an error
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return res(classify(err), err)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return res(CertMismatch, errors.New("no certificate"))
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: sni, Roots: p.Roots, Intermediates: inter}); err != nil {
		return res(CertMismatch, err)
	}
	return res(OK, nil)
}

func classify(err error) Outcome {
	// crypto/tls reports a received alert as *net.OpError{Op: "remote error"}.
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "remote error" {
		return Alert
	}
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		return Injected
	}
	var re *socks.ReplyError
	switch {
	case errors.As(err, &re):
		return Refused
	case isAny(err, resetErrs), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return Reset
	case isAny(err, refusedErrs):
		return Refused
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return Timeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout
	}
	return Other
}

// IsReset reports whether err is the peer resetting the connection, read
// from the system's error code (Winsock's on Windows) rather than its message,
// which Windows writes in the system's language.
func IsReset(err error) bool { return isAny(err, resetErrs) }

func isAny(err error, targets []error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}
