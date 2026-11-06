// Package socks is a minimal SOCKS5 (CONNECT only, no auth) server handshake
// and client dialer, enough to sit between sing-box, ciadpi and the observer.
package socks

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const (
	ver5       = 5
	cmdConnect = 1

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

// Reply codes.
const (
	RepOK              byte = 0
	RepFailure         byte = 1
	RepNotAllowed      byte = 2
	RepNetUnreachable  byte = 3
	RepHostUnreachable byte = 4
	RepRefused         byte = 5
	RepCmdUnsupported  byte = 7
	RepAtypUnsupported byte = 8
)

type Request struct {
	Host string // domain name or IP literal
	Port int
}

func (r *Request) Addr() string { return net.JoinHostPort(r.Host, strconv.Itoa(r.Port)) }

// IP reports the destination as an address when it is an IP literal.
func (r *Request) IP() (netip.Addr, bool) {
	a, err := netip.ParseAddr(r.Host)
	return a, err == nil
}

// Accept runs the server half of the handshake up to and including the CONNECT
// request. The caller answers with Reply. The returned conn replays any bytes
// the client pipelined behind the request.
func Accept(c net.Conn) (net.Conn, *Request, error) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})

	br := bufio.NewReader(c)
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, nil, err
	}
	if hdr[0] != ver5 {
		return nil, nil, fmt.Errorf("socks: unsupported version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return nil, nil, err
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{ver5, 0xff})
		return nil, nil, errors.New("socks: no acceptable auth method")
	}
	if _, err := c.Write([]byte{ver5, 0}); err != nil {
		return nil, nil, err
	}

	var rq [4]byte
	if _, err := io.ReadFull(br, rq[:]); err != nil {
		return nil, nil, err
	}
	if rq[0] != ver5 {
		return nil, nil, fmt.Errorf("socks: bad request version %d", rq[0])
	}
	bc := &bufConn{Conn: c, r: br}
	if rq[1] != cmdConnect {
		_ = Reply(bc, RepCmdUnsupported)
		return nil, nil, fmt.Errorf("socks: unsupported command %d", rq[1])
	}

	var host string
	switch rq[3] {
	case atypIPv4:
		var a [4]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return nil, nil, err
		}
		host = netip.AddrFrom4(a).String()
	case atypIPv6:
		var a [16]byte
		if _, err := io.ReadFull(br, a[:]); err != nil {
			return nil, nil, err
		}
		host = netip.AddrFrom16(a).String()
	case atypDomain:
		n, err := br.ReadByte()
		if err != nil {
			return nil, nil, err
		}
		name := make([]byte, n)
		if _, err := io.ReadFull(br, name); err != nil {
			return nil, nil, err
		}
		host = string(name)
	default:
		_ = Reply(bc, RepAtypUnsupported)
		return nil, nil, fmt.Errorf("socks: unsupported address type %d", rq[3])
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return nil, nil, err
	}
	return bc, &Request{Host: host, Port: int(pb[0])<<8 | int(pb[1])}, nil
}

// Reply answers a CONNECT request with the given code.
func Reply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{ver5, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Dialer is the subset of net.Dialer that Dial needs.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Dial connects to a SOCKS5 proxy and asks it to CONNECT to host:port. host is
// sent as an address when it parses as an IP, otherwise as a domain.
func Dial(ctx context.Context, d Dialer, proxy, host string, port int) (net.Conn, error) {
	if d == nil {
		d = &net.Dialer{}
	}
	c, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()

	if err := clientHandshake(c, host, port); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func clientHandshake(c net.Conn, host string, port int) error {
	if _, err := c.Write([]byte{ver5, 1, 0}); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return err
	}
	if resp[0] != ver5 || resp[1] != 0 {
		return errors.New("socks: proxy refused no-auth")
	}

	req := []byte{ver5, cmdConnect, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a := ip.As4()
			req = append(req, atypIPv4)
			req = append(req, a[:]...)
		} else {
			a := ip.As16()
			req = append(req, atypIPv6)
			req = append(req, a[:]...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("socks: host name too long")
		}
		req = append(req, atypDomain, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return err
	}

	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return err
	}
	if head[1] != RepOK {
		return &ReplyError{Code: head[1]}
	}
	skip := 0
	switch head[3] {
	case atypIPv4:
		skip = 4 + 2
	case atypIPv6:
		skip = 16 + 2
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return err
		}
		skip = int(n[0]) + 2
	default:
		return fmt.Errorf("socks: bad reply address type %d", head[3])
	}
	_, err := io.CopyN(io.Discard, c, int64(skip))
	return err
}

// ReplyError is returned when the proxy answers a CONNECT with a failure code.
type ReplyError struct{ Code byte }

func (e *ReplyError) Error() string { return fmt.Sprintf("socks: proxy replied %d", e.Code) }
