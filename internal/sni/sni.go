// Package sni extracts the server name from a TLS ClientHello.
package sni

import (
	"errors"
	"net"
	"strings"
	"time"
)

var (
	ErrNotTLS    = errors.New("sni: not a TLS ClientHello")
	ErrTruncated = errors.New("sni: truncated ClientHello")
	ErrNoSNI     = errors.New("sni: no server_name extension")
)

// MaxRecord bounds how much of a first flight we are willing to buffer.
const MaxRecord = 16384 + 2048

// Parse returns the lower-cased server_name carried by a buffer that begins
// with the TLS record holding a ClientHello. The handshake message may span
// several consecutive handshake records (a client or a record-fragmenting hop
// may split it); they are joined before parsing. Trailing bytes are ignored.
func Parse(b []byte) (string, error) {
	if len(b) < 5 || b[0] != 0x16 || b[1] != 0x03 {
		return "", ErrNotTLS
	}
	body := handshakeBytes(b)
	if len(body) < 4 || body[0] != 0x01 {
		return "", ErrNotTLS
	}
	hs := body[4:]
	if n := int(body[1])<<16 | int(body[2])<<8 | int(body[3]); len(hs) > n {
		hs = hs[:n]
	}

	c := cursor{b: hs}
	c.skip(2 + 32)  // legacy_version + random
	c.skip(c.u8())  // session_id
	c.skip(c.u16()) // cipher_suites
	c.skip(c.u8())  // compression_methods
	extLen := c.u16()
	if c.bad {
		return "", ErrTruncated
	}
	ext := cursor{b: c.rest(extLen)}
	for ext.left() >= 4 {
		typ, l := ext.u16(), ext.u16()
		data := ext.take(l)
		if ext.bad {
			return "", ErrTruncated
		}
		if typ != 0 { // server_name
			continue
		}
		list := cursor{b: data}
		list.skip(2) // server_name_list length
		for list.left() >= 3 {
			nameType, n := list.u8(), list.u16()
			name := list.take(n)
			if list.bad {
				return "", ErrTruncated
			}
			if nameType == 0 && len(name) > 0 {
				if !hostChars(name) {
					return "", ErrNoSNI // not a host name (RFC 6066: ASCII); lower-casing would invent one
				}
				return strings.ToLower(string(name)), nil
			}
		}
	}
	return "", ErrNoSNI
}

// handshakeBytes returns the payload of the consecutive handshake records at
// the start of b (a cut-short last record is tolerated). With a single record
// it aliases b.
func handshakeBytes(b []byte) []byte {
	var out []byte
	first := true
	for len(b) >= 5 && b[0] == 0x16 && b[1] == 0x03 {
		n := int(b[3])<<8 | int(b[4])
		body := b[5:]
		if len(body) > n {
			body = body[:n]
		}
		if first {
			out = body[:len(body):len(body)] // appending below must not write into b
		} else {
			out = append(out, body...)
		}
		first = false
		if len(b)-5 < n {
			break
		}
		b = b[5+n:]
	}
	return out
}

const (
	// MaxFlight bounds how many bytes of a multi-record ClientHello are buffered.
	MaxFlight = 64 << 10
	// MaxFlightTime bounds how long a client may take to deliver its first flight
	// however steadily it keeps sending; the wait argument of ReadFirstFlight is
	// the longest it may stay silent.
	MaxFlightTime = 20 * time.Second
)

// ReadFirstFlight reads the client's first flight from c: the TLS record that
// starts a ClientHello and, when the handshake message is longer than that
// record, the records that continue it (up to MaxFlight bytes). The client may
// stay silent for at most wait between reads. For anything that does not look
// like TLS (or is too large to buffer) it returns the bytes read so far with
// isTLS=false so the caller can forward them untouched. Bytes after the
// ClientHello stay unread.
func ReadFirstFlight(c net.Conn, wait time.Duration) (data []byte, isTLS bool, err error) {
	defer c.SetReadDeadline(time.Time{})
	abs := time.Now().Add(MaxFlightTime)
	read := func(p []byte) (int, error) {
		dl := time.Now().Add(wait)
		if dl.After(abs) {
			dl = abs
		}
		_ = c.SetReadDeadline(dl)
		return c.Read(p)
	}
	buf := make([]byte, 0, 2048)
	// fill reads until buf holds upto bytes.
	fill := func(upto int) error {
		if cap(buf) < upto {
			grown := make([]byte, len(buf), upto)
			copy(grown, buf)
			buf = grown
		}
		for len(buf) < upto {
			n, rerr := read(buf[len(buf):upto])
			buf = buf[:len(buf)+n]
			if rerr != nil && len(buf) < upto {
				return rerr
			}
		}
		return nil
	}

	// The first header is judged as it arrives, so a protocol that is not TLS
	// is recognised from its first byte.
	for len(buf) < 5 {
		n, rerr := read(buf[len(buf):5])
		buf = buf[:len(buf)+n]
		if len(buf) > 0 && buf[0] != 0x16 {
			return buf, false, nil
		}
		if rerr != nil && len(buf) < 5 {
			return buf, false, rerr
		}
	}
	if buf[1] != 0x03 {
		return buf, false, nil
	}

	var hdr [4]byte // the first bytes of the handshake message: type and length
	got, hsLen := 0, -1
	for pos := 0; ; {
		n := int(buf[pos+3])<<8 | int(buf[pos+4])
		if 5+n > MaxRecord || len(buf)+n > MaxFlight {
			return buf, false, nil
		}
		if err := fill(pos + 5 + n); err != nil {
			return buf, true, err
		}
		body := buf[pos+5 : pos+5+n]
		if pos == 0 && (n == 0 || body[0] != 0x01) {
			return buf, true, nil // not a ClientHello: the first record is all there is
		}
		for _, x := range body {
			if got < len(hdr) {
				hdr[got] = x
			}
			if got++; got == len(hdr) {
				hsLen = 4 + int(hdr[1])<<16 + int(hdr[2])<<8 + int(hdr[3])
			}
		}
		if hsLen > MaxFlight {
			return buf, false, nil
		}
		if hsLen >= 0 && got >= hsLen {
			return buf, true, nil
		}
		// The ClientHello continues in the next record. A client that stops
		// or dies at a record boundary leaves what it sent to be forwarded as is.
		pos += 5 + n
		if err := fill(pos + 5); err != nil {
			return buf, true, nil
		}
		if buf[pos] != 0x16 || buf[pos+1] != 0x03 {
			return buf, true, nil // not a continuation; the server will judge it
		}
	}
}

// hostChars reports whether b is printable ASCII without spaces, which every
// real server_name is. Anything else (invalid UTF-8, control bytes) would come
// back mangled from ToLower and could put terminal escapes into the journal.
func hostChars(b []byte) bool {
	for _, c := range b {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

type cursor struct {
	b   []byte
	bad bool
}

func (c *cursor) left() int { return len(c.b) }

func (c *cursor) take(n int) []byte {
	if n < 0 || n > len(c.b) {
		c.bad = true
		c.b = nil
		return nil
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out
}

// rest returns up to n bytes, tolerating a ClientHello cut short by the first
// record boundary; the SNI usually sits early enough to survive that.
func (c *cursor) rest(n int) []byte {
	if n > len(c.b) {
		n = len(c.b)
	}
	return c.take(n)
}

func (c *cursor) skip(n int) { c.take(n) }

func (c *cursor) u8() int {
	b := c.take(1)
	if len(b) == 0 {
		return 0
	}
	return int(b[0])
}

func (c *cursor) u16() int {
	b := c.take(2)
	if len(b) == 0 {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}
