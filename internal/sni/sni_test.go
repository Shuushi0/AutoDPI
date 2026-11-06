package sni

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// clientHello captures the first flight crypto/tls would send for name.
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	go func() {
		_ = tls.Client(c1, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	}()
	buf := make([]byte, 8192)
	n, err := c2.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	return buf[:n]
}

func TestParse(t *testing.T) {
	hello := clientHello(t, "Gateway.Discord.GG")
	got, err := Parse(hello)
	if err != nil || got != "gateway.discord.gg" {
		t.Fatalf("Parse = %q, %v", got, err)
	}
}

func TestParseNoSNI(t *testing.T) {
	hello := clientHello(t, "")
	if _, err := Parse(hello); !errors.Is(err, ErrNoSNI) {
		t.Fatalf("want ErrNoSNI, got %v", err)
	}
}

func TestParseNotTLS(t *testing.T) {
	if _, err := Parse([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); !errors.Is(err, ErrNotTLS) {
		t.Fatalf("want ErrNotTLS, got %v", err)
	}
}

func TestParseNeverPanicsOnPrefixes(t *testing.T) {
	hello := clientHello(t, "example.org")
	for i := 0; i <= len(hello); i++ {
		_, _ = Parse(hello[:i])
	}
	// Corrupt every byte once: must not panic either.
	for i := range hello {
		b := append([]byte(nil), hello...)
		b[i] ^= 0xff
		_, _ = Parse(b)
	}
}

func TestReadFirstFlightFragmented(t *testing.T) {
	hello := clientHello(t, "example.org")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		for _, part := range [][]byte{hello[:1], hello[1:7], hello[7:40], hello[40:]} {
			_, _ = c1.Write(part)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	got, isTLS, err := ReadFirstFlight(c2, time.Second)
	if err != nil || !isTLS || string(got) != string(hello) {
		t.Fatalf("isTLS=%v err=%v len(got)=%d want %d", isTLS, err, len(got), len(hello))
	}
}

func TestReadFirstFlightNonTLS(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _, _ = c1.Write([]byte("GET /")) }()
	got, isTLS, err := ReadFirstFlight(c2, time.Second)
	// The first byte already proves it is not TLS; whatever arrived with it must
	// be handed back untouched.
	if err != nil || isTLS || len(got) == 0 || got[0] != 'G' {
		t.Fatalf("isTLS=%v err=%v got=%q", isTLS, err, got)
	}
}

func TestReadFirstFlightTimeout(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	got, isTLS, err := ReadFirstFlight(c2, 30*time.Millisecond)
	if err == nil || isTLS || len(got) != 0 {
		t.Fatalf("want timeout, got isTLS=%v err=%v got=%q", isTLS, err, got)
	}
}

// helloWithName builds a minimal ClientHello whose server_name is name, raw
// bytes and all (crypto/tls would refuse to send most of these).
func helloWithName(name []byte) []byte {
	u16 := func(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
	sniData := append(append([]byte{0}, u16(len(name))...), name...) // host_name
	ext := append(append([]byte{0, 0}, u16(len(sniData)+2)...), append(u16(len(sniData)), sniData...)...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)              // random
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)        // session_id, cipher_suites, compression
	body = append(append(body, u16(len(ext))...), ext...) // extensions
	hs := append([]byte{0x01, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append(append([]byte{0x16, 0x03, 0x01}, u16(len(hs))...), hs...)
}

// A server_name is an ASCII host name (RFC 6066). Other bytes are not
// lower-cased into something new, and control bytes (terminal escapes) never
// reach the journal or `autodpi log`.
func TestParseRejectsNonHostBytes(t *testing.T) {
	if got, err := Parse(helloWithName([]byte("Ok.Example.NET"))); err != nil || got != "ok.example.net" {
		t.Fatalf("plain name: %q %v", got, err)
	}
	for _, name := range []string{"\xe2\xab", "caf\xc3\xa9.example", "a\x1b]0;pwned\x07.example", "a b.example", "a\x00.example"} {
		if got, err := Parse(helloWithName([]byte(name))); err == nil {
			t.Errorf("Parse accepted %q as %q", name, got)
		}
	}
}

// A ClientHello may be sent as several handshake records; the first flight
// holds all of them, the name is found whichever record it is in, and bytes
// after the hello stay unread.
func TestMultiRecordClientHello(t *testing.T) {
	h := hello("split.example.org")
	for _, at := range []int{1, 3, 4, 20, 100, len(h) - 6} {
		body := h[5:]
		mk := func(b []byte) []byte { return append([]byte{0x16, 3, 1, byte(len(b) >> 8), byte(len(b))}, b...) }
		two := append(mk(body[:at]), mk(body[at:])...)
		if got, err := Parse(two); err != nil || got != "split.example.org" {
			t.Fatalf("split at %d: Parse = %q, %v", at, got, err)
		}
		extra := []byte("EXTRA")
		s := &scripted{chunks: [][]byte{append(append([]byte(nil), two...), extra...)}}
		got, isTLS, err := ReadFirstFlight(s, time.Second)
		if err != nil || !isTLS || !bytes.Equal(got, two) {
			t.Fatalf("split at %d: ReadFirstFlight = %d bytes, %v, %v (want %d)", at, len(got), isTLS, err, len(two))
		}
		if len(s.chunks) != 1 || !bytes.Equal(s.chunks[0], extra) {
			t.Fatalf("split at %d: over-read", at)
		}
	}
}

// A hello larger than MaxFlight is forwarded blind rather than buffered.
func TestHugeHandshakeIsNotBuffered(t *testing.T) {
	first := []byte{0x16, 3, 1, 0, 8, 0x01, 0xff, 0xff, 0xff, 1, 2, 3, 4}
	got, isTLS, err := ReadFirstFlight(&scripted{chunks: [][]byte{first}}, time.Second)
	if isTLS || err != nil || len(got) != len(first) {
		t.Fatalf("got %d bytes, isTLS=%v, err=%v", len(got), isTLS, err)
	}
}
