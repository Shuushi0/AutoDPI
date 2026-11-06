package sni

import (
	"bytes"
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

type capConn struct {
	net.Conn
	buf     bytes.Buffer
	readSig chan struct{}
	fired   bool
}

func (c *capConn) Write(p []byte) (int, error)        { c.buf.Write(p); return len(p), nil }
func (c *capConn) Close() error                       { return nil }
func (c *capConn) SetDeadline(t time.Time) error      { return nil }
func (c *capConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *capConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *capConn) Read(p []byte) (int, error) {
	if !c.fired {
		c.fired = true
		close(c.readSig)
	}
	return 0, io.EOF
}

func hello(name string) []byte {
	cc := &capConn{readSig: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		_ = tls.Client(cc, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
		close(done)
	}()
	<-done
	return cc.buf.Bytes()
}

func TestArea1_RealClientHellos(t *testing.T) {
	for _, n := range []string{"example.com", "a.b.c.d.example.co.uk", "xn--bcher-kva.example", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + ".com"} {
		h := hello(n)
		got, err := Parse(h)
		if err != nil || got != n {
			t.Errorf("%s: %q %v", n, got, err)
		}
	}
	// no SNI for IP literal
	if _, err := Parse(hello("1.2.3.4")); err != ErrNoSNI {
		t.Errorf("IP literal: %v", err)
	}
	// upper case folded
	if got, _ := Parse(hello("ExAmple.COM")); got != "example.com" {
		t.Errorf("fold: %q", got)
	}
}

// Parse must be total: no panic, no huge allocation, on any truncation/mutation.
func TestArea1_ParseMutationSweep(t *testing.T) {
	h := hello("example.com")
	for n := 0; n <= len(h); n++ {
		Parse(h[:n])
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200000; i++ {
		b := append([]byte(nil), h...)
		for k := 0; k < 1+rng.Intn(4); k++ {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		if rng.Intn(4) == 0 {
			b = b[:rng.Intn(len(b)+1)]
		}
		name, err := Parse(b)
		if err == nil && name == "" {
			t.Fatalf("nil error with empty name: %x", b)
		}
		if err == nil && !hostChars([]byte(name)) {
			t.Fatalf("non-host chars leaked: %q", name)
		}
	}
}

// Extension layout tests built by hand.
func ext(typ int, data []byte) []byte {
	return append([]byte{byte(typ >> 8), byte(typ), byte(len(data) >> 8), byte(len(data))}, data...)
}
func sniExt(entries ...[]byte) []byte {
	var l []byte
	for _, e := range entries {
		l = append(l, e...)
	}
	return ext(0, append([]byte{byte(len(l) >> 8), byte(len(l))}, l...))
}
func entry(typ byte, name string) []byte {
	return append([]byte{typ, byte(len(name) >> 8), byte(len(name))}, name...)
}
func build(exts ...[]byte) []byte {
	var e []byte
	for _, x := range exts {
		e = append(e, x...)
	}
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)             // session id
	body = append(body, 0, 2, 0x13, 1) // suites
	body = append(body, 1, 0)          // compression
	body = append(body, byte(len(e)>>8), byte(len(e)))
	body = append(body, e...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestArea1_ParseLayouts(t *testing.T) {
	cases := []struct {
		name string
		h    []byte
		want string
		err  error
	}{
		{"sni after many exts", build(ext(0x0a, make([]byte, 40)), ext(0x2b, []byte{2, 3, 4}), sniExt(entry(0, "late.example"))), "late.example", nil},
		{"first entry non-hostname", build(sniExt(entry(1, "zzz"), entry(0, "second.example"))), "second.example", nil},
		{"empty host entry then real", build(sniExt(entry(0, ""), entry(0, "real.example"))), "real.example", nil},
		{"two sni exts, first bad (fail closed)", build(sniExt(entry(0, "bad name")), sniExt(entry(0, "ok.example"))), "", ErrNoSNI},
		{"trailing dot", build(sniExt(entry(0, "example.com."))), "example.com.", nil},
		{"control chars", build(sniExt(entry(0, "a\x1b[2Jb"))), "", ErrNoSNI},
		{"utf8", build(sniExt(entry(0, "bücher.example"))), "", ErrNoSNI},
		{"no exts", build(), "", ErrNoSNI},
	}
	for _, c := range cases {
		got, err := Parse(c.h)
		if got != c.want || err != c.err {
			t.Errorf("%s: got %q,%v want %q,%v", c.name, got, err, c.want, c.err)
		}
	}
}

// First record carries only the front of a ClientHello (split across records):
// the SNI is recoverable only if it is early enough.
func TestArea1_ParseSplitAcrossRecords(t *testing.T) {
	h := build(sniExt(entry(0, "early.example")), ext(0x15, make([]byte, 2000)))
	// cut the record after 100 body bytes but keep original handshake length
	body := h[5:]
	first := append([]byte{0x16, 3, 1, 0, 100}, body[:100]...)
	if got, err := Parse(first); err != nil || got != "early.example" {
		t.Errorf("early SNI in first fragment: %q %v", got, err)
	}
	// SNI late: should be ErrTruncated or NoSNI, not a wrong name
	h = build(ext(0x15, make([]byte, 2000)), sniExt(entry(0, "late.example")))
	body = h[5:]
	first = append([]byte{0x16, 3, 1, 0, 100}, body[:100]...)
	if got, err := Parse(first); got != "" || err == nil {
		t.Errorf("late SNI: %q %v", got, err)
	}
}

// ---- ReadFirstFlight ----

type scripted struct {
	net.Conn
	chunks [][]byte
	delay  time.Duration
	err    error
	dl     time.Time
}

func (s *scripted) Read(p []byte) (int, error) {
	if len(s.chunks) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		// block until deadline
		if s.dl.IsZero() {
			select {} // would hang: caller forgot a deadline
		}
		time.Sleep(time.Until(s.dl))
		return 0, timeoutErr{}
	}
	time.Sleep(s.delay)
	c := s.chunks[0]
	n := copy(p, c)
	if n < len(c) {
		s.chunks[0] = c[n:]
	} else {
		s.chunks = s.chunks[1:]
	}
	return n, nil
}
func (s *scripted) SetReadDeadline(t time.Time) error { s.dl = t; return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestArea1_ReadFirstFlightDribble(t *testing.T) {
	h := hello("dribble.example")
	var chunks [][]byte
	for i := range h {
		chunks = append(chunks, h[i:i+1])
	}
	s := &scripted{chunks: chunks}
	got, isTLS, err := ReadFirstFlight(s, time.Second)
	if err != nil || !isTLS || !bytes.Equal(got, h) {
		t.Fatalf("%v %v len %d/%d", err, isTLS, len(got), len(h))
	}
	if !s.dl.IsZero() {
		t.Fatal("read deadline not cleared")
	}
}

func TestArea1_ReadFirstFlightTrailingBytesStayUnread(t *testing.T) {
	h := hello("x.example")
	extra := []byte("EXTRA-APPDATA")
	s := &scripted{chunks: [][]byte{append(append([]byte(nil), h...), extra...)}}
	got, isTLS, err := ReadFirstFlight(s, time.Second)
	if err != nil || !isTLS || !bytes.Equal(got, h) {
		t.Fatalf("%v %v", err, isTLS)
	}
	// reads are bounded by 'total', so the extra stays in the conn
	if len(s.chunks) != 1 || !bytes.Equal(s.chunks[0], extra) {
		t.Fatalf("over-read: left %q", s.chunks)
	}
}

func TestArea1_ReadFirstFlightBoundaries(t *testing.T) {
	mk := func(n int) []byte {
		b := []byte{0x16, 3, 1, byte(n >> 8), byte(n)}
		return append(b, make([]byte, n)...)
	}
	// exactly MaxRecord-5 body: accepted
	rec := mk(MaxRecord - 5)
	got, isTLS, err := ReadFirstFlight(&scripted{chunks: [][]byte{rec}}, time.Second)
	if err != nil || !isTLS || len(got) != MaxRecord {
		t.Errorf("max: %v %v %d", err, isTLS, len(got))
	}
	// one more: refused as TLS, header returned, nothing else consumed
	rec = mk(MaxRecord - 4)
	got, isTLS, err = ReadFirstFlight(&scripted{chunks: [][]byte{rec}}, time.Second)
	if isTLS || len(got) != 5 || err != nil {
		t.Errorf("max+1: %v %v %d", err, isTLS, len(got))
	}
	// zero-length record
	got, isTLS, err = ReadFirstFlight(&scripted{chunks: [][]byte{{0x16, 3, 1, 0, 0}}}, time.Second)
	if err != nil || !isTLS || len(got) != 5 {
		t.Errorf("zero: %v %v %d", err, isTLS, len(got))
	}
	// EOF mid-header / mid-body
	for _, part := range [][]byte{{0x16}, {0x16, 3, 1}, {0x16, 3, 1, 0, 10, 1, 2}} {
		got, isTLS, err = ReadFirstFlight(&scripted{chunks: [][]byte{part}, err: io.EOF}, time.Second)
		if err == nil || !bytes.Equal(got, part) {
			t.Errorf("eof %x: %q %v %v", part, got, isTLS, err)
		}
	}
	// non-TLS first byte
	got, isTLS, _ = ReadFirstFlight(&scripted{chunks: [][]byte{[]byte("GET /")}}, time.Second)
	if isTLS || !bytes.HasPrefix(got, []byte("G")) {
		t.Errorf("http: %q %v", got, isTLS)
	}
	// 0x16 then bad version byte
	got, isTLS, _ = ReadFirstFlight(&scripted{chunks: [][]byte{{0x16, 0x01, 0, 0, 5, 1, 2, 3, 4, 5}}}, time.Second)
	if isTLS || len(got) != 5 {
		t.Errorf("badver: %x %v", got, isTLS)
	}
	// SSLv2-style hello (0x80) is not handled: forwarded as non-TLS
	_, isTLS, _ = ReadFirstFlight(&scripted{chunks: [][]byte{{0x80, 0x2e, 1, 0, 2}}}, time.Second)
	if isTLS {
		t.Errorf("sslv2 treated as TLS")
	}
}

func TestArea1_ReadFirstFlightTimeoutMidRecord(t *testing.T) {
	s := &scripted{chunks: [][]byte{{0x16, 3, 1, 0x01, 0x00, 1, 2, 3}}}
	t0 := time.Now()
	got, isTLS, err := ReadFirstFlight(s, 150*time.Millisecond)
	if err == nil || !isTLS || len(got) != 8 {
		t.Fatalf("%v %v %d", err, isTLS, len(got))
	}
	if time.Since(t0) > time.Second {
		t.Fatal("slow")
	}
	if !s.dl.IsZero() {
		t.Fatal("deadline left set after timeout")
	}
}
