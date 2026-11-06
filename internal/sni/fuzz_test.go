package sni

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// Parse sees whatever a client (or anything that reached port 443) sends
// first. It must never panic, and a name it returns must come from the input.
func FuzzParse(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	// Found by this fuzzer: a 2-byte name cut out of a UTF-8 sequence came back
	// from ToLower as two U+FFFD runes, a name the input never contained.
	f.Add([]byte("\x16\x03000\x010000000000000000000000000000000000000\x00\x00\x00\x0000\x00\x00\x00\v00\x00\x00\x02⫡\xea00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		name, err := Parse(b)
		if err == nil && (name == "" || !bytes.Contains(bytes.ToLower(b), []byte(name))) {
			t.Fatalf("name %q not taken from the input", name)
		}
	})
}

func FuzzReadFirstFlight(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00})
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		c1, c2 := net.Pipe()
		go func() { _, _ = c1.Write(b); c1.Close() }()
		data, isTLS, _ := ReadFirstFlight(c2, 200*time.Millisecond)
		c2.Close()
		if !bytes.HasPrefix(b, data) {
			t.Fatalf("returned bytes %x are not a prefix of the input", data)
		}
		if isTLS && len(data) > MaxFlight {
			t.Fatalf("buffered %d bytes", len(data))
		}
	})
}
