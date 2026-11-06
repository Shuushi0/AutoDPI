package socks

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// memConn serves a fixed byte stream and swallows writes.
type memConn struct{ r *bytes.Reader }

func (m memConn) Read(p []byte) (int, error)       { return m.r.Read(p) }
func (m memConn) Write(p []byte) (int, error)      { return len(p), nil }
func (m memConn) Close() error                     { return nil }
func (m memConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (m memConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (m memConn) SetDeadline(time.Time) error      { return nil }
func (m memConn) SetReadDeadline(time.Time) error  { return nil }
func (m memConn) SetWriteDeadline(time.Time) error { return nil }

// Accept parses bytes from any local process; it must fail cleanly, never
// panic, and hand back exactly the bytes pipelined behind the request.
func FuzzAccept(f *testing.F) {
	f.Add([]byte{5, 1, 0, 5, 1, 0, 1, 1, 2, 3, 4, 1, 187, 0x16})
	f.Add([]byte{5, 1, 0, 5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187})
	f.Add([]byte{5, 1, 0, 5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187})
	f.Fuzz(func(t *testing.T, b []byte) {
		bc, req, err := Accept(memConn{bytes.NewReader(b)})
		if err != nil {
			return
		}
		if bc == nil || req == nil || req.Port < 0 || req.Port > 65535 {
			t.Fatalf("bad success: %v %+v", bc, req)
		}
		rest, _ := io.ReadAll(bc)
		if !bytes.HasSuffix(b, rest) {
			t.Fatalf("pipelined bytes %x are not the tail of the input", rest)
		}
	})
}
