package singbox_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/singbox"
	"github.com/Shuushi0/AutoDPI/internal/sni"
	"github.com/Shuushi0/AutoDPI/internal/socks"
)

// What the tlsrec and tlsfrag engines put on the wire, read by the server
// end. Every other test only sees that sing-box accepts the configuration and
// that a connection opens; a sing-box that stops fragmenting passes them all,
// and AutoDPI then reports success while the DPI box reads the server name as
// before. sing-box 1.15 adds a kernel splice fast path that is skipped only
// while the fragment options are set on the connection: if a release stops
// setting them, this is the only place that notices.

// flight is the first flight one connection to the origin carried.
type flight struct {
	reads   []int    // length of each read: where TCP delivered segment boundaries, roughly
	records [][]byte // the TLS records it came in: header and payload
	hello   []byte   // the handshake message, joined from the records' payloads
	err     error
}

// readFlight reads TLS records until they hold one whole handshake message.
// It does not answer: the client's handshake fails, which it is expected to.
func readFlight(c net.Conn) flight {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	var f flight
	var buf []byte
	tmp := make([]byte, 64<<10)
	for {
		n, err := c.Read(tmp)
		if n > 0 {
			f.reads = append(f.reads, n)
			buf = append(buf, tmp[:n]...)
		}
		for len(buf) >= 5 {
			if buf[0] != 0x16 || buf[1] != 0x03 {
				f.err = fmt.Errorf("record %d is not a handshake record: % x", len(f.records), buf[:5])
				return f
			}
			n := 5 + int(binary.BigEndian.Uint16(buf[3:5]))
			if len(buf) < n {
				break
			}
			f.records = append(f.records, append([]byte(nil), buf[:n]...))
			f.hello = append(f.hello, buf[5:n]...)
			buf = buf[n:]
		}
		if len(f.hello) >= 4 {
			if want := 4 + (int(f.hello[1])<<16 | int(f.hello[2])<<8 | int(f.hello[3])); len(f.hello) >= want {
				if len(f.hello) > want || len(buf) > 0 {
					f.err = fmt.Errorf("%d bytes after the ClientHello in its first flight", len(f.hello)-want+len(buf))
				}
				return f
			}
		}
		if err != nil {
			f.err = fmt.Errorf("after %d bytes in %d records: %w", len(f.hello), len(f.records), err)
			return f
		}
	}
}

// writeRecorder keeps what the TLS client wrote, to compare with what the
// origin got.
type writeRecorder struct {
	net.Conn
	mu sync.Mutex
	b  []byte
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.b = append(w.b, p...)
	w.mu.Unlock()
	return w.Conn.Write(p)
}

func (w *writeRecorder) written() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.b...)
}

func TestFragmentingEnginesOnTheWire(t *testing.T) {
	bin := area2Bin(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	originPort := ln.Addr().(*net.TCPAddr).Port
	flights := make(chan flight, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { flights <- readFlight(c) }()
		}
	}()

	for _, kind := range []singbox.Kind{singbox.TLSRecord, singbox.TLSSegment} {
		t.Run(string(kind), func(t *testing.T) {
			dir := t.TempDir()
			name := string(kind)
			if err := singbox.WriteRuleSet(dir, name, []string{"blocked.test"}); err != nil {
				t.Fatal(err)
			}
			var testPort, retryPort int
			startRetrying(t, bin, dir, name, func() ([]byte, func(*boxProc) bool) {
				testPort, retryPort = freePort(t), freePort(t)
				cfg, err := singbox.Build(singbox.Options{
					Engines:      []singbox.Engine{{Name: name, Kind: kind, Port: retryPort}},
					ObserverPort: freePort(t), RuleDir: dir, TestPort: testPort, LogLevel: "debug",
				})
				if err != nil {
					t.Fatal(err)
				}
				var m map[string]any
				if err := json.Unmarshal(cfg, &m); err != nil {
					t.Fatal(err)
				}
				// The origin is on loopback, and Build keeps private
				// addresses away from the engines on purpose: the capture
				// sends them direct before the list rules, the retry inbound
				// refuses them. Those two rules, and only those, go: each is
				// matched and removed whole, by value. The rules that apply
				// the fragment option (rule_set match on the sniffed name, or
				// the retry inbound's own route-options) are Build's own,
				// untouched, and are what carries the flows here. The
				// removed rules can only send a flow away from fragmenting,
				// never towards it, so without them nothing that should not
				// fragment starts to; the unlisted case checks that.
				dropRule(t, m, map[string]any{"ip_is_private": true, "outbound": "direct"})
				dropRule(t, m, map[string]any{"inbound": []string{name + "-in"}, "ip_is_private": true, "action": "reject"})
				cfg, _ = json.MarshalIndent(m, "", "  ")
				return cfg, func(p *boxProc) bool { return answers(testPort)(p) && answers(retryPort)(p) }
			})

			// hello opens a TLS connection to the origin through a SOCKS5
			// inbound and returns the ClientHello the client sent and the
			// flight the origin read.
			hello := func(t *testing.T, proxyPort int, serverName string) (sent []byte, got flight) {
				t.Helper()
				for len(flights) > 0 { // nothing from an earlier connection may be taken for this one
					<-flights
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				c, err := socks.Dial(ctx, nil, fmt.Sprintf("127.0.0.1:%d", proxyPort), "127.0.0.1", originPort)
				if err != nil {
					t.Fatalf("SOCKS5 connect through 127.0.0.1:%d: %v", proxyPort, err)
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				rec := &writeRecorder{Conn: c}
				tc := tls.Client(rec, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
				// The origin never answers; the handshake ends when it closes.
				_ = tc.HandshakeContext(ctx)
				select {
				case got = <-flights:
				case <-ctx.Done():
					t.Fatalf("%s: the origin got no connection", serverName)
				}
				if got.err != nil {
					t.Fatalf("%s: the origin could not read a ClientHello: %v (reads %v)", serverName, got.err, got.reads)
				}
				w := rec.written()
				if len(w) < 5 || w[0] != 0x16 {
					t.Fatalf("%s: the client's first write is not a handshake record: % x", serverName, w[:min(len(w), 5)])
				}
				n := 5 + int(binary.BigEndian.Uint16(w[3:5]))
				if len(w) < n {
					t.Fatalf("%s: the client wrote %d of a %d-byte record", serverName, len(w), n)
				}
				sent = w[:n]
				// Fragmenting must not change a byte of the message.
				if !bytes.Equal(got.hello, sent[5:]) {
					t.Fatalf("%s: the ClientHello arrived altered (%d bytes sent, %d joined from %d records)",
						serverName, len(sent)-5, len(got.hello), len(got.records))
				}
				one := append(append([]byte(nil), sent[:3]...), byte(len(got.hello)>>8), byte(len(got.hello)))
				if name, err := sni.Parse(append(one, got.hello...)); err != nil || name != serverName {
					t.Fatalf("%s: the joined ClientHello carries %q (%v)", serverName, name, err)
				}
				for i, r := range got.records {
					if !bytes.Equal(r[:3], sent[:3]) {
						t.Fatalf("%s: record %d has header % x, the client's had % x", serverName, i, r[:3], sent[:3])
					}
				}
				return sent, got
			}

			// splitInName checks that the first record ends inside the
			// server name or before it: a DPI box reading only the first
			// record must not get the whole name. sing-box splits each
			// label at a random offset, so the exact point varies.
			splitInName := func(t *testing.T, f flight, serverName string) {
				t.Helper()
				at := bytes.Index(f.hello, []byte(serverName))
				if at < 0 || bytes.Count(f.hello, []byte(serverName)) != 1 {
					t.Fatalf("%s appears %d times in the ClientHello", serverName, bytes.Count(f.hello, []byte(serverName)))
				}
				first := len(f.records[0]) - 5
				t.Logf("%s: %d records, the first ends at byte %d of the ClientHello, the name is bytes %d-%d",
					serverName, len(f.records), first, at, at+len(serverName))
				if first >= at+len(serverName) {
					t.Fatalf("the first record holds %d bytes of the ClientHello and the whole name (bytes %d-%d)",
						first, at, at+len(serverName))
				}
			}

			// segmented checks that the first read the origin did was shorter
			// than the record: tls_fragment wrote it in two parts, 500 ms
			// apart (sing-box's fallback delay; on loopback the ACK arrives
			// at once, and then it waits). A loaded machine can deschedule
			// the reader past that and get both parts in one read, so one
			// in three attempts is enough; a sing-box that does not split
			// gives one read every time.
			segmented := func(t *testing.T, proxyPort int, serverName string) {
				t.Helper()
				var seen [][]int
				size := 0
				for i := 0; i < 3; i++ {
					sent, f := hello(t, proxyPort, serverName)
					if len(f.records) != 1 {
						t.Fatalf("%s: tls_fragment must keep one TLS record, got %d", serverName, len(f.records))
					}
					if f.reads[0] < len(sent) {
						return
					}
					seen, size = append(seen, f.reads), len(sent)
				}
				t.Fatalf("%s: the %d-byte ClientHello record arrived in one read every time (reads %v): sing-box did not segment it",
					serverName, size, seen)
			}

			switch kind {
			case singbox.TLSRecord:
				t.Run("listed name, capture inbound", func(t *testing.T) {
					_, f := hello(t, testPort, "blocked.test")
					if len(f.records) < 2 {
						t.Fatalf("blocked.test is listed for tlsrec, but its ClientHello arrived as %d TLS record: sing-box did not apply tls_record_fragment", len(f.records))
					}
					splitInName(t, f, "blocked.test")
				})
				t.Run("unlisted name, capture inbound", func(t *testing.T) {
					if _, f := hello(t, testPort, "open.test"); len(f.records) != 1 {
						t.Fatalf("open.test is not listed, but its ClientHello arrived as %d records", len(f.records))
					}
				})
				t.Run("retry inbound", func(t *testing.T) {
					// The observer's retry path: everything sent here is
					// fragmented, listed or not.
					_, f := hello(t, retryPort, "open.test")
					if len(f.records) < 2 {
						t.Fatalf("the tlsrec retry inbound delivered the ClientHello as %d TLS record: sing-box did not apply tls_record_fragment", len(f.records))
					}
					splitInName(t, f, "open.test")
				})
			case singbox.TLSSegment:
				t.Run("listed name, capture inbound", func(t *testing.T) { segmented(t, testPort, "blocked.test") })
				t.Run("unlisted name, capture inbound", func(t *testing.T) {
					// Nothing to say about segments here: an unsplit write
					// can still arrive in several reads.
					if _, f := hello(t, testPort, "open.test"); len(f.records) != 1 {
						t.Fatalf("open.test: %d records", len(f.records))
					}
				})
				t.Run("retry inbound", func(t *testing.T) { segmented(t, retryPort, "open.test") })
			}
		})
	}
}
