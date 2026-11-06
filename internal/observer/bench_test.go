package observer

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/socks"
)

func socksConnB(b *testing.B, proxy, target string) net.Conn {
	b.Helper()
	host, ps, _ := net.SplitHostPort(target)
	port, _ := net.LookupPort("tcp", ps)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := socks.Dial(ctx, nil, proxy, host, port)
	if err != nil {
		b.Fatal(err)
	}
	return c
}

// benchFlow measures one complete flow (SOCKS, ClientHello, server's first
// bytes, close) through an observer whose Mode is mode. Run with -benchmem:
// allocs/op of Light against Full is the saving for an open name.
func benchFlow(b *testing.B, mode Mode) {
	hello := captureHello(&tls.Config{ServerName: "www.example.org", InsecureSkipVerify: true})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write(rec(0x16, []byte{2, 0, 0, 0}))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	o := New(Options{
		Dial:          (&net.Dialer{}).DialContext,
		Events:        func(Event) {},
		Mode:          func(string) Mode { return mode },
		AllowLoopback: true,
		Ports:         []int{port},
		HelloWait:     time.Second,
	})
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	go func() { _ = o.Serve(pl) }()
	defer o.Close()
	target := ln.Addr().String()
	reply := make([]byte, 9)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := socksConnB(b, pl.Addr().String(), target)
		_, _ = c.Write(hello)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(c, reply); err != nil {
			b.Fatal(err)
		}
		c.Close()
	}
}

func BenchmarkFlowFullPath(b *testing.B)  { benchFlow(b, Full) }
func BenchmarkFlowLightPath(b *testing.B) { benchFlow(b, Light) }
