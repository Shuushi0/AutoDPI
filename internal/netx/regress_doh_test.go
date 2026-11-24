package netx

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blackhole is a TCP relay whose existing connections can be made to swallow
// everything in both directions without closing, while new connections work:
// what a phone hotspot does to flows whose NAT state it lost (its upstream got
// a new address, it restarted tethering), or a Wi-Fi that came back with a new
// lease.
type blackhole struct {
	ln      net.Listener
	target  string
	mu      sync.Mutex
	conns   []*atomic.Bool
	accepts atomic.Int32
}

func (b *blackhole) killExisting() {
	b.mu.Lock()
	for _, d := range b.conns {
		d.Store(true)
	}
	b.mu.Unlock()
}

func (b *blackhole) serve() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		b.accepts.Add(1)
		u, err := net.Dial("tcp", b.target)
		if err != nil {
			c.Close()
			continue
		}
		dead := new(atomic.Bool)
		b.mu.Lock()
		b.conns = append(b.conns, dead)
		b.mu.Unlock()
		pipe := func(dst, src net.Conn) {
			buf := make([]byte, 32<<10)
			for {
				n, err := src.Read(buf)
				if err != nil {
					dst.Close()
					return
				}
				if dead.Load() {
					continue // swallowed: no error, no answer
				}
				if _, err := dst.Write(buf[:n]); err != nil {
					src.Close()
					return
				}
			}
		}
		go pipe(u, c)
		go pipe(c, u)
	}
}

// After a blip that kills the pooled DoH connection silently, does the
// daemon's DoH client (health check, ASN lookup, observer resolve) open a new
// one, or keep sending into the dead one?
func TestRegressDoHPoolAfterSilentDeath(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"type":1,"data":"93.184.215.14"}]}`)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	bh := &blackhole{ln: ln, target: srv.Listener.Addr().String()}
	go bh.serve()

	d := NewDoHServers(&Dialer{Timeout: 12 * time.Second}, []string{ln.Addr().String()})
	tr := d.Client.Transport.(*http.Transport)
	tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	switch os.Getenv("R4_FIX") {
	case "ping":
		tr.HTTP2 = &http.HTTP2Config{SendPingTimeout: 5 * time.Second, PingTimeout: 3 * time.Second}
	}
	tries := 8
	if n, err := strconv.Atoi(os.Getenv("R4_TRIES")); err == nil {
		tries = n
	}

	look := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second) // as healthy()
		defer cancel()
		_, err := d.LookupIPv4(ctx, "example.com")
		return err
	}
	for range 3 {
		if err := look(); err != nil {
			t.Fatalf("warm-up: %v", err)
		}
	}
	if n := bh.accepts.Load(); n != 1 {
		t.Fatalf("warm-up used %d connections, want 1 (pooled)", n)
	}
	bh.killExisting() // the blip
	if os.Getenv("R4_FIX") == "closeidle" {
		tr.CloseIdleConnections() // what a "route came back" hook could do
	}
	var results []string
	start := time.Now()
	recovered := false
	for i := 0; i < tries; i++ { // health checks in a row
		t0 := time.Now()
		err := look()
		r := "ok"
		if err != nil {
			r = "FAIL"
		}
		results = append(results, r+"/"+time.Since(t0).Round(100*time.Millisecond).String())
		if err == nil {
			recovered = true
			break
		}
	}
	t.Logf("after silent death: %v (total %v), new connections: %d", results, time.Since(start).Round(time.Second), bh.accepts.Load()-1)
	if !recovered {
		t.Errorf("DoH never left the dead pooled connection in %d lookups", len(results))
	}
}

// A lookup the caller gave up on says nothing about the connections: the one
// that works is kept, not closed under the other lookups using it.
func TestACancelledLookupKeepsTheConnection(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"type":1,"data":"93.184.215.14"}]}`)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	bh := &blackhole{ln: ln, target: srv.Listener.Addr().String()}
	go bh.serve()

	d := NewDoHServers(&Dialer{Timeout: 12 * time.Second}, []string{ln.Addr().String()})
	tr := d.Client.Transport.(*http.Transport)
	tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	if _, err := d.LookupIPv4(context.Background(), "example.com"); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.LookupIPv4(gone, "example.com"); err == nil {
		t.Fatal("a cancelled lookup succeeded")
	}
	if _, err := d.LookupIPv4(context.Background(), "example.com"); err != nil {
		t.Fatalf("after the cancelled lookup: %v", err)
	}
	if n := bh.accepts.Load(); n != 1 {
		t.Fatalf("%d connections were opened, want 1: the cancelled lookup closed a working one", n)
	}
	d.Reset()
	if _, err := d.LookupIPv4(context.Background(), "example.com"); err != nil {
		t.Fatalf("after Reset: %v", err)
	}
	if n := bh.accepts.Load(); n != 2 {
		t.Fatalf("%d connections after Reset, want 2 (a new one)", n)
	}
	d.mu.Lock()
	open := len(d.conns)
	d.mu.Unlock()
	if open != 1 {
		t.Fatalf("%d connections are tracked, want 1 (closed ones are forgotten)", open)
	}
}
