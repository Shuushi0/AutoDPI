//go:build !windows

package daemon

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/Shuushi0/AutoDPI/internal/fakenet"
	"github.com/Shuushi0/AutoDPI/internal/observer"
	"github.com/Shuushi0/AutoDPI/internal/socks"
)

// Stopping the capture closes the flows its engines carried, which reads like a
// server's rejection. What the observer remembers from before must not outlive
// it: on a network switch the capture stops after the network change was handled.
func TestStoppingTheCaptureForgetsRememberedDestinations(t *testing.T) {
	d, _ := rig(t, Options{})
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Read(make([]byte, 4096)) // the ClientHello, then a close
			}()
		}
	}()
	host, ps, _ := net.SplitHostPort(srv.Addr().String())
	port, _ := net.LookupPort("tcp", ps)
	eng, err := fakenet.NewSplitEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	d.obs = observer.New(observer.Options{
		Engines:        func() []observer.Engine { return []observer.Engine{{Name: "tlsrec", Addr: eng.Addr()}} },
		Dial:           (&net.Dialer{}).DialContext,
		HelloWait:      time.Second,
		ConnectTimeout: time.Second,
		FirstByte:      time.Second,
		Hedge:          20 * time.Millisecond,
		AllowLoopback:  true,
		Ports:          []int{port},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = d.obs.Serve(ln) }()
	defer d.obs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := socks.Dial(ctx, nil, ln.Addr().String(), host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tls.Client(c, &tls.Config{ServerName: "rejected.test", InsecureSkipVerify: true}).Handshake(); err == nil {
		t.Fatal("a rejecting server opened")
	}
	waitFor(t, "the destination to be remembered", func() bool { return d.obs.DeadLen() == 1 })

	d.mu.Lock()
	d.sbStop = func() {}
	d.mu.Unlock()
	d.stopSingBox()
	if n := d.obs.DeadLen(); n != 0 {
		t.Fatalf("DeadLen = %d after the capture stopped", n)
	}
}
