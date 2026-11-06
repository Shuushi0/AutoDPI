package singbox_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The race tests ask real sing-box for DNS answers through a plain UDP DNS
// listener: a `direct` inbound aimed at port 53, which the generated rules'
// hijack-dns action answers from the configured DNS servers, the same path the
// TUN's captured port-53 traffic takes. (The clash API's /dns/query would do
// as well, but it would need `with_clash_api` compiled into the slim sing-box.)

// freeUDPPort picks a UDP port that is free now. freePort checks only TCP, and
// a TCP-free number can still be taken for UDP (that flaked the race tests).
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// addDNSProbe adds that inbound to a generated config and returns its port.
func addDNSProbe(t *testing.T, cfg map[string]any) int {
	t.Helper()
	port := freeUDPPort(t)
	cfg["inbounds"] = append(cfg["inbounds"].([]any), map[string]any{
		"type": "direct", "tag": "dns-probe", "network": "udp",
		"listen": "127.0.0.1", "listen_port": port,
		"override_address": "192.0.2.53", "override_port": 53,
	})
	return port
}

// probeAnswer is what a probe query got: the rcode, the A records and, when
// sing-box gave no usable answer (silence or SERVFAIL), a message.
type probeAnswer struct {
	Status  int
	Answer  []string
	Message string
}

func probeQuery(t *testing.T, port int, name string, wait time.Duration) probeAnswer {
	t.Helper()
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatal(err)
	}
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(wait))
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	k, err := c.Read(buf)
	if err != nil {
		return probeAnswer{Status: -1, Message: err.Error()}
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:k]); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	ans := probeAnswer{Status: int(resp.Header.RCode)}
	for _, a := range resp.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			ans.Answer = append(ans.Answer, net.IP(r.A[:]).String())
		}
	}
	if resp.Header.RCode != dnsmessage.RCodeSuccess && resp.Header.RCode != dnsmessage.RCodeNameError {
		ans.Message = "rcode " + resp.Header.RCode.String()
	}
	return ans
}

// tcpPort is the port of the generated config's loopback "test-in" listener,
// which accepts connections once sing-box has started all its inbounds.
func tcpPort(cfg map[string]any) int {
	for _, in := range cfg["inbounds"].([]any) {
		if m := in.(map[string]any); m["tag"] == "test-in" {
			return int(m["listen_port"].(float64))
		}
	}
	return 0
}
