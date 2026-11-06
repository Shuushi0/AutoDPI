package probe

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestClassifyWinsock(t *testing.T) {
	op := func(e error) error {
		return &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("wsarecv", e)}
	}
	for _, c := range []struct {
		err  error
		want Outcome
	}{
		{op(windows.WSAECONNRESET), Reset},
		{op(windows.WSAECONNABORTED), Other}, // local abort, not a peer RST (W7)
		{op(windows.WSAECONNREFUSED), Refused},
		{op(windows.WSAENETUNREACH), Refused},
	} {
		if got := classify(c.err); got != c.want {
			t.Errorf("classify(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
