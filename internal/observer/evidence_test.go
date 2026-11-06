package observer

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
)

// codedErr carries an error code under a message that names no reset, as
// Windows does in a language other than English.
type codedErr struct{ code error }

func (e codedErr) Error() string {
	return "Varolan bir bağlantı uzaktaki bir ana bilgisayar tarafından zorla kapatıldı."
}
func (e codedErr) Unwrap() error { return e.code }

func TestResetIsReadFromTheCodeNotTheText(t *testing.T) {
	err := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("wsarecv", codedErr{resetCode})}
	if !blockEvidence(err) {
		t.Fatalf("a reset worded in Turkish is not block evidence: %v", err)
	}
	if s := (outcome{name: "direct", err: err}).String(); !strings.Contains(s, "reset") {
		t.Fatalf("the journal text does not name the reset: %q", s)
	}
	if blockEvidence(errors.New("i/o timeout")) {
		t.Fatal("a timeout counted as block evidence")
	}
}
