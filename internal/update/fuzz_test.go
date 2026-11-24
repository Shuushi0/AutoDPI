package update

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// A release tag is whatever the release list says. Compare must stay an order,
// and two different texts must never both be the same valid version: the
// archive name is built from the text, the decision to install from the order.
func FuzzCompare(f *testing.F) {
	for _, s := range [][2]string{{"0.1.0", "0.1.1"}, {"1.0.0-rc1", "1.0.0"}, {"+1.2.3", "1.2.3"}, {"1.2.3-", "1.2.3"}, {"", "x"}, {"01.2.3", "1.2.3"}, {"1.2.3-a-b", "1.2.3-a"}, {"0.0.0- ", "0.0.0"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, ba := Compare(a, b), Compare(b, a)
		if ab != -ba {
			t.Fatalf("Compare(%q, %q) = %d but the reverse is %d", a, b, ab, ba)
		}
		if Compare(a, a) != 0 {
			t.Fatalf("Compare(%q, %q) != 0", a, a)
		}
		if ab == 0 && a != b && Valid(a) && Valid(b) {
			t.Fatalf("two spellings of one version: %q and %q", a, b)
		}
		if Valid(a) && strings.Trim(a, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-") != "" {
			t.Fatalf("valid version with an unsafe character: %q", a)
		}
	})
}

// sumFor reads SHA256SUMS after its signature passed; still, a hash it
// returns must be one the listing holds.
func FuzzSumFor(f *testing.F) {
	h := sha256.Sum256([]byte("x"))
	f.Add([]byte(hex.EncodeToString(h[:])+"  a.zip\n"), "a.zip")
	f.Add([]byte(hex.EncodeToString(h[:])+" *a.zip\r\n"), "a.zip")
	f.Add([]byte("zz  a.zip\n"), "a.zip")
	f.Fuzz(func(t *testing.T, sums []byte, name string) {
		got, err := sumFor(sums, name)
		if err != nil {
			return
		}
		if len(got) != sha256.Size || name == "" || !strings.Contains(strings.ToLower(string(sums)), hex.EncodeToString(got)) {
			t.Fatalf("hash %x for %q is not taken from the listing", got, name)
		}
	})
}
