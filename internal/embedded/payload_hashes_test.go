//go:build embedbins

package embedded

import "testing"

// Run with: go test -tags embedbins ./internal/embedded (after scripts/build.sh
// or build-windows.sh): the generated constants must describe the embedded bytes.
func TestPayloadHashesMatchEmbedded(t *testing.T) {
	for _, name := range []string{SingBox, Ciadpi} {
		want, ok := payloadHashes[name]
		if !ok {
			t.Fatalf("no build-time hash for %s", name)
		}
		r, err := openPayload(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := hashOf(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: embedded payload hash %s, generated constant %s (stale payload_hashes_gen.go?)", name, got, want)
		}
	}
}
