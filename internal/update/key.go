package update

import (
	"crypto/ed25519"
	"encoding/base64"
)

// PublicKey verifies SHA256SUMS.sig. Its private half lives only on the
// release machine (tools/relsign); a release signed with anything else is
// refused.
var PublicKey = mustKey("IrV7HyrQKaSB03ma8cDzMmfJMvOjkp23MJXofoAraxM=")

func mustKey(s string) ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("update: bad public key")
	}
	return b
}
