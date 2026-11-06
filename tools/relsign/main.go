// relsign makes and uses the release signing key (see internal/update).
//
//	go run ./tools/relsign keygen ~/.autodpi-signing/release.key
//	    writes a new private key (mode 0600) and prints the public key for
//	    internal/update/key.go; refuses to overwrite an existing key
//	go run ./tools/relsign sign ~/.autodpi-signing/release.key dist/release/SHA256SUMS
//	    writes dist/release/SHA256SUMS.sig and checks it against key.go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/Shuushi0/AutoDPI/internal/update"
)

func main() {
	if len(os.Args) < 3 {
		die("usage: relsign keygen KEYFILE | relsign sign KEYFILE SHA256SUMS")
	}
	switch os.Args[1] {
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			die("%v", err)
		}
		f, err := os.OpenFile(os.Args[2], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			die("%v", err)
		}
		fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed()))
		if err := f.Close(); err != nil {
			die("%v", err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
	case "sign":
		if len(os.Args) != 4 {
			die("usage: relsign sign KEYFILE SHA256SUMS")
		}
		b, err := os.ReadFile(os.Args[2])
		if err != nil {
			die("%v", err)
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			die("%s is not a release key", os.Args[2])
		}
		key := ed25519.NewKeyFromSeed(seed)
		sums, err := os.ReadFile(os.Args[3])
		if err != nil {
			die("%v", err)
		}
		sig := update.Sign(sums, key)
		// A key that is not the one the binaries trust would publish a release
		// no installed copy accepts.
		if err := update.Verify(sums, sig, update.PublicKey); err != nil {
			die("this key does not match internal/update/key.go: %v", err)
		}
		if err := os.WriteFile(os.Args[3]+".sig", sig, 0o644); err != nil {
			die("%v", err)
		}
	default:
		die("unknown command %q", os.Args[1])
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "relsign: "+format+"\n", a...)
	os.Exit(1)
}
