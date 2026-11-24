#!/bin/bash
# Build the single self-contained binary: autodpi with sing-box and ciadpi
# embedded. Output: dist/autodpi (AUTODPI_OUT=path overrides it)
set -euo pipefail
cd "$(dirname "$0")/.."

for b in sing-box ciadpi; do
    [ -x "bin/$b" ] || { echo "bin/$b missing; run scripts/fetch-bins.sh first" >&2; exit 1; }
    cp "bin/$b" "internal/embedded/payload/$b"
done
scripts/gen-payload-hashes.sh 'embedbins && !windows' payload_hashes_gen.go sing-box ciadpi
# What is embedded is what the fetch script built and recorded, not a file
# that happens to lie in bin/ from an experiment.
[ -f bin/SHA256SUMS ] && (cd bin && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1) ||
    { echo "bin/ does not match bin/SHA256SUMS; run scripts/fetch-bins.sh first" >&2; exit 1; }
# And sing-box is the build this tree pins (tools/singbox/expected.sha256, a
# tracked file): bin/'s own list is rewritten by whatever was built last.
[ -n "${SB_NOPIN:-}" ] || [ "$(shasum -a 256 bin/sing-box | awk '{print $1}')" = "$(awk '$2 == "darwin-arm64" { print $1 }' tools/singbox/expected.sha256)" ] ||
    { echo "bin/sing-box is not the build tools/singbox/expected.sha256 names; run the fetch script again" >&2; exit 1; }
OUT=${AUTODPI_OUT:-dist/autodpi}
# Go's switches as the release needs them, whatever the shell or `go env -w`
# says (GOENV=off: an empty variable alone does not override a saved one):
# no extra flags, the baseline processor, the Go that go.mod names.
export GOENV=off GOFIPS140=off GOFLAGS= GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0 GOWORK=off GOTOOLCHAIN="go$(awk '$1=="go"{print $2; exit}' go.mod)"
mkdir -p "$(dirname "$OUT")"
CGO_ENABLED=0 go build -tags embedbins -trimpath -ldflags "-s -w" -o "$OUT" ./cmd/autodpi
ls -lh "$OUT"
