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
OUT=${AUTODPI_OUT:-dist/autodpi}
mkdir -p "$(dirname "$OUT")"
CGO_ENABLED=0 go build -tags embedbins -trimpath -ldflags "-s -w" -o "$OUT" ./cmd/autodpi
ls -lh "$OUT"
