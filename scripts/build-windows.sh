#!/bin/bash
# Build the self-contained Windows binary, autodpi.exe with sing-box.exe and
# ciadpi.exe embedded, and the tray app autodpi-tray.exe next to it.
# Cross-compiles from macOS/Linux.
# Output: dist/autodpi.exe and dist/autodpi-tray.exe (windows/amd64;
# AUTODPI_OUT=path moves both)
set -euo pipefail
cd "$(dirname "$0")/.."

for b in sing-box.exe ciadpi.exe; do
    [ -s "bin/$b" ] || { echo "bin/$b missing; run scripts/fetch-bins-windows.sh first" >&2; exit 1; }
done
OUT=${AUTODPI_OUT:-dist/autodpi.exe}
mkdir -p internal/embedded/payload "$(dirname "$OUT")"
cp bin/sing-box.exe bin/ciadpi.exe internal/embedded/payload/
scripts/gen-payload-hashes.sh 'embedbins && windows' payload_hashes_windows_gen.go sing-box.exe ciadpi.exe
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags embedbins -trimpath -ldflags "-s -w" -o "$OUT" ./cmd/autodpi
# The notification-area app: a GUI-subsystem binary (no console window), next
# to autodpi.exe so `autodpi install` finds and installs it.
TRAY="$(dirname "$OUT")/autodpi-tray.exe"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H windowsgui" -o "$TRAY" ./cmd/autodpi-tray
ls -lh "$OUT" "$TRAY"
