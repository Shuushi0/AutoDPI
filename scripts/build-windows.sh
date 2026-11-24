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
# What is embedded is what the fetch script built and recorded, not a file
# that happens to lie in bin/ from an experiment.
[ -f bin/SHA256SUMS.windows ] && (cd bin && shasum -a 256 -c SHA256SUMS.windows >/dev/null 2>&1) ||
    { echo "bin/ does not match bin/SHA256SUMS.windows; run scripts/fetch-bins-windows.sh first" >&2; exit 1; }
# And sing-box is the build this tree pins (tools/singbox/expected.sha256, a
# tracked file): bin/'s own list is rewritten by whatever was built last.
[ -n "${SB_NOPIN:-}" ] || [ "$(shasum -a 256 bin/sing-box.exe | awk '{print $1}')" = "$(awk '$2 == "windows-amd64" { print $1 }' tools/singbox/expected.sha256)" ] ||
    { echo "bin/sing-box.exe is not the build tools/singbox/expected.sha256 names; run the fetch script again" >&2; exit 1; }
OUT=${AUTODPI_OUT:-dist/autodpi.exe}
# Go's switches as the release needs them, whatever the shell or `go env -w`
# says (GOENV=off: an empty variable alone does not override a saved one):
# no extra flags, the baseline processor, the Go that go.mod names.
export GOENV=off GOFIPS140=off GOFLAGS= GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0 GOWORK=off GOTOOLCHAIN="go$(awk '$1=="go"{print $2; exit}' go.mod)"
mkdir -p internal/embedded/payload "$(dirname "$OUT")"
cp bin/sing-box.exe bin/ciadpi.exe internal/embedded/payload/
scripts/gen-payload-hashes.sh 'embedbins && windows' payload_hashes_windows_gen.go sing-box.exe ciadpi.exe
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags embedbins -trimpath -ldflags "-s -w" -o "$OUT" ./cmd/autodpi
# The notification-area app: a GUI-subsystem binary (no console window), next
# to autodpi.exe so `autodpi install` finds and installs it.
TRAY="$(dirname "$OUT")/autodpi-tray.exe"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H windowsgui" -o "$TRAY" ./cmd/autodpi-tray
ls -lh "$OUT" "$TRAY"
