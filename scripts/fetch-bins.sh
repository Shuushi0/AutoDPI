#!/bin/bash
# Put the helper binaries into bin/ for development and tests. Release builds
# embed them through internal/embedded/payload (see scripts/build.sh).
#   sing-box: slim build from the official source (default), see
#             scripts/build-singbox.sh: pinned through tools/singbox/go.mod and
#             go.sum, only the build tags our configs need (~37 MB instead of
#             84 MB). Needs the Go toolchain and network access to the module
#             proxy (checked against go.sum / sum.golang.org).
#             SINGBOX_SOURCE=release falls back to the official release binary
#             from GitHub (full feature set, pinned version, checksum-verified).
#   ciadpi:   built from the pinned byedpi source (it ships no macOS binary)
set -euo pipefail
cd "$(dirname "$0")/.."

SB_VERSION=1.14.4 # also the sing-box requirement in tools/singbox/go.mod
SB_SHA256=0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838 # darwin-arm64 tarball
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v$SB_VERSION/sing-box-$SB_VERSION-darwin-arm64.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
case "${SINGBOX_SOURCE:-slim}" in
slim)
    pinned=$(cd tools/singbox && go list -m -f '{{.Version}}' github.com/sagernet/sing-box)
    [ "$pinned" = "v$SB_VERSION" ] || { echo "tools/singbox pins $pinned, this script says v$SB_VERSION" >&2; exit 1; }
    scripts/build-singbox.sh darwin arm64 "$tmp/sing-box"
    install -m 755 "$tmp/sing-box" bin/sing-box
    ;;
release)
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 -o "$tmp/sb.tar.gz" "$SB_URL"
    echo "$SB_SHA256  $tmp/sb.tar.gz" | shasum -a 256 -c - >/dev/null || { echo "sing-box checksum mismatch" >&2; exit 1; }
    tar -xzf "$tmp/sb.tar.gz" -C "$tmp"
    install -m 755 "$tmp/sing-box-$SB_VERSION-darwin-arm64/sing-box" bin/sing-box
    ;;
*) echo "SINGBOX_SOURCE must be slim or release" >&2; exit 2 ;;
esac

# ciadpi (byedpi): built from the pinned upstream source tarball (MIT).
BY_VERSION=0.17.3
BY_SHA256=0a9cb8585554c68c3e2be88c33c9bf6f99f8e8c7f54b362285adab99e262566c # source tarball
command -v clang >/dev/null || { echo "clang not found; install the Command Line Tools: xcode-select --install" >&2; exit 1; }
curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 -o "$tmp/byedpi.tar.gz" "https://github.com/hufrea/byedpi/archive/refs/tags/v$BY_VERSION.tar.gz"
echo "$BY_SHA256  $tmp/byedpi.tar.gz" | shasum -a 256 -c - >/dev/null || { echo "byedpi checksum mismatch" >&2; exit 1; }
tar -xzf "$tmp/byedpi.tar.gz" -C "$tmp"
make -C "$tmp/byedpi-$BY_VERSION" CC=clang CFLAGS="-arch arm64 -mmacosx-version-min=13.0" LDFLAGS="-arch arm64" >"$tmp/make.log" 2>&1 || { cat "$tmp/make.log" >&2; exit 1; }
strip "$tmp/byedpi-$BY_VERSION/ciadpi"
install -m 755 "$tmp/byedpi-$BY_VERSION/ciadpi" bin/ciadpi

bin/sing-box version | head -1
(cd bin && shasum -a 256 sing-box ciadpi | tee SHA256SUMS)
