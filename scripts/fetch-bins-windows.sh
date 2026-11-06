#!/bin/bash
# Put the Windows (amd64) helper binaries into bin/ as sing-box.exe and
# ciadpi.exe, next to the macOS ones (the names do not collide). Runs on
# macOS, Linux or Git Bash; scripts/build-windows.sh embeds the result.
#   sing-box: slim build from the official source (default), see
#             scripts/build-singbox.sh (Go toolchain + module proxy needed;
#             wintun.dll is embedded in the binary, libcronet.dll is not used).
#             SINGBOX_SOURCE=release falls back to the official release zip
#             from GitHub (pinned version, checksum-verified).
#   ciadpi:   byedpi's official x86_64-w64 release, pinned version, checksum-verified
# libcronet.dll from the release archive is not needed: sing-box.exe has no
# static DLL imports and loads it only for the naive outbound, which we never use.
set -euo pipefail
cd "$(dirname "$0")/.."

SB_VERSION=1.14.4 # also the sing-box requirement in tools/singbox/go.mod
SB_SHA256=99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df # windows-amd64 zip
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v$SB_VERSION/sing-box-$SB_VERSION-windows-amd64.zip"

BD_VERSION=17.3
BD_SHA256=70d2c94147193cb915f9c6eb5144b8d404dacbcfa90bda2383b6b211afafa456 # x86_64-w64 zip
BD_URL="https://github.com/hufrea/byedpi/releases/download/v0.$BD_VERSION/byedpi-$BD_VERSION-x86_64-w64.zip"

sha256() {
    if command -v shasum >/dev/null; then shasum -a 256 "$1"; else sha256sum "$1"; fi | cut -d' ' -f1
}
fetch() { # url sha256 out
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 -o "$3" "$1"
    local got
    got=$(sha256 "$3")
    [ "$got" = "$2" ] || { echo "checksum mismatch for $1: got $got" >&2; exit 1; }
}
extract() { # zip member out
    if command -v unzip >/dev/null; then
        unzip -p "$1" "$2" >"$3"
    else # bsdtar (macOS, Windows 10+) reads zip archives too
        tar -xOf "$1" "$2" >"$3"
    fi
    [ -s "$3" ] || { echo "$2 missing from $1" >&2; exit 1; }
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p bin

case "${SINGBOX_SOURCE:-slim}" in
slim)
    pinned=$(cd tools/singbox && go list -m -f '{{.Version}}' github.com/sagernet/sing-box)
    [ "$pinned" = "v$SB_VERSION" ] || { echo "tools/singbox pins $pinned, this script says v$SB_VERSION" >&2; exit 1; }
    scripts/build-singbox.sh windows amd64 "$tmp/sing-box.exe"
    install -m 755 "$tmp/sing-box.exe" bin/sing-box.exe
    ;;
release)
    fetch "$SB_URL" "$SB_SHA256" "$tmp/sb.zip"
    extract "$tmp/sb.zip" "sing-box-$SB_VERSION-windows-amd64/sing-box.exe" bin/sing-box.exe
    ;;
*) echo "SINGBOX_SOURCE must be slim or release" >&2; exit 2 ;;
esac

fetch "$BD_URL" "$BD_SHA256" "$tmp/bd.zip"
extract "$tmp/bd.zip" ciadpi.exe bin/ciadpi.exe

(cd bin && for f in sing-box.exe ciadpi.exe; do echo "$(sha256 "$f")  $f"; done | tee SHA256SUMS.windows)
