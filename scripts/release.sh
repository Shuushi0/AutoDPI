#!/bin/bash
# Build the release archives from scratch (needs Go, clang/Xcode CLT, curl; macOS arm64 host).
# Output in dist/release/:
#   autodpi-macos-arm64-VERSION.zip    autodpi, AutoDPI.app (menu bar app),
#                                      restore-network.sh, license and READMEs
#   autodpi-windows-amd64-VERSION.zip  autodpi.exe, autodpi-tray.exe (tray app),
#                                      AutoDPI.cmd, AutoDPI Panel.cmd, autodpi-menu.ps1,
#                                      restore-network.ps1, docs/windows-test.md (where
#                                      the READMEs link it), license and READMEs
#   SHA256SUMS, SHA256SUMS.sig  (the signature installed copies check before
#                                updating; key: AUTODPI_SIGN_KEY, default
#                                ~/.autodpi-signing/release.key)
#
#   scripts/release.sh [version]     version only names the archives (default: dev);
#                                    the binaries carry internal/version and Info.plist
set -euo pipefail
cd "$(dirname "$0")/.."

VER=${1:-dev}
OUT=dist/release
KEY=${AUTODPI_SIGN_KEY:-$HOME/.autodpi-signing/release.key}

# A release must carry the version its archives are named after: the updater
# compares them, and an installed copy refuses a binary that says otherwise.
if [ "$VER" != dev ]; then
    code=$(sed -n 's/^const Version = "\(.*\)"$/\1/p' internal/version/version.go)
    plist=$(plutil -extract CFBundleShortVersionString raw macos-app/Info.plist)
    [ "$VER" = "$code" ] && [ "$VER" = "$plist" ] || {
        echo "version $VER does not match internal/version ($code) and Info.plist ($plist)" >&2; exit 1; }
    [ -f "$KEY" ] || { echo "no signing key at $KEY" >&2; exit 1; }
fi
rm -rf "$OUT" dist/autodpi dist/autodpi.exe dist/autodpi-tray.exe dist/AutoDPI.app
mkdir -p "$OUT"
DOCS="LICENSE THIRD_PARTY.md README.md README.tr.md"

echo "== macOS (arm64)"
scripts/fetch-bins.sh
scripts/build.sh
scripts/build-app.sh
M="$OUT/autodpi-macos-arm64-$VER"
mkdir -p "$M"
cp dist/autodpi "$M/"
cp -R dist/AutoDPI.app "$M/"
cp scripts/restore-network.sh $DOCS "$M/"
(cd "$OUT" && zip -qry "autodpi-macos-arm64-$VER.zip" "autodpi-macos-arm64-$VER")

echo "== Windows (amd64)"
scripts/fetch-bins-windows.sh
scripts/build-windows.sh
W="$OUT/autodpi-windows-amd64-$VER"
mkdir -p "$W"
cp dist/autodpi.exe dist/autodpi-tray.exe "$W/"
cp scripts/restore-network.ps1 scripts/windows/AutoDPI.cmd "scripts/windows/AutoDPI Panel.cmd" \
    scripts/windows/autodpi-menu.ps1 $DOCS "$W/"
mkdir -p "$W/docs" && cp docs/windows-test.md "$W/docs/" # where the READMEs link it
(cd "$OUT" && zip -qry "autodpi-windows-amd64-$VER.zip" "autodpi-windows-amd64-$VER")

rm -rf "$M" "$W"
(cd "$OUT" && shasum -a 256 *.zip | tee SHA256SUMS)
if [ -f "$KEY" ]; then
    go run ./tools/relsign sign "$KEY" "$OUT/SHA256SUMS"
    echo "signed: $OUT/SHA256SUMS.sig"
else
    echo "unsigned (no key at $KEY): installed copies will not update to this build" >&2
fi
