#!/bin/bash
# Build the native menu bar app with swiftc from the Command Line Tools (no Xcode).
# Output: dist/AutoDPI.app   (universal arm64+x86_64 when both can be built)
#
#   ARCHS="arm64"  scripts/build-app.sh     # override the architectures
#   APP=/tmp/X.app scripts/build-app.sh     # build somewhere other than dist/
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=macos-app
APP=${APP:-dist/AutoDPI.app}
MIN_OS=13.0
NAME=AutoDPI

command -v swiftc >/dev/null || { echo "swiftc not found; install the Command Line Tools: xcode-select --install" >&2; exit 1; }
SDK=$(xcrun --show-sdk-path 2>/dev/null) || { echo "no macOS SDK found (xcrun --show-sdk-path failed)" >&2; exit 1; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/autodpi-app.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

ARCHS=${ARCHS:-"arm64 x86_64"}
BUILT=()
for arch in $ARCHS; do
    echo "• swiftc ($arch)"
    if swiftc -O -swift-version 5 -target "$arch-apple-macos$MIN_OS" -sdk "$SDK" \
        -module-cache-path "$WORK/modcache" \
        "$SRC"/Sources/*.swift -o "$WORK/$NAME-$arch" 2> "$WORK/err-$arch.txt"; then
        BUILT+=("$WORK/$NAME-$arch")
    else
        echo "  $arch build failed:" >&2
        sed 's/^/    /' "$WORK/err-$arch.txt" >&2
    fi
done
[ ${#BUILT[@]} -gt 0 ] || { echo "no architecture built" >&2; exit 1; }
grep -h "warning:" "$WORK"/err-*.txt 2>/dev/null | sort -u | head -5 || true

echo "• icon"
swiftc -O -module-cache-path "$WORK/modcache" "$SRC/tools/make-icon.swift" -o "$WORK/make-icon" 2>/dev/null
"$WORK/make-icon" "$WORK/AppIcon.iconset"
iconutil -c icns "$WORK/AppIcon.iconset" -o "$WORK/AppIcon.icns"

echo "• bundle $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
if [ ${#BUILT[@]} -gt 1 ]; then
    lipo -create "${BUILT[@]}" -output "$APP/Contents/MacOS/$NAME"
else
    cp "${BUILT[0]}" "$APP/Contents/MacOS/$NAME"
fi
cp "$SRC/Info.plist" "$APP/Contents/Info.plist"
cp "$WORK/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
printf 'APPL????' > "$APP/Contents/PkgInfo"
# Ad-hoc signature: enough for a locally built app to launch.
codesign --force --sign - "$APP" >/dev/null 2>&1
codesign --verify --strict "$APP"

lipo -archs "$APP/Contents/MacOS/$NAME" | sed 's/^/  architectures: /'
echo "built $APP"
echo "  run:     open $APP"
echo "  install: cp -R $APP /Applications/"
