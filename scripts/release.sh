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

# What a shell left set must not shape a release: these switch the helper
# binaries to other files, sing-box to another feature set or source, and the
# output to another place, all without a word in the result.
unset AUTODPI_BINDIR AUTODPI_OUT SB_TAGS SB_NOPIN SINGBOX_SOURCE AUTODPI_HOME AUTODPI_LANG
# The same for Go's own switches. GOENV=off is what shuts out settings saved
# with `go env -w`: a variable exported EMPTY does not override them (Go then
# reads its env file), so a saved GOFLAGS=-skip=... ran the suite without the
# tests it named, and a saved GOEXPERIMENT went into the binaries.
# GOAMD64=v3 left from another project builds Windows programs that do not
# start on a processor without AVX2, and nothing on this machine runs them.
# GOTOOLCHAIN: exactly the Go that go.mod names, as for sing-box.
export GOENV=off GOFIPS140=off GOFLAGS= GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0 GOWORK=off GOTOOLCHAIN="go$(awk '$1=="go"{print $2; exit}' go.mod)"

# A release must carry the version its archives are named after: the updater
# compares them, and an installed copy refuses a binary that says otherwise.
if [ "$VER" != dev ]; then
    code=$(sed -n 's/^const Version = "\(.*\)"$/\1/p' internal/version/version.go)
    plist=$(plutil -extract CFBundleShortVersionString raw macos-app/Info.plist)
    [ "$VER" = "$code" ] && [ "$VER" = "$plist" ] || {
        echo "version $VER does not match internal/version ($code) and Info.plist ($plist)" >&2; exit 1; }
    [ -f "$KEY" ] || { echo "no signing key at $KEY" >&2; exit 1; }
    # A signed release is what a commit says, nothing else: with changes in
    # the working tree the archives would hold code no commit and no tag
    # describes, under a signature every installed copy trusts.
    dirty=$(git status --porcelain 2>/dev/null) || { echo "not a git checkout: a release is built from a commit" >&2; exit 1; }
    [ -z "$dirty" ] || { echo "the working tree has changes that are not committed:" >&2; echo "$dirty" | head -20 >&2
        echo "commit (or stash) them first: nothing was built" >&2; exit 1; }
    echo "== release $VER from commit $(git rev-parse --short HEAD)"
fi
rm -rf "$OUT" dist/autodpi dist/autodpi.exe dist/autodpi-tray.exe dist/AutoDPI.app
mkdir -p "$OUT"
DOCS="LICENSE THIRD_PARTY.md README.md README.tr.md"

echo "== macOS (arm64)"
scripts/fetch-bins.sh
scripts/build.sh

# Nothing is packaged unless the whole test suite ran against the helper
# binaries just built. sing-box here is our own build of it (tools/singbox):
# the tests are what says that it still accepts every configuration the
# daemon writes and holds nothing else. Tests that need the binaries skip
# themselves when they are missing, which must not pass for a release.
echo "== tests, with the helpers just built"
testlog=$(mktemp)
trap 'rm -f "$testlog"' EXIT
go vet ./...
GOOS=windows GOARCH=amd64 go vet ./...
if ! go test -count=1 -v ./... >"$testlog" 2>&1; then
    grep -E '^(--- FAIL|FAIL|panic:)' -B2 -A15 "$testlog" | head -120 >&2
    echo "tests failed: nothing was packaged" >&2; exit 1
fi
if grep -Eiq 'sing-box binary not available|no sing-box binary|helper binaries not available|not AutoDPI.s own sing-box build|dist/autodpi not built' "$testlog"; then
    grep -Ei -A1 'not available|no sing-box binary|own sing-box build|not built' "$testlog" | head -20 >&2
    echo "tests that need the helper binaries were skipped: nothing was packaged" >&2; exit 1
fi
grep -q 'combinations accepted' "$testlog" || { echo "the configuration matrix did not run: nothing was packaged" >&2; exit 1; }
# And no test skipped at all, whatever it says: on the machine a release is
# built on, with the helpers just built and the network up, none has a reason
# to. A new skip is a guard that quietly stopped guarding.
# The one exception: the checks of the Windows scripts need PowerShell 7,
# which is not something this machine has to have. Without it they are named
# here, loudly, instead of failing the release.
if grep -q 'no PowerShell 7 here' "$testlog"; then
    echo "NOTE: the Windows script checks did not run (no PowerShell 7; set AUTODPI_PWSH)" >&2
fi
# (go test -v prints a skip's reason on the line BEFORE its "--- SKIP".)
if ! awk '/^[[:space:]]*--- SKIP/ && prev !~ /no PowerShell 7 here/ { bad = 1 } { prev = $0 } END { exit bad }' "$testlog"; then
    grep -E -B2 '^[[:space:]]*--- SKIP' "$testlog" | head -30 >&2
    echo "tests were skipped: nothing was packaged" >&2; exit 1
fi
# The tests that pin what every user runs did run and did pass. A test that
# is skipped is caught above; one that never ran at all (a -skip flag, a build
# tag, a renamed function, an early return) leaves no line to find, so the
# lines that must be there are looked for.
for must in TestConfigurationsAreUnchanged TestRuleSetFilesAreUnchanged TestCaptureSettingsArePinned \
    TestTheDaemonWritesThePinnedConfiguration TestTheUsersSettingsReachSingBox \
    TestCheckCreatesTheBox TestDeprecationsAreReported TestTheBinaryIsBuiltFromThePinnedModules \
    TestTheBinaryIsThePinnedBuild TestTheBuildHasGVisor TestDoHOverHTTP2 TestContractIsAccepted \
    TestASingBoxThatAcceptsEverythingFails TestCrashAtEveryStepOfAnInstall TestTwoFailedRenamesNeverLoseTheProgram; do
    grep -q "^--- PASS: $must " "$testlog" || { echo "$must did not run and pass: nothing was packaged" >&2; exit 1; }
done
# And the tests changed nothing in the tree (the golden files can be rewritten
# by a test run with -update; a release is built from what was committed).
if [ "$VER" != dev ] && [ -n "$(git status --porcelain)" ]; then
    git status --porcelain | head -10 >&2
    echo "the test run changed files in the tree: nothing was packaged" >&2; exit 1
fi
# The helpers inside dist/autodpi are the ones the tests just ran against:
# the hashes compiled in must be the hashes of what is embedded.
go test -count=1 -tags embedbins -run TestPayloadHashesMatchEmbedded ./internal/embedded/ >/dev/null || {
    echo "the embedded helpers do not match their recorded hashes: nothing was packaged" >&2; exit 1; }
dist/autodpi selftest

# Nothing is packaged with a published vulnerability in what it carries. The
# one exception is an advisory against golang.org/x/crypto/openpgp as a whole,
# which the scan pins on sing-box's x/crypto although no openpgp code is in the
# binary.
#
# The gate is closed unless the scan itself says it ran: a scanner that could
# not be fetched, could not reach the vulnerability database or could not
# read the file used to print no advisory id, and that passed as "none".
# The scanner is a fixed version, built once into a directory of its own.
GOVULNCHECK=golang.org/x/vuln/cmd/govulncheck@v1.9.0
vulnbin=$(mktemp -d)
trap 'rm -rf "$testlog" "$vulnbin"' EXIT
GOBIN="$vulnbin" go install "$GOVULNCHECK" || { echo "the vulnerability scanner could not be built: nothing was packaged" >&2; exit 1; }
novulns() {
    local f out rc ids
    for f in "$@"; do
        rc=0
        out=$("$vulnbin/govulncheck" -mode binary "$f" 2>&1) || rc=$?
        # 0: scanned, nothing found. 3: scanned, something found. Anything
        # else, or a 0 without the scanner's own words for it: it did not scan.
        if { [ "$rc" != 0 ] && [ "$rc" != 3 ]; } || { [ "$rc" = 0 ] && ! printf '%s\n' "$out" | grep -q 'No vulnerabilities found'; }; then
            printf '%s\n' "$out" | tail -8 >&2
            echo "$f could not be scanned for vulnerabilities (exit $rc): nothing was packaged" >&2; exit 1
        fi
        ids=$(printf '%s\n' "$out" | grep -oE 'GO-[0-9]+-[0-9]+' | sort -u | grep -vx 'GO-2026-5932' || true)
        if [ "$rc" = 3 ] && [ -z "$ids" ] && ! printf '%s\n' "$out" | grep -q 'GO-2026-5932'; then
            printf '%s\n' "$out" | tail -8 >&2
            echo "$f: the scan reported findings this script could not read: nothing was packaged" >&2; exit 1
        fi
        [ -z "$ids" ] || { echo "$f has published vulnerabilities:" $ids "(a newer Go or dependency fixes them: nothing was packaged)" >&2; exit 1; }
    done
}
echo "== known vulnerabilities"
novulns dist/autodpi bin/sing-box

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
# The Windows programs cannot be run here. What can be said from this side:
# sing-box.exe is the same source and the same dependencies as the macOS one
# that just passed. Before a release goes out, run `autodpi.exe selftest` on
# a Windows machine once; an installed copy runs it by itself before updating.
# Built for every amd64 processor, not for whatever the shell had set.
for exe in bin/sing-box.exe dist/autodpi.exe dist/autodpi-tray.exe; do
    go version -m "$exe" | grep -q 'GOAMD64=v1$' || { echo "$exe was not built with GOAMD64=v1" >&2; exit 1; }
done
same() { go version -m "$1" | awk '$1 == "mod" || $1 == "dep" { print $2, $3 }' | grep -Ev 'netx-go|wintun|go-ole|mousetrap' | sort; }
if ! diff <(same bin/sing-box) <(same bin/sing-box.exe) >/dev/null; then
    diff <(same bin/sing-box) <(same bin/sing-box.exe) >&2 || true
    echo "sing-box.exe is not built from the same modules as the macOS sing-box" >&2; exit 1
fi
novulns dist/autodpi.exe dist/autodpi-tray.exe bin/sing-box.exe
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
