#!/bin/bash
# Build a slim sing-box from the official source, pinned through the Go module
# system, instead of using the full release binary (84 MB: tailscale, openvpn,
# openconnect, cloudflared, acme, clash api, naive, ...).
#
# What is built is tools/singbox/main.go: sing-box as a library, with only the
# protocols internal/singbox configures registered. The stock command
# registers every protocol unconditionally (include/registry.go), which no
# build tag can undo; that kept ssh, shadowsocks, vmess, gRPC and the rest in
# the binary (36 MB). Without them it is 18 MB.
#
#   scripts/build-singbox.sh <goos> <goarch> <output file>
#
# The version is the sing-box requirement in tools/singbox/go.mod; go.sum next
# to it pins every dependency's hash, `go mod verify` re-checks the module
# cache against it, and -mod=readonly stops the build from changing either
# (a hash not in go.sum is checked against sum.golang.org by `go get`, never
# silently trusted). To move to another version: cd tools/singbox &&
# go get github.com/sagernet/sing-box@vX.Y.Z && go mod tidy, then update
# SB_VERSION and the checksums in scripts/fetch-bins*.sh. go.mod there also
# holds a few dependencies newer than that sing-box release asks for, where
# the older one has a published vulnerability; `go get` keeps them.
#
# Build tags (SB_TAGS overrides this list):
#   with_gvisor     the TUN stack. Our TUN inbound names `stack: mixed`
#                   (system TCP + gVisor UDP), which needs gVisor built in
#                   (+4 MB). WireGuard's userspace netstack needs it as well.
#   with_wireguard  kept as the official build has it. In sing-box 1.14 the
#                   tag is read only by sing-box's own include/ package, which
#                   this build does not use: the `warp` engine's WireGuard
#                   endpoint is registered in main.go either way.
# Not needed by any config internal/singbox generates, so left out:
#   with_quic (QUIC/HTTP3 transports; our DoH is HTTP/2), with_utls, with_dhcp,
#   with_acme, with_clash_api, with_tailscale, with_cloudflared, with_openvpn,
#   with_openconnect, with_usbip, with_ccm, with_ocm, with_naive_outbound,
#   badlinkname/tfogo_checklinkname0 (speed-ups through crypto/tls linknames).
# Route options tls_record_fragment, tls_fragment and tls_spoof, DoH/UDP/TCP DNS
# servers, the `evaluate`/`respond`/`race` DNS rule actions, tun, mixed, socks
# and direct need no tag. CGO is off, like the daemon itself.
set -euo pipefail
cd "$(dirname "$0")/.."

GOOS_=${1:?usage: build-singbox.sh <goos> <goarch> <output>}
GOARCH_=${2:?usage: build-singbox.sh <goos> <goarch> <output>}
OUT=${3:?usage: build-singbox.sh <goos> <goarch> <output>}
case $OUT in /*) ;; *) OUT=$PWD/$OUT ;; esac
TAGS=${SB_TAGS-with_gvisor,with_wireguard}

command -v go >/dev/null || { echo "go is required to build sing-box (or use SINGBOX_SOURCE=release)" >&2; exit 1; }
cd tools/singbox
VERSION=$(go list -m -f '{{.Version}}' github.com/sagernet/sing-box)
VERSION=${VERSION#v}
# GOWORK=off: a go.work in a parent folder must not put this build into
# workspace mode. GOTOOLCHAIN: exactly the Go that go.mod names, not whatever
# newer one happens to be installed.
export GOFLAGS=-mod=readonly GOWORK=off GOTOOLCHAIN="go$(awk '$1=="go"{print $2; exit}' go.mod)" \
    CGO_ENABLED=0 GOOS=$GOOS_ GOARCH=$GOARCH_
# The baseline processor and no experiments, whatever the shell has set: a
# GOAMD64=v3 left from another project builds a sing-box.exe that does not
# start on a processor without AVX2.
export GOENV=off GOFIPS140=off GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0
# A replace line is a build of something else under this version's name.
! grep -Eq '^[[:space:]]*replace[[:space:](]' go.mod || { echo "tools/singbox/go.mod has a replace line: not building" >&2; exit 1; }
go mod verify >&2
# The godebug defaults are the official release's (see release/LDFLAGS).
go build -trimpath -buildvcs=false -tags "$TAGS" \
    -ldflags "-s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=$VERSION -X runtime.godebugDefault=multipathtcp=0,tlssha1=1" \
    -o "$OUT" .
echo "built sing-box $VERSION ($GOOS_/$GOARCH_, tags: ${TAGS:-none}) -> $OUT" >&2

# The bits themselves are pinned. The build is reproducible (same source, same
# Go, same flags give the same file), so anything that changes the result is
# either a change someone meant (a new sing-box, a new Go, another tag: then
# expected.sha256 changes in the same commit, where it can be read) or
# something that got in (an environment switch, a godebug line, a module
# replaced on disk). bin/SHA256SUMS could not say which: it is rewritten from
# whatever was just built. SB_NOPIN=1 skips this for an experiment; the
# release script clears it.
if [ -z "${SB_NOPIN:-}" ]; then
    got=$(shasum -a 256 "$OUT" | awk '{print $1}')
    want=$(awk -v k="$GOOS_-$GOARCH_" '$2 == k { print $1 }' expected.sha256 2>/dev/null)
    [ "$got" = "$want" ] || {
        echo "sing-box ($GOOS_/$GOARCH_) is $got, tools/singbox/expected.sha256 says ${want:-nothing}." >&2
        echo "If tools/singbox, its go.mod or the Go version was changed on purpose, put the new hash there; otherwise something else changed the build." >&2
        exit 1; }
fi
