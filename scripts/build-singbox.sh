#!/bin/bash
# Build a slim sing-box from the official source, pinned through the Go module
# system, instead of using the full release binary (84 MB: tailscale, openvpn,
# openconnect, cloudflared, acme, clash api, naive, ...).
#
#   scripts/build-singbox.sh <goos> <goarch> <output file>
#
# The version is the sing-box requirement in tools/singbox/go.mod; go.sum next
# to it pins every dependency's hash, `go mod verify` re-checks the module
# cache against it, and -mod=readonly stops the build from changing either
# (a hash not in go.sum is checked against sum.golang.org by `go get`, never
# silently trusted). To move to another version: cd tools/singbox &&
# go get -tool github.com/sagernet/sing-box/cmd/sing-box@vX.Y.Z && go mod tidy,
# then update SB_VERSION and the checksums in scripts/fetch-bins*.sh.
#
# Build tags (SB_TAGS overrides this list; sing-box 1.14.4 has no tag for the
# many protocol stubs registered unconditionally in include/registry.go, so
# the binary stays ~37 MB, not smaller):
#   with_gvisor     the TUN stack. Our TUN inbound leaves `stack` unset, which is
#                   "mixed" (system TCP + gVisor UDP) only when gVisor is built
#                   in; without it sing-box silently falls back to "system".
#                   Kept so the TUN behaves exactly as with the release binary
#                   (+4 MB). WireGuard's userspace netstack needs it as well.
#   with_wireguard  the optional `warp` engine (WireGuard endpoint), +0.8 MB.
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
export GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=$GOOS_ GOARCH=$GOARCH_
go mod verify >&2
# The godebug defaults are the official release's (see release/LDFLAGS).
go build -trimpath -buildvcs=false -tags "$TAGS" \
    -ldflags "-s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=$VERSION -X runtime.godebugDefault=multipathtcp=0,tlssha1=1" \
    -o "$OUT" github.com/sagernet/sing-box/cmd/sing-box
echo "built sing-box $VERSION ($GOOS_/$GOARCH_, tags: ${TAGS:-none}) -> $OUT" >&2
