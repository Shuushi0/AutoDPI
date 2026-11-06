#!/bin/bash
# Time-boxed, system-wide trial with the real TUN. Runs the daemon in the
# foreground for N seconds, then it shuts itself down and the network is back to
# normal. Nothing is installed. Needs sudo and no VPN (WARP) connected.
#
#   scripts/dev/trial.sh [dist/autodpi] [3m]
#
# From a second terminal while it runs:
#   dist/autodpi status | list | log | test discord.com --all
set -u
cd "$(dirname "$0")/../.."
BIN=${1:-dist/autodpi}
DUR=${2:-3m}

[ -x "$BIN" ] || { echo "$BIN missing; run scripts/build.sh first" >&2; exit 1; }
if warp-cli status 2>/dev/null | grep -q 'Connected'; then
    echo "Cloudflare WARP is connected. Two tunnels get in each other's way: turn WARP off first." >&2
    exit 1
fi
echo "Trial: $DUR. Then the daemon stops by itself and the network is as before."
echo "In an emergency: Ctrl-C or scripts/restore-network.sh"
exec sudo "$BIN" daemon --for "$DUR" -v
