#!/bin/bash
# Interleaved A/B latency benchmark: does AutoDPI add milliseconds?
# The link (a phone hotspot) jitters by hundreds of ms, so the two paths are
# measured alternately, request by request, and compared by median.
#
#   scripts/dev/bench.sh socks PORT [rounds]   A = direct, B = through a --test-port daemon
#                                              (sing-box rules + observer, no TUN, no root)
#   scripts/dev/bench.sh tun [rounds]          A = bound to the physical interface (skips
#                                              the TUN), B = default route (through the TUN);
#                                              run while scripts/dev/trial.sh is active
# Downloads ~1 MB per throughput sample (set MB=0 to skip).
set -u
MODE=${1:?socks PORT | tun}
if [ "$MODE" = socks ]; then PORT=${2:?port}; ROUNDS=${3:-15}; else ROUNDS=${2:-15}; fi
MB=${MB:-1}
IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

ip_of() { curl -s --interface "$IFACE" -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$1&type=A" |
  python3 -c 'import sys,json; print([a["data"] for a in json.load(sys.stdin)["Answer"] if a["type"]==1][0])'; }

# one request: path target url -> "path target connect tls ttfb total code"
req() {
  local path=$1 name=$2 host=$3 url=$4 ip=$5 extra=()
  case "$MODE:$path" in
    socks:A) extra=(--resolve "$host:443:$ip") ;;
    socks:B) extra=(--socks5 "127.0.0.1:$PORT" --resolve "$host:443:$ip") ;;
    tun:A)   extra=(--interface "$IFACE") ;;
    tun:B)   extra=(-q) ;;
  esac
  curl -s -o /dev/null -m 15 "${extra[@]}" \
    -w "$path $name %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{http_code} %{speed_download}\n" "$url" >>"$OUT" 2>/dev/null ||
    echo "$path $name 0 0 0 0 000 0" >>"$OUT"
}

TARGETS=(
  "google www.google.com https://www.google.com/generate_204"
  "cloudflare www.cloudflare.com https://www.cloudflare.com/cdn-cgi/trace"
  "discord discord.com https://discord.com/api/v9/gateway"
)
# bash 3.2 (macOS) has no associative arrays: one variable per target
for t in "${TARGETS[@]}"; do set -- $t; eval "IP_$1=\$(ip_of $2)"; done
[ "$MB" != 0 ] && IP_dl=$(ip_of speed.cloudflare.com)

echo "mode=$MODE rounds=$ROUNDS iface=$IFACE"
for ((r = 1; r <= ROUNDS; r++)); do
  for t in "${TARGETS[@]}"; do
    set -- $t
    if ((r % 2)); then order="A B"; else order="B A"; fi # alternate who goes first
    eval "ip=\$IP_$1"
    for p in $order; do req "$p" "$1" "$2" "$3" "$ip"; done
  done
  if [ "$MB" != 0 ] && ((r % 5 == 0)); then
    for p in A B; do req "$p" dl speed.cloudflare.com "https://speed.cloudflare.com/__down?bytes=$((MB * 1000000))" "$IP_dl"; done
  fi
  printf '.'
done
echo

python3 - "$OUT" <<'EOF'
import sys, statistics as st
rows = [l.split() for l in open(sys.argv[1])]
def med(xs): return st.median(xs) if xs else float('nan')
print(f"{'target':<11}{'path':<5}{'ok':>6}  {'connect':>8}{'tls':>8}{'ttfb':>8}{'total':>8}  (median ms)")
for name in dict.fromkeys(r[1] for r in rows):
    for path in "AB":
        rs = [r for r in rows if r[0] == path and r[1] == name]
        ok = [r for r in rs if r[6] not in ("000",)]
        if name == "dl":
            sp = [float(r[7]) * 8 / 1e6 for r in ok]
            print(f"{name:<11}{path:<5}{len(ok):>3}/{len(rs):<2}  throughput median {med(sp):.1f} Mbit/s")
            continue
        c, t, f, tot = ([float(r[i]) * 1000 for r in ok] for i in (2, 3, 4, 5))
        print(f"{name:<11}{path:<5}{len(ok):>3}/{len(rs):<2}  {med(c):8.0f}{med(t):8.0f}{med(f):8.0f}{med(tot):8.0f}")
EOF
