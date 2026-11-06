#!/bin/bash
# End-to-end on the real network with no TUN and no root: the daemon runs with
# --test-port, which swaps the system capture for a loopback proxy running the
# very same rules. Needs no VPN/WARP connected. Usage: scripts/dev/e2e-notun.sh
cd "$(dirname "$0")/../.."
SP=$(mktemp -d)
go build -o "$SP/autodpi" ./cmd/autodpi || exit 1
MAD=$SP/autodpi
# Short path on purpose: unix socket paths are limited to 104 bytes. The CLI
# speaks English whatever the system's language, so the greps below match.
export AUTODPI_HOME=/tmp/mad-home AUTODPI_BINDIR=$PWD/bin AUTODPI_LANG=en
PORT=21999

if warp-cli status 2>&1 | grep -q 'Connected'; then echo "WARP connected - abort"; exit 3; fi
rm -rf $AUTODPI_HOME; mkdir -p $AUTODPI_HOME

$MAD daemon --test-port $PORT -v --for 140s > $SP/e2e-daemon.log 2>&1 &
DPID=$!
trap 'kill $DPID 2>/dev/null; sleep 4; rm -rf $AUTODPI_HOME $SP' EXIT

for i in $(seq 1 50); do nc -z 127.0.0.1 $PORT 2>/dev/null && break; sleep 0.2; done
nc -z 127.0.0.1 $PORT || { echo "sing-box test inbound never came up"; tail -20 $SP/e2e-daemon.log; exit 1; }
sleep 3   # let the ASN lookup finish and the network settle

ip_of() { curl -s -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$1&type=A" | python3 -c 'import sys,json; print([a["data"] for a in json.load(sys.stdin)["Answer"] if a["type"]==1][0])'; }
fetch() { # host: one line, with curl's own error when it failed (a timeout after the headers still says http 200)
  local ip w rc err; ip=$(ip_of "$1"); err=$(mktemp)
  w=$(curl -sS -o /dev/null -m 15 -w 'http %{http_code} in %{time_total}s' \
    --socks5 127.0.0.1:$PORT --resolve "$1:443:$ip" "https://$1/" 2>"$err"); rc=$?
  if [ $rc -eq 0 ]; then
    echo "  $1 -> $w (ip $ip)"
  else
    echo "  $1 -> FAILED, curl exit $rc: $(tr '\n' ' ' < "$err")($w, ip $ip)"
  fi
  rm -f "$err"
  return $rc
}
counters() { $MAD status | grep -E '^(Observer|List):'; }
observed() { grep -c "msg=observed sni=$1 " $SP/e2e-daemon.log; } # the observer logs every flow it handles (-v)

echo "=== 0. start state"; $MAD status | head -3
echo "=== 1. fresh home: nothing listed yet"; $MAD list

echo "=== 2. control: unblocked site through the proxy"; fetch www.google.com; counters

echo "=== 3. blocked + unlisted: first connection must open via the observer"; fetch discord.com; counters
echo "   observer events:"; grep -E 'observed' $SP/e2e-daemon.log | tail -3 | cut -c1-260

echo "=== 4. wait for validation + listing"
for i in $(seq 1 30); do $MAD list 2>/dev/null | grep -q 'discord.com' && break; sleep 1; done
$MAD list | grep -E 'DOMAIN|discord' || echo "   FAILED: discord.com was not listed"
$MAD log -n 8

echo "=== 5. listed now: next connection should bypass the observer entirely"
sleep 2; before=$(observed discord.com)
fetch discord.com
sleep 1; after=$(observed discord.com)
if [ "$before" = "$after" ]; then
  echo "   observer flows for discord.com: $before before, $after after: went straight to the engine"
else
  echo "   FAILED: observer flows for discord.com: $before before, $after after: it went through the observer"
fi

echo "=== 6. test command (all engines)"; $MAD test gateway.discord.gg --all
