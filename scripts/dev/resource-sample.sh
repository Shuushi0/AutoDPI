#!/bin/bash
# Sample CPU and memory of every AutoDPI process for N seconds.
# Read-only (ps and top), works without root.
#
# FOOTPRINT is what Activity Monitor's "Memory" column shows (the memory a
# process really uses), read with top(1) at the end of the run. RSS also counts
# shared system libraries and clean file-backed pages, so it reads much higher.
#
#   scripts/dev/resource-sample.sh [-n SECONDS] [-i INTERVAL] [-p PID]...
#
#   -n  total sampling time in seconds (default 60)
#   -i  seconds between samples (default 2)
#   -p  sample only this process and its descendants (repeatable); without it
#       every process that looks like AutoDPI is sampled: the menu bar app,
#       `autodpi daemon|guard|ui`, sing-box and ciadpi
#
# CPU% is derived from the growth of each process's CPU time over the sample
# interval (100% = one core), so it is a real average, not ps's decayed figure.
set -u

N=60
INT=2
PIDS=()
while getopts "n:i:p:h" o; do
    case $o in
        n) N=$OPTARG ;;
        i) INT=$OPTARG ;;
        p) PIDS+=("$OPTARG") ;;
        *) sed -n '2,15p' "$0"; exit 2 ;;
    esac
done

snap() { ps -axo pid=,ppid=,rss=,time=,command= ; }

# role: classify a command line
awk_prog='
function secs(t,   a, n, s) {            # [[H:]M:]S.cc or D-HH:MM:SS
    n = split(t, a, ":"); s = 0
    for (i = 1; i <= n; i++) s = s * 60 + a[i]
    return s
}
function role(cmd) {
    if (cmd ~ /\.app\/Contents\/MacOS\/AutoDPI( |$)/) return "app"
    if (cmd ~ /autodpi[^ ]* guard /) return "guard"
    if (cmd ~ /autodpi[^ ]* daemon/) return "daemon"
    if (cmd ~ /autodpi[^ ]* ui/) return "ui"
    if (cmd ~ /\/sing-box( |$)/) return "sing-box"
    if (cmd ~ /\/ciadpi( |$)/) return "ciadpi"
    return ""
}
'

want=""
if [ ${#PIDS[@]} -gt 0 ]; then want="${PIDS[*]}"; fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/resample.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

steps=$(( N / INT )); [ "$steps" -ge 1 ] || steps=1
for ((k = 0; k <= steps; k++)); do
    snap | awk -v t="$(date +%s)" -v want="$want" "$awk_prog"'
    {
        pid = $1; ppid[pid] = $2; rss[pid] = $3; cpu[pid] = secs($4)
        cmd = $0; sub(/^ *[0-9]+ +[0-9]+ +[0-9]+ +[^ ]+ +/, "", cmd); c[pid] = cmd
        order[++cnt] = pid
    }
    END {
        nw = split(want, w, " ")
        for (i = 1; i <= nw; i++) root[w[i]] = 1
        for (i = 1; i <= cnt; i++) {
            p = order[i]; q = p; in_tree = 0
            if (nw == 0) { r = role(c[p]); in_tree = (r != "") }
            else { while (q > 1 && q != "") { if (q in root) { in_tree = 1; break } q = ppid[q] }
                   r = role(c[p]); if (r == "") r = "other" }
            if (in_tree) printf "%s %d %s %d %.2f\n", t, p, r, rss[p], cpu[p]
        }
    }' > "$TMP/s.$k"
    [ "$k" -lt "$steps" ] && sleep "$INT"
done

# footprint per pid, as top reports it (e.g. 24M, 5473K, 1.2G; +/- trend marks dropped)
for p in $(cat "$TMP"/s.* | awk '{print $2}' | sort -u); do
    top -l 1 -pid "$p" -stats pid,mem 2>/dev/null | awk -v p="$p" '$1 == p { m = $2; gsub(/[+-]$/, "", m)
        u = substr(m, length(m)); v = substr(m, 1, length(m) - 1) + 0
        if (u == "K") v /= 1024; else if (u == "G") v *= 1024; else if (u != "M") v = m / 1048576
        printf "FP %s %.1f\n", p, v }'
done > "$TMP/fp"

cat "$TMP/fp" "$TMP"/s.* | awk -v steps="$steps" '
$1 == "FP" { fp[$2] = $3; next }
{
    t = $1; pid = $2; role = $3; rss = $4; cpu = $5
    key = pid
    if (!(key in first)) { first[key] = cpu; firstT[key] = t; role_of[key] = role; order[++n] = key }
    if (key in last) {
        dt = t - lastT[key]
        if (dt > 0) { d = (cpu - last[key]) / dt * 100; if (d > peak[key]) peak[key] = d }
    }
    last[key] = cpu; lastT[key] = t
    sum[key] += rss; cnt[key]++
    if (rss > maxr[key]) maxr[key] = rss
    seen[key] = t
}
END {
    printf "%-9s %7s %10s %9s %9s %8s %8s\n", "ROLE", "PID", "FOOTPRINT", "AVG_RSS", "MAX_RSS", "AVG_CPU", "PEAK_CPU"
    tr = 0; tc = 0; tf = 0
    for (i = 1; i <= n; i++) {
        k = order[i]; span = lastT[k] - firstT[k]
        avgc = span > 0 ? (last[k] - first[k]) / span * 100 : 0
        printf "%-9s %7s %8.1fMB %7.1fMB %7.1fMB %7.2f%% %7.1f%%\n", role_of[k], k, fp[k], sum[k]/cnt[k]/1024, maxr[k]/1024, avgc, peak[k]
        tr += sum[k]/cnt[k]/1024; tc += avgc; tf += fp[k]
    }
    printf "%-9s %7s %8.1fMB %7.1fMB %9s %7.2f%%\n", "TOTAL", "", tf, tr, "", tc
}'
