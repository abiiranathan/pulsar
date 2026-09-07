#!/usr/bin/env bash
#
# bench_compare.sh — repeated wrk runs against the Pulsar server and the
# net/http baseline server, alternated to spread out systematic drift
# (thermal throttling, background load) rather than run all of one
# server then all of the other. Produces a per-run CSV and a
# mean/stdev-across-runs summary table for req/s and each latency
# percentile, which is the number that actually answers "is the gap
# real or run-to-run noise" — a single wrk invocation's own +/- Stdev
# column only describes variance *within* that one run, not between
# repeated runs.
#
# Requirements: wrk, bash >= 4 (associative arrays), awk, curl (for the
# warm-up probe and health check). Assumes both binaries are already
# built; this script only starts/stops/benchmarks/tears down.
#
# Usage:
#   ./bench_compare.sh [options]
#
# Options:
#   -p PATH      Path to the Pulsar server binary                 (required)
#   -s PATH      Path to the stdlib net/http server binary        (required)
#   -u URL       URL path both servers should be hit on           (default: http://localhost:8080/)
#   -n COUNT     Number of alternating runs per server             (default: 5)
#   -t THREADS   wrk -t value                                      (default: 4)
#   -c CONNS     wrk -c value                                      (default: 200)
#   -d DURATION  wrk -d value                                      (default: 10s)
#   -w SECONDS   Warm-up time after each server start, before wrk   (default: 2)
#   -g           Capture GODEBUG=gctrace=1 output for the stdlib runs
#   -o DIR       Output directory for logs/CSV                     (default: ./bench-results)
#
# Both servers MUST already be configured to listen on the same port
# given in -u (they are started and stopped one at a time, so a shared
# port is fine and expected). The script does not build either binary;
# build them yourself first, e.g.:
#
#   go build -o ./pulsar-server ./cmd/server
#   go build -o ./stdlib-server ./cmd/stdlib-baseline
#
# Example:
#   ./bench_compare.sh -p ./pulsar-server -s ./stdlib-server -n 5 -g

set -euo pipefail

# ---- defaults ----
PULSAR_BIN=""
STDLIB_BIN=""
URL="http://localhost:8080/"
RUNS=5
THREADS=4
CONNS=200
DURATION="10s"
WARMUP=2
CAPTURE_GC=0
OUTDIR="./bench-results"

usage() {
    grep '^#' "$0" | sed -n '2,/^$/p' | sed 's/^# \{0,1\}//'
    exit 1
}

while getopts "p:s:u:n:t:c:d:w:go:h" opt; do
    case "$opt" in
        p) PULSAR_BIN="$OPTARG" ;;
        s) STDLIB_BIN="$OPTARG" ;;
        u) URL="$OPTARG" ;;
        n) RUNS="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        c) CONNS="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        w) WARMUP="$OPTARG" ;;
        g) CAPTURE_GC=1 ;;
        o) OUTDIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$PULSAR_BIN" || -z "$STDLIB_BIN" ]]; then
    echo "error: -p and -s are required" >&2
    usage
fi
if [[ ! -x "$PULSAR_BIN" ]]; then
    echo "error: $PULSAR_BIN is not an executable file" >&2
    exit 1
fi
if [[ ! -x "$STDLIB_BIN" ]]; then
    echo "error: $STDLIB_BIN is not an executable file" >&2
    exit 1
fi
if ! command -v wrk >/dev/null 2>&1; then
    echo "error: wrk not found on PATH (install it first — e.g. 'sudo pacman -S wrk' on Arch)" >&2
    exit 1
fi

mkdir -p "$OUTDIR"
CSV="$OUTDIR/results.csv"
echo "server,run,req_per_sec,p50_ms,p75_ms,p90_ms,p99_ms,total_requests,duration_s" > "$CSV"

# ---- helpers ----

# wait_for_server PID URL — polls URL until it responds or the process
# dies, so wrk never starts against a server that hasn't finished
# binding its listener yet.
wait_for_server() {
    local pid="$1" url="$2" tries=50
    while (( tries-- > 0 )); do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "error: server process $pid exited before becoming ready" >&2
            return 1
        fi
        if curl -s -o /dev/null --max-time 1 "$url"; then
            return 0
        fi
        sleep 0.1
    done
    echo "error: server did not become ready within timeout" >&2
    return 1
}

# ms_from_wrk VALUE UNIT — wrk prints latency values with a unit suffix
# (us, ms, s) glued on; normalize everything to milliseconds as a plain
# number so the CSV and summary math stay unit-consistent.
ms_from_wrk() {
    local raw="$1"
    local num unit
    num="${raw%[a-z]*}"
    unit="${raw##*[0-9.]}"
    case "$unit" in
        us) awk -v n="$num" 'BEGIN { printf "%.4f", n / 1000 }' ;;
        ms) awk -v n="$num" 'BEGIN { printf "%.4f", n }' ;;
        s)  awk -v n="$num" 'BEGIN { printf "%.4f", n * 1000 }' ;;
        *)  echo "0" ;;
    esac
}

# run_wrk_once LABEL RUN_INDEX BIN_PATH — starts BIN_PATH, waits for it
# to come up, optionally captures gctrace, runs one wrk invocation
# against it, tears the server down, and appends one row to the CSV.
run_wrk_once() {
    local label="$1" idx="$2" bin="$3"
    local logfile="$OUTDIR/${label}-run${idx}.server.log"
    local wrkout="$OUTDIR/${label}-run${idx}.wrk.txt"

    echo "==> [$label run $idx] starting server"
    local env_prefix=""
    if [[ "$CAPTURE_GC" -eq 1 && "$label" == "stdlib" ]]; then
        env_prefix="GODEBUG=gctrace=1"
    fi

    # Start the server in the background, capturing its stdout/stderr
    # (including gctrace lines, which Go writes to stderr) to a log file
    # scoped to this specific run.
    if [[ -n "$env_prefix" ]]; then
        env $env_prefix "$bin" > "$logfile" 2>&1 &
    else
        "$bin" > "$logfile" 2>&1 &
    fi
    local pid=$!

    if ! wait_for_server "$pid" "$URL"; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        return 1
    fi

    echo "==> [$label run $idx] warming up (${WARMUP}s)"
    local warmup_end=$(( $(date +%s) + WARMUP ))
    while (( $(date +%s) < warmup_end )); do
        curl -s -o /dev/null --max-time 1 "$URL" || true
    done

    echo "==> [$label run $idx] running wrk (-t$THREADS -c$CONNS -d$DURATION)"
    wrk -t"$THREADS" -c"$CONNS" -d"$DURATION" --latency "$URL" > "$wrkout" 2>&1 || {
        echo "error: wrk failed for $label run $idx — see $wrkout" >&2
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        return 1
    }

    echo "==> [$label run $idx] stopping server"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    # Give the OS a moment to release the port before the next run starts.
    sleep 1

    # ---- parse wrk output ----
    local req_per_sec p50 p75 p90 p99 total_requests duration_s
    req_per_sec=$(awk '/^Requests\/sec:/ { print $2 }' "$wrkout")
    p50_raw=$(awk '/^ *50%/ { print $2 }' "$wrkout")
    p75_raw=$(awk '/^ *75%/ { print $2 }' "$wrkout")
    p90_raw=$(awk '/^ *90%/ { print $2 }' "$wrkout")
    p99_raw=$(awk '/^ *99%/ { print $2 }' "$wrkout")
    total_requests=$(awk '/requests in/ { print $1 }' "$wrkout")
    duration_s=$(awk '/requests in/ { gsub(/s,/, "", $4); print $4 }' "$wrkout")

    p50=$(ms_from_wrk "$p50_raw")
    p75=$(ms_from_wrk "$p75_raw")
    p90=$(ms_from_wrk "$p90_raw")
    p99=$(ms_from_wrk "$p99_raw")

    echo "$label,$idx,$req_per_sec,$p50,$p75,$p90,$p99,$total_requests,$duration_s" >> "$CSV"
    echo "==> [$label run $idx] done: ${req_per_sec} req/s, p50=${p50}ms p99=${p99}ms"
}

# ---- main: alternate pulsar / stdlib for RUNS iterations each ----
for (( i = 1; i <= RUNS; i++ )); do
    run_wrk_once "pulsar" "$i" "$PULSAR_BIN"
    run_wrk_once "stdlib" "$i" "$STDLIB_BIN"
done

echo
echo "==> all runs complete, raw results: $CSV"
echo

# ---- summary: mean and stdev across runs, per server, per metric ----
awk -F, '
NR == 1 { next }
{
    server = $1
    n[server]++
    req[server]      += $3;  req2[server]      += $3*$3
    p50[server]       += $4;  p50sq[server]     += $4*$4
    p75[server]       += $5;  p75sq[server]     += $5*$5
    p90[server]       += $6;  p90sq[server]     += $6*$6
    p99[server]       += $7;  p99sq[server]     += $7*$7
}
function stdev(sum, sumsq, count) {
    if (count < 2) return 0
    mean = sum / count
    variance = (sumsq / count) - (mean * mean)
    if (variance < 0) variance = 0
    return sqrt(variance)
}
END {
    printf "%-10s %8s %14s %14s %10s %10s %10s %10s\n", "server", "runs", "req/s (mean)", "req/s (stdev)", "p50 mean", "p75 mean", "p90 mean", "p99 mean"
    for (s in n) {
        printf "%-10s %8d %14.1f %14.1f %10.3f %10.3f %10.3f %10.3f\n", \
            s, n[s], req[s]/n[s], stdev(req[s], req2[s], n[s]), \
            p50[s]/n[s], p75[s]/n[s], p90[s]/n[s], p99[s]/n[s]
    }
}
' "$CSV" | tee "$OUTDIR/summary.txt"

echo
echo "Per-run detail: $CSV"
echo "Per-run server/wrk logs: $OUTDIR/*.log $OUTDIR/*.wrk.txt"
if [[ "$CAPTURE_GC" -eq 1 ]]; then
    echo "GC traces (stdlib only): $OUTDIR/stdlib-run*.server.log"
fi
