#!/usr/bin/env bash
# Bench helper: boot server, wait for readiness (v4 or v6), run wrk passes,
# report best/median. Server is always killed before exit.
set -u

PORT="${PORT:-8099}"
PASSES="${PASSES:-3}"
THREADS="${THREADS:-4}"
CONNS="${CONNS:-200}"
DURATION="${DURATION:-10s}"
BIN="${BIN:-./build/bin/server}"
URL_PATH="${URL_PATH:-/}"

SRV_PID=""
cleanup() {
    if [ -n "$SRV_PID" ]; then
        kill -INT "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

"$BIN" "$PORT" >/tmp/pulsar-bench.log 2>&1 &
SRV_PID=$!

URL=""
for i in $(seq 1 60); do
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
        echo "server died during startup" >&2
        cat /tmp/pulsar-bench.log >&2
        exit 1
    fi
    if curl -s -o /dev/null -m 1 "http://127.0.0.1:$PORT$URL_PATH"; then
        URL="http://127.0.0.1:$PORT$URL_PATH"; break
    fi
    if curl -s -o /dev/null -m 1 "http://[::1]:$PORT$URL_PATH"; then
        URL="http://[::1]:$PORT$URL_PATH"; break
    fi
    sleep 0.1
done

if [ -z "$URL" ]; then
    echo "server never became ready" >&2
    cat /tmp/pulsar-bench.log >&2
    exit 1
fi
echo "bench URL: $URL" >&2

RESULTS=()
for i in $(seq 1 "$PASSES"); do
    OUT=$(wrk -t"$THREADS" -c"$CONNS" -d"$DURATION" --latency "$URL" 2>/dev/null \
        | awk '/Requests\/sec/ {print $2}')
    if [ -z "$OUT" ]; then
        echo "wrk pass $i failed" >&2
        exit 1
    fi
    RESULTS+=("$OUT")
    echo "pass $i: $OUT req/s" >&2
done

printf '%s\n' "${RESULTS[@]}" | sort -n | awk '
    { a[NR]=$1 }
    END {
        best=a[NR]; median=a[int((NR+1)/2)];
        printf "BEST=%.0f MEDIAN=%.0f\n", best, median
    }'
