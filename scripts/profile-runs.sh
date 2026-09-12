#!/usr/bin/env bash
# Profile helper: boot server under 'perf record', drive it with wrk, then
# SIGINT the whole group so perf finalizes and the server shuts down.
# Everything (start, load, stop, wait) happens inside this script so no
# background process outlives it.
#
# Usage: FREQ=299 DURATION=12 [WRK_ARGS...] bash scripts/profile-runs.sh
# Output: perf-data/<NAME>.data and a .report.txt next to it.
set -u

PORT="${PORT:-8094}"
NAME="${NAME:-profile}"
FREQ="${FREQ:-299}"
DURATION="${DURATION:-12}"
BIN="${BIN:-./build/bin/server}"
THREADS="${THREADS:-4}"
CONNS="${CONNS:-200}"
CALLGRAPH="${CALLGRAPH:-dwarf}"
OUT="perf-data/${NAME}.data"

mkdir -p perf-data
rm -f "$OUT"

# perf record in its own process group so a single kill -INT reaches both
# perf (finalize + write data) and the server (graceful shutdown).
setsid perf record -F "$FREQ" -g --call-graph="$CALLGRAPH" \
    --output="$OUT" -- "$BIN" "$PORT" >/tmp/perf-record.log 2>&1 &
PERF_PID=$!

URL=""
for i in $(seq 1 60); do
    if curl -s -o /dev/null -m 1 "http://127.0.0.1:$PORT/"; then
        URL="http://127.0.0.1:$PORT/"; break
    fi
    if curl -s -o /dev/null -m 1 "http://[::1]:$PORT/"; then
        URL="http://[::1]:$PORT/"; break
    fi
    sleep 0.1
done

if [ -z "$URL" ]; then
    echo "server never became ready under perf" >&2
    cat /tmp/perf-record.log >&2
    kill -9 -"$PERF_PID" 2>/dev/null || true
    exit 1
fi
echo "profiling against $URL for ${DURATION}s ..." >&2

wrk -t"$THREADS" -c"$CONNS" -d"$DURATION" --latency "$URL" 2>/dev/null | tail -n 8 >&2

# SIGINT to perf's whole group: perf writes the data file, server exits.
kill -INT -"$PERF_PID" 2>/dev/null || true

# perf needs a moment to finalize; wait up to 30s for the file to settle.
for i in $(seq 1 60); do
    kill -0 "$PERF_PID" 2>/dev/null || break
    sleep 0.5
done
if kill -0 "$PERF_PID" 2>/dev/null; then
    echo "perf did not exit; killing" >&2
    kill -9 -"$PERF_PID" 2>/dev/null || true
fi
wait "$PERF_PID" 2>/dev/null

if [ ! -s "$OUT" ]; then
    echo "no perf data written" >&2
    cat /tmp/perf-record.log >&2
    exit 1
fi

REPORT="${OUT%.data}.report.txt"
perf report --input="$OUT" --sort=dso,symbol --stdio > "$REPORT" 2>/dev/null
perf report --input="$OUT" --sort=symbol --stdio 2>/dev/null | head -n 40 >&2
echo "saved $OUT and $REPORT"
