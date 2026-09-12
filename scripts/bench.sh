#!/usr/bin/env bash
set -euo pipefail

URL="${URL:-http://127.0.0.1:8080/}"
THREADS="${THREADS:-4}"
CONNS="${CONNS:-200}"
DURATION="${DURATION:-10s}"

if ! command -v wrk >/dev/null 2>&1; then
    echo "error: wrk is required but not found on PATH" >&2
    exit 1
fi

printf 'Running wrk: URL=%s threads=%s conns=%s duration=%s\n' "$URL" "$THREADS" "$CONNS" "$DURATION"
wrk -t"$THREADS" -c"$CONNS" -d"$DURATION" --latency "$URL"