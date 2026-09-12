#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./build/bin/server}"
shift || true
OUT_DIR="${OUT_DIR:-./perf-data}"
OUTPUT="${OUTPUT:-${OUT_DIR}/perf.data}"

if ! command -v perf >/dev/null 2>&1; then
    echo "error: perf is required but not found on PATH" >&2
    exit 1
fi

if [[ ! -x "$BIN" ]]; then
    echo "error: binary not executable: $BIN" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
printf 'Recording perf data for %s to %s\n' "$BIN" "$OUTPUT"
perf record -F 99 -g --call-graph=dwarf --output="$OUTPUT" -- "$BIN" "$@"