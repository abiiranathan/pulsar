#!/usr/bin/env bash
set -euo pipefail

DATA="${1:-./perf-data/perf.data}"
OUT="${OUT:-${DATA}.report.txt}"

if [[ ! -f "$DATA" ]]; then
    echo "error: perf data not found: $DATA" >&2
    echo "hint: run ./scripts/record.sh ./build/bin/server" >&2
    exit 1
fi

printf 'Generating perf report from %s\n' "$DATA"
perf report --input="$DATA" --sort=comm,dso,symbol --stdio > "$OUT"
printf 'Saved report to %s\n' "$OUT"