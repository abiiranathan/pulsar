#!/usr/bin/env bash
# Dev entry point: ensure vendored static libs are built, then run the example.
# For the full flow (static binary, tests, deploy) use the Makefile targets.
# Env: CC (default musl-gcc), PORT (default 8080).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

make -C "$SCRIPT_DIR" libs
exec env CGO_ENABLED=1 CC="${CC:-musl-gcc}" go run "$SCRIPT_DIR/cmd/server"
