#!/usr/bin/env bash
# Build the C engine (CMake output lands in ../build/lib) and run the Go app.
# The cgo directives in pulsar.go already point at ../build/lib and embed an
# rpath for it, so no CGO_* overrides are needed here.
# The engine is rebuilt every time (a no-op when fresh) so the Go binding
# never picks up a stale libpulsar.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Ensuring Pulsar C engine is up to date (cmake)..."
cmake -S "$SCRIPT_DIR/.." -B "$SCRIPT_DIR/../build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$SCRIPT_DIR/../build"

exec go run "$SCRIPT_DIR/cmd/server/main.go"
