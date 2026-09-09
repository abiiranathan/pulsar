#!/usr/bin/env bash
# Install the statically-linked pulsar-go server binary to $PREFIX/bin.
#
# Usage: ./scripts/deploy.sh [--prefix /usr/local] [--binary ./bin/server]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_DIR="$(dirname "$SCRIPT_DIR")"

PREFIX="/usr/local"
BIN="$GO_DIR/bin/server"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --binary) BIN="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

if [[ ! -x "$BIN" ]]; then
    echo "error: $BIN is not executable. Run 'make static' first." >&2
    exit 1
fi

# Static binaries must not carry a dynamic loader dependency.
if command -v file >/dev/null 2>&1; then
    file "$BIN"
fi
if ldd "$BIN" 2>&1 | grep -q "=>"; then
    echo "warning: $BIN looks dynamically linked (ldd shows libs); expected a static musl binary." >&2
fi

echo "==> Installing $BIN -> $PREFIX/bin/pulsar-server"
install -d "$PREFIX/bin"
install -m 755 "$BIN" "$PREFIX/bin/pulsar-server"

echo "DEPLOY DONE: $PREFIX/bin/pulsar-server"
