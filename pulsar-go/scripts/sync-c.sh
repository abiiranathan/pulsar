#!/usr/bin/env bash
# Sync the pulsar C engine (../../src, ../../include) into
# pulsar-go/third_party/pulsar so the Go module is self-contained.
#
# A `go get` consumer only receives the pulsar-go/ subtree — monorepo paths
# like ../include do not exist there. The cgo sources (bridge.c, *.go
# preambles) therefore include third_party/pulsar/include/..., and
# build-libs.sh compiles third_party/pulsar/src/*.c.
#
# In a full repo checkout this copies from the live tree and stamps .sync
# with the source commit. Inside an exported module (no ../../src) it is a
# no-op: the previously synced copy in the module zip is used as-is.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_DIR="$(dirname "$SCRIPT_DIR")"
REPO_SRC="$(dirname "$GO_DIR")/src"
REPO_INC="$(dirname "$GO_DIR")/include"
DEST="$GO_DIR/third_party/pulsar"

if [[ ! -d "$REPO_SRC" || ! -d "$REPO_INC" ]]; then
    if [[ -d "$DEST/src" && -d "$DEST/include" ]]; then
        echo "sync-c: no monorepo tree found; using in-module copy ($(cat "$DEST/.sync" 2>/dev/null || echo 'unstamped'))."
        exit 0
    fi
    echo "error: cannot find pulsar C sources ($REPO_SRC) and no in-module copy exists." >&2
    exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST/src" "$DEST/include"
cp "$REPO_SRC"/forms.c "$REPO_SRC"/pulsar.c "$REPO_SRC"/routing.c "$DEST/src/"
cp "$REPO_INC"/*.h "$DEST/include/"

(
    src_commit="$(git -C "$(dirname "$GO_DIR")" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "repo_commit: $src_commit"
    echo "synced: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
) > "$DEST/.sync"

echo "sync-c: third_party/pulsar refreshed ($(cat "$DEST/.sync" | tr '\n' ' '))"
