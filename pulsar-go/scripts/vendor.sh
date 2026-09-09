#!/usr/bin/env bash
# Vendor the solidc C dependency into pulsar-go/third_party/solidc.
#
# The Go module must be self-contained for `go get`: instead of requiring a
# system-installed libsolidc, we pin an upstream commit, clone it here, and
# prune everything except what scripts/build-libs.sh compiles
# (include/, src/, deps/xxhash/, LICENSE).
#
# Usage: ./scripts/vendor.sh [--commit SHA] [--repo URL]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_DIR="$(dirname "$SCRIPT_DIR")"
VENDOR_DIR="$GO_DIR/third_party/solidc"

SOLIDC_REPO="${SOLIDC_REPO:-https://github.com/abiiranathan/solidc.git}"
SOLIDC_COMMIT="${SOLIDC_COMMIT:-bd515462132886b1be21ea9bca28832f191355e4}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --commit) SOLIDC_COMMIT="$2"; shift 2 ;;
        --repo) SOLIDC_REPO="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

if [[ -f "$VENDOR_DIR/.pin" ]] && grep -q "$SOLIDC_COMMIT" "$VENDOR_DIR/.pin" 2>/dev/null \
    && [[ -d "$VENDOR_DIR/include" ]]; then
    echo "third_party/solidc already vendored at $SOLIDC_COMMIT, skipping."
    echo "Remove $VENDOR_DIR to re-vendor."
    exit 0
fi

rm -rf "$VENDOR_DIR"
mkdir -p "$VENDOR_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Cloning $SOLIDC_REPO at $SOLIDC_COMMIT ..."
git clone --depth 1 "$SOLIDC_REPO" "$TMP/solidc"
git -C "$TMP/solidc" fetch --depth 1 origin "$SOLIDC_COMMIT"
git -C "$TMP/solidc" checkout --detach "$SOLIDC_COMMIT"

echo "==> Pruning to shippable sources ..."
mkdir -p "$VENDOR_DIR"
cp -r "$TMP/solidc/include" "$VENDOR_DIR/include"
cp -r "$TMP/solidc/src" "$VENDOR_DIR/src"
mkdir -p "$VENDOR_DIR/deps"
cp -r "$TMP/solidc/deps/xxhash" "$VENDOR_DIR/deps/xxhash"
cp "$TMP/solidc/LICENSE" "$VENDOR_DIR/LICENSE.solidc" 2>/dev/null || true

# Drop platform backends we never compile (mirrors solidc's CMake platform
# selection for Linux/musl in scripts/build-libs.sh).
rm -f "$VENDOR_DIR/src/filepath/filepath_win32.c" \
      "$VENDOR_DIR/src/process/process_win32.c" \
      "$VENDOR_DIR/src/poller/poller_win32.c" \
      "$VENDOR_DIR/src/poller/poller_kqueue.c" \
      "$VENDOR_DIR/src/win32_dirent.c" \
      "$VENDOR_DIR/src/win_strptime.c"

cat > "$VENDOR_DIR/.pin" <<EOF
repo: $SOLIDC_REPO
commit: $SOLIDC_COMMIT
vendored: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# Pulsar includes solidc as <solidc/*.h> (installed layout) but the vendored
# tree is flat. Mirror the headers under include/solidc/ as real copies
# (not a symlink: module proxies and Windows checkouts cannot be trusted
# with symlinks). Both build-libs.sh and the cgo CFLAGS rely on this path.
rm -rf "$VENDOR_DIR/include/solidc"
mkdir -p "$VENDOR_DIR/include/solidc"
cp "$VENDOR_DIR"/include/*.h "$VENDOR_DIR/include/solidc/"

echo "==> Vendored solidc $SOLIDC_COMMIT into third_party/solidc"
find "$VENDOR_DIR" -name '*.c' | wc -l | xargs echo "    C files:"
du -sh "$VENDOR_DIR" | xargs echo "    size:"

echo "==> Syncing pulsar C engine into third_party/pulsar ..."
"$SCRIPT_DIR/sync-c.sh"

echo "==> Vendoring Go module dependencies (best-effort) ..."
if ! go mod vendor 2>&1 | tee /tmp/pulsar-govendor.log; then
    if grep -q "no dependencies to vendor" /tmp/pulsar-govendor.log; then
        echo "    (no Go dependencies to vendor yet; C deps above are the vendored set)"
    else
        exit 1
    fi
fi
