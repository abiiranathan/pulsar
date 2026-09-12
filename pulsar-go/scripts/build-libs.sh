#!/usr/bin/env bash
# Maintainer-only rebuild of the prebuilt musl static archives checked into
# pulsar-go/lib/:
#   pulsar-go/lib/libsolidc.a  (solidc at the pinned commit, Linux source set)
#   pulsar-go/lib/libpulsar.a  (live monorepo ../src/*.c)
#
# Normal `go get` consumers never run this: the archives plus the minimal
# header snapshots under third_party/ are checked in, so `go build` works
# out of the box. Run this only when the C engine, the solidc pin, or the
# build flags change, then commit the refreshed lib/*.a, third_party/
# snapshots, and lib/.version together.
#
# Requirements: x86_64 Linux, musl-gcc, network access (solidc is fetched
# at the pinned commit into a temp dir — its sources are NOT vendored).
#
# Usage: CC=musl-gcc OPT=-O3 NUM_WORKERS=4 ./scripts/build-libs.sh
#   [--commit SHA] [--repo URL]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$GO_DIR")"
LIVE_SRC="$REPO_ROOT/src"
LIVE_INC="$REPO_ROOT/include"
LIBDIR="$GO_DIR/lib"

CC="${CC:-musl-gcc}"
NUM_WORKERS="${NUM_WORKERS:-4}"
OPT="${OPT:--O3}"

SOLIDC_REPO="${SOLIDC_REPO:-https://github.com/abiiranathan/solidc.git}"
SOLIDC_COMMIT="${SOLIDC_COMMIT:-bd515462132886b1be21ea9bca28832f191355e4}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --commit) SOLIDC_COMMIT="$2"; shift 2 ;;
        --repo) SOLIDC_REPO="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

if [[ ! -d "$LIVE_SRC" || ! -d "$LIVE_INC" ]]; then
    echo "error: live C sources not found ($LIVE_SRC). Rebuilding requires" >&2
    echo "a full monorepo checkout; 'go get' consumers already have the" >&2
    echo "checked-in archives in lib/ and must not run this script." >&2
    exit 1
fi

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "error: C compiler '$CC' not found." >&2
    echo "Install musl-tools (apt: musl-tools, apk: musl-dev)." >&2
    exit 1
fi

if [[ "$CC" != *musl* ]]; then
    echo "error: refusing to rebuild with non-musl CC='$CC'." >&2
    echo "The checked-in archives are x86_64-linux-musl only; rebuilding" >&2
    echo "with glibc gcc would ship mixed-libc objects. Use CC=musl-gcc." >&2
    exit 1
fi

mkdir -p "$LIBDIR"
OBJDIR="$(mktemp -d)"
trap 'rm -rf "$OBJDIR"' EXIT

# --- fetch solidc sources (temp only, never vendored) -----------------------
SOLIDC_SRC_DIR="$OBJDIR/solidc"
echo "==> Fetching $SOLIDC_REPO at $SOLIDC_COMMIT ..."
git clone --quiet --depth 1 "$SOLIDC_REPO" "$SOLIDC_SRC_DIR"
git -C "$SOLIDC_SRC_DIR" fetch --quiet --depth 1 origin "$SOLIDC_COMMIT"
git -C "$SOLIDC_SRC_DIR" checkout --quiet --detach "$SOLIDC_COMMIT"
VENDOR="$SOLIDC_SRC_DIR"

# musl ships no <linux/version.h> of its own and borrowing /usr/include
# wholesale mixes glibc and musl headers (their bits/ collide). Solidc only
# needs LINUX_VERSION_CODE for a copy_file_range(2) feature check (musl
# provides the wrapper since 1.2.x), so generate a minimal compat header.
# Override with MUSL_EXTRA_INCLUDES if your toolchain already provides it.
MUSL_COMPAT_INCLUDES=""
MUSL_EXTRA_INCLUDES="${MUSL_EXTRA_INCLUDES:-}"
if [[ -z "$MUSL_EXTRA_INCLUDES" ]]; then
    mkdir -p "$OBJDIR/musl-compat/linux"
    cat > "$OBJDIR/musl-compat/linux/version.h" <<'EOF'
#pragma once
/* Compat shim for musl toolchains (no kernel <linux/*> headers shipped).
 * Only what solidc's file.c feature check needs. */
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(5, 15, 0)
EOF
    # glibc exposes ino64_t/off64_t (used by solidc's getdents64 dirent);
    # musl does not (its ino_t/off_t are already 64-bit, same layout).
    # Injected only for musl builds so glibc builds never see a clash.
    cat > "$OBJDIR/musl-compat/glibc-types.h" <<'EOF'
#pragma once
#if !defined(__GLIBC__)
#include <stdint.h>
typedef uint64_t ino64_t;
typedef int64_t off64_t;
#endif
EOF
    MUSL_COMPAT_INCLUDES="-I$OBJDIR/musl-compat -include $OBJDIR/musl-compat/glibc-types.h"
fi
MUSL_INCLUDES="$MUSL_COMPAT_INCLUDES $MUSL_EXTRA_INCLUDES"

echo "==> CC=$CC OPT=$OPT NUM_WORKERS=$NUM_WORKERS"

# --- libsolidc.a: source set mirrors solidc CMakeLists (Linux branch) --------
SOLIDC_SRCS=(
    src/arena.c
    src/channels.c
    src/chan_patterns.c
    src/cstr.c
    src/csvparser.c
    src/file.c
    src/poller/poller_common.c
    src/poller/poller_epoll.c
    src/filepath/filepath.c
    src/filepath/filepath_string.c
    src/filepath/filepath_posix.c
    src/hash.c
    src/list.c
    src/lock.c
    src/map.c
    src/sort.c
    src/map_swiss.c
    src/pipeline.c
    src/process/process.c
    src/process/process_posix.c
    src/slist.c
    src/socket.c
    src/stdstreams.c
    src/str_to_num.c
    src/thread.c
    src/threadpool.c
    src/unicode.c
    src/cache.c
    src/dynarray.c
    src/dotenv.c
    src/xtime.c
    src/trie.c
    src/flags.c
    src/prettytable.c
    src/strsim.c
    deps/xxhash/xxhash.c
)

# regex.c needs libpcre2 headers and nothing pulsar links uses it, so it is
# skipped by default. Set SOLIDC_WITH_REGEX=1 plus CFLAGS_EXTRA with the
# pcre2 include path to keep it (final Go link then also needs -lpcre2-8).
if [[ "${SOLIDC_WITH_REGEX:-0}" == "1" ]]; then
    SOLIDC_SRCS+=(src/regex.c)
fi

echo "==> Compiling solidc (${#SOLIDC_SRCS[@]} files) ..."
for src in "${SOLIDC_SRCS[@]}"; do
    if [[ ! -f "$VENDOR/$src" ]]; then
        echo "error: solidc source missing at $SOLIDC_COMMIT: $src" >&2
        exit 1
    fi
    obj="$OBJDIR/solidc_$(echo "$src" | tr '/.' '__').o"
    "$CC" $OPT -std=c11 -D_GNU_SOURCE -D_USE_MATH_DEFINES -DARENA_ABORT_ON_OOM \
        -I"$VENDOR/include" -I"$VENDOR/deps/xxhash" \
        $MUSL_INCLUDES ${CFLAGS_EXTRA:-} -c "$VENDOR/$src" -o "$obj"
done
ar rcs "$LIBDIR/libsolidc.a" "$OBJDIR"/solidc_*.o
ranlib "$LIBDIR/libsolidc.a" 2>/dev/null || true

# --- libpulsar.a (live monorepo sources) --------------------------------------
echo "==> Compiling pulsar (forms.c pulsar.c routing.c, live tree) ..."
for src in forms pulsar routing; do
    if [[ ! -f "$LIVE_SRC/$src.c" ]]; then
        echo "error: missing $LIVE_SRC/$src.c" >&2
        exit 1
    fi
    "$CC" $OPT -std=c11 -D_GNU_SOURCE -DNUM_WORKERS="$NUM_WORKERS" \
        -I"$LIVE_INC" -I"$VENDOR/include" \
        $MUSL_INCLUDES ${CFLAGS_EXTRA:-} -c "$LIVE_SRC/$src.c" -o "$OBJDIR/pulsar_$src.o"
done
ar rcs "$LIBDIR/libpulsar.a" "$OBJDIR"/pulsar_*.o
ranlib "$LIBDIR/libpulsar.a" 2>/dev/null || true

# --- refresh header snapshots cgo compiles against ---------------------------
# Full pulsar public headers (small); only the solidc headers the pulsar
# headers include (see scripts note + Makefile). Both are snapshots — the
# .a files above are the real dependency.
echo "==> Refreshing third_party/ header snapshots ..."
rm -f "$GO_DIR/third_party/pulsar/include/"*.h
cp "$LIVE_INC"/*.h "$GO_DIR/third_party/pulsar/include/"
(
    src_commit="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "repo_commit: $src_commit"
    echo "synced: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
) > "$GO_DIR/third_party/pulsar/.sync"

SOLIDC_SNAP="$GO_DIR/third_party/solidc"
rm -rf "$SOLIDC_SNAP/include"
mkdir -p "$SOLIDC_SNAP/include/solidc"
for h in align arena file filepath macros platform str_slice str_to_num; do
    cp "$VENDOR/include/$h.h" "$SOLIDC_SNAP/include/solidc/$h.h"
done
cp "$VENDOR/LICENSE" "$SOLIDC_SNAP/LICENSE.solidc" 2>/dev/null || true
cat > "$SOLIDC_SNAP/.pin" <<EOF
repo: $SOLIDC_REPO
commit: $SOLIDC_COMMIT
vendored: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# --- version stamp for the checked-in archives ---------------------------------
cat > "$LIBDIR/.version" <<EOF
pulsar_commit: $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
solidc_repo: $SOLIDC_REPO
solidc_commit: $SOLIDC_COMMIT
CC: $CC
OPT: $OPT
NUM_WORKERS: $NUM_WORKERS
built: $(date -u +%Y-%m-%dT%H:%M:%SZ)
target: x86_64-linux-musl (static)
EOF

echo "==> Built:"
ls -la "$LIBDIR/libsolidc.a" "$LIBDIR/libpulsar.a"
cat "$LIBDIR/.version"
