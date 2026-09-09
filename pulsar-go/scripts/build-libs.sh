#!/usr/bin/env bash
# Build vendored static C libraries for the Go bindings:
#   pulsar-go/lib/libsolidc.a  (from third_party/solidc, Linux/musl source set
#                               mirroring solidc's CMakeLists for non-Windows)
#   pulsar-go/lib/libpulsar.a  (from ../../src/*.c, same flags as CMake Release
#                               minus -march=native so binaries stay portable)
#
# The cgo directives in pulsar.go link these archives, so no system-installed
# libpulsar or libsolidc is required and `go build` works after `go get`.
#
# Usage: CC=musl-gcc ./scripts/build-libs.sh
#   CC defaults to musl-gcc (fully static, portable binaries).
#   Use CC=gcc for a fast glibc dev loop; do NOT ship those archives.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_DIR="$(dirname "$SCRIPT_DIR")"
VENDOR="$GO_DIR/third_party/solidc"
# The C engine is vendored in-module (see scripts/sync-c.sh) so `go get`
# consumers build without the monorepo checkout.
PULSAR_SRC="$GO_DIR/third_party/pulsar/src"
PULSAR_INC="$GO_DIR/third_party/pulsar/include"
LIBDIR="$GO_DIR/lib"

CC="${CC:-musl-gcc}"
NUM_WORKERS="${NUM_WORKERS:-4}"
OPT="${OPT:--O3}"

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "error: C compiler '$CC' not found." >&2
    echo "Install musl-tools (apt: musl-tools, apk: musl-dev, brew: filosottile/musl-cross/musl-cross)." >&2
    exit 1
fi

if [[ ! -d "$VENDOR/include" || ! -d "$VENDOR/src" ]]; then
    echo "error: $VENDOR is missing. Run ./scripts/vendor.sh first." >&2
    exit 1
fi

mkdir -p "$LIBDIR"
OBJDIR="$(mktemp -d)"
trap 'rm -rf "$OBJDIR"' EXIT

# musl ships no <linux/version.h> of its own and borrowing /usr/include
# wholesale mixes glibc and musl headers (their bits/ collide). Solidc only
# needs LINUX_VERSION_CODE for a copy_file_range(2) feature check (musl
# provides the wrapper since 1.2.x), so generate a minimal compat header.
# Override with MUSL_EXTRA_INCLUDES if your toolchain already provides it.
MUSL_COMPAT_INCLUDES=""
if [[ "$CC" == *musl* ]]; then
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
else
    MUSL_EXTRA_INCLUDES="${MUSL_EXTRA_INCLUDES:-}"
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
        echo "error: vendored source missing: $VENDOR/$src" >&2
        echo "Re-run ./scripts/vendor.sh (and check the pin in third_party/solidc/.pin)." >&2
        exit 1
    fi
    obj="$OBJDIR/solidc_$(echo "$src" | tr '/.' '__').o"
    "$CC" $OPT -std=c11 -D_GNU_SOURCE -D_USE_MATH_DEFINES -DARENA_ABORT_ON_OOM \
        -I"$VENDOR/include" -I"$VENDOR/deps/xxhash" \
        $MUSL_INCLUDES ${CFLAGS_EXTRA:-} -c "$VENDOR/$src" -o "$obj"
done
ar rcs "$LIBDIR/libsolidc.a" "$OBJDIR"/solidc_*.o
ranlib "$LIBDIR/libsolidc.a" 2>/dev/null || true

# --- libpulsar.a --------------------------------------------------------------
echo "==> Compiling pulsar (forms.c pulsar.c routing.c) ..."
for src in forms pulsar routing; do
    if [[ ! -f "$PULSAR_SRC/$src.c" ]]; then
        echo "error: missing $PULSAR_SRC/$src.c. Run ./scripts/sync-c.sh (full checkout) first." >&2
        exit 1
    fi
    "$CC" $OPT -std=c11 -D_GNU_SOURCE -DNUM_WORKERS="$NUM_WORKERS" \
        -I"$PULSAR_INC" -I"$VENDOR/include" \
        $MUSL_INCLUDES ${CFLAGS_EXTRA:-} -c "$PULSAR_SRC/$src.c" -o "$OBJDIR/pulsar_$src.o"
done
ar rcs "$LIBDIR/libpulsar.a" "$OBJDIR"/pulsar_*.o
ranlib "$LIBDIR/libpulsar.a" 2>/dev/null || true

echo "==> Built:"
ls -la "$LIBDIR/libsolidc.a" "$LIBDIR/libpulsar.a"
