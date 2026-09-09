#ifndef SOLIDC_TYPES_H
#define SOLIDC_TYPES_H

#include <stdbool.h>  // bool (C99+)
#include <stddef.h>   // size_t, ptrdiff_t
#include <stdint.h>   // intN_t, uintN_t

// Types for C STDC_VERSION  from C89 to C23.
#define C_VERSION_89 (198900L)  // C89/C90 (same value for both)
#define C_VERSION_99 (199901L)  // C99
#define C_VERSION_11 (201112L)  // C11
#define C_VERSION_17 (201710L)  // C17 (technically a bugfix release, but often treated as a separate version)
#define C_VERSION_23 (202311L)  // C23

// Check for C11 compiler support.
#if defined(__STDC_VERSION__) && __STDC_VERSION__ < 201112L
    #error "solidc requires a C11-compliant compiler"
#endif

// ── Detect compiler / platform ───────────────────────────────────────────────
// Used to gate features that are not available on all compilers (e.g. atomics on MSVC).
#if defined(_MSC_VER)
    #define SOLIDC_MSVC
#elif defined(__GNUC__) || defined(__clang__)
    #define SOLIDC_GCC_LIKE
#endif

// ── Signed integers ──────────────────────────────────────────────────────────
#ifndef i8
/** 8-bit signed integer (-128 to 127) */
typedef int8_t i8;
#endif
#ifndef i16
/** 16-bit signed integer (-32,768 to 32,767) */
typedef int16_t i16;
#endif
#ifndef i32
/** 32-bit signed integer (-2,147,483,648 to 2,147,483,647) */
typedef int32_t i32;
#endif
#ifndef i64
/** 64-bit signed integer (-9,223,372,036,854,775,808 to 9,223,372,036,854,775,807) */
typedef int64_t i64;
#endif

// ── Unsigned integers ────────────────────────────────────────────────────────
#ifndef u8
/** 8-bit unsigned integer (0 to 255) */
typedef uint8_t u8;
#endif
#ifndef u16
/** 16-bit unsigned integer (0 to 65,535) */
typedef uint16_t u16;
#endif
#ifndef u32
/** 32-bit unsigned integer (0 to 4,294,967,295) */
typedef uint32_t u32;
#endif
#ifndef u64
/** 64-bit unsigned integer (0 to 18,446,744,073,709,551,615) */
typedef uint64_t u64;
#endif

// ── Floating point ───────────────────────────────────────────────────────────
// Mirrors the integer naming convention; makes numeric code more consistent.
#ifndef f32
/** 32-bit IEEE 754 float (~7 significant decimal digits) */
typedef float f32;
#endif
#ifndef f64
/** 64-bit IEEE 754 double (~15 significant decimal digits) */
typedef double f64;
#endif

// ── Platform-sized types ─────────────────────────────────────────────────────
// These match the natural word size of the target — use them for array lengths,
// memory sizes, and pointer arithmetic instead of assuming int/long widths.
#ifndef usize
/** Unsigned, sizeof-compatible; equivalent to Rust's usize. Use for array lengths and memory sizes. */
typedef size_t usize;
#endif
#ifndef isize
/** Signed counterpart to usize; safe for pointer differences. */
typedef ptrdiff_t isize;
#endif
#ifndef iptr
/** Signed integer wide enough to hold a pointer value. */
typedef intptr_t iptr;
#endif
#ifndef uptr
/** Unsigned integer wide enough to hold a pointer value. */
typedef uintptr_t uptr;
#endif

// ── Byte alias ───────────────────────────────────────────────────────────────
#ifndef byte
/** Raw memory byte. Semantically distinct from u8: use for buffers, use u8 for numeric 8-bit values. */
typedef uint8_t byte;
#endif

// ── Atomic variants ──────────────────────────────────────────────────────────
// Gated behind C11 and a non-MSVC check:
// out entirely (useful for embedded or C99 targets).
// Check SOLIDC_HAS_ATOMICS in downstream code instead of repeating this guard.
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(SOLIDC_NO_ATOMICS)
    #include <stdatomic.h>
    #ifndef atomic_i32
/** Atomic 32-bit signed integer (C11 only). */
typedef _Atomic(i32) atomic_i32;
    #endif
    #ifndef atomic_u32
/** Atomic 32-bit unsigned integer (C11 only). */
typedef _Atomic(u32) atomic_u32;
    #endif
    #ifndef atomic_i64
/** Atomic 64-bit signed integer (C11 only). */
typedef _Atomic(i64) atomic_i64;
    #endif
    #ifndef atomic_u64
/** Atomic 64-bit unsigned integer (C11 only). */
typedef _Atomic(u64) atomic_u64;
    #endif

    #define SOLIDC_HAS_ATOMICS 1
#else
    #define SOLIDC_HAS_ATOMICS 0
#endif

// ── Compile-time width checks ────────────────────────────────────────────────
// Zero runtime cost. Catches platforms where float/double/pointer sizes deviate
// from the expected layout (e.g. some DSPs or exotic embedded targets).
// Guarded so the file stays valid on C99, where _Static_assert does not exist.
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(i8) == 1, "i8 must be 1 byte");
_Static_assert(sizeof(i16) == 2, "i16 must be 2 bytes");
_Static_assert(sizeof(i32) == 4, "i32 must be 4 bytes");
_Static_assert(sizeof(i64) == 8, "i64 must be 8 bytes");
_Static_assert(sizeof(f32) == 4, "f32 must be 4 bytes");
_Static_assert(sizeof(f64) == 8, "f64 must be 8 bytes");
_Static_assert(sizeof(usize) == sizeof(void*), "usize must match pointer width");
_Static_assert(sizeof(isize) == sizeof(void*), "isize must match pointer width");
#endif

#endif  // SOLIDC_TYPES_H
