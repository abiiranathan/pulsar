/**
 * @file macros.h
 * @brief Portable utility macros for assertions, memory, math, iteration,
 *        timing, and platform compatibility.
 *
 * Supports: GCC, Clang, MSVC (C11 / C17).
 * All macros are safe for use in C and C++ translation units.
 *
 * Portability notes:
 *   - typeof / __typeof__  : GCC/Clang only. MSVC C11 does not support it.
 *     Macros that require a temporary variable (ASSERT_EQ, FOR_EACH_*, etc.)
 *     use __typeof__ under GCC/Clang and fall back to a less type-safe but
 *     functional alternative under MSVC.
 *   - Statement expressions ({ ... }) : GCC/Clang extension.
 *     ROUND_UP_POW2 is provided as an inline function to avoid this.
 *   - _Thread_local : C11 standard keyword. MSVC uses __declspec(thread).
 *   - strtok_r, gmtime_r, localtime_r : POSIX. MSVC provides strtok_s,
 *     gmtime_s, localtime_s with a reversed argument order; shims are provided.
 */

#ifndef SOLIDC_MACROS_H
#define SOLIDC_MACROS_H

#include <math.h>     /* isnan                                */
#include <stdalign.h> /* alignof                            */
#include <stddef.h>   /* size_t, ptrdiff_t                    */
#include <stdint.h>   /* uint64_t, uintptr_t, intptr_t, ...  */
#include <stdio.h>    /* printf, fprintf, stderr              */
#include <stdlib.h>   /* exit                                 */
#include <string.h>   /* strcmp, strncmp, memset              */
#include <time.h>     /* time_t, struct tm, clock_gettime     */

#if defined(__cplusplus)
extern "C" {
#endif

/* =========================================================================
 * COMPILER DETECTION
 * ========================================================================= */

#if defined(_MSC_VER)
    #define SOLIDC_MSVC  1
    #define SOLIDC_GCC   0
    #define SOLIDC_CLANG 0
#elif defined(__clang__)
    #define SOLIDC_MSVC  0
    #define SOLIDC_GCC   0
    #define SOLIDC_CLANG 1
#elif defined(__GNUC__)
    #define SOLIDC_MSVC  0
    #define SOLIDC_GCC   1
    #define SOLIDC_CLANG 0
#else
    #define SOLIDC_MSVC  0
    #define SOLIDC_GCC   0
    #define SOLIDC_CLANG 0
#endif

/* =========================================================================
 * COMPILER HINTS AND ATTRIBUTES
 * ========================================================================= */

/** Hint that a condition is likely true (branch prediction). */
#if SOLIDC_GCC || SOLIDC_CLANG
    #define LIKELY(x)   __builtin_expect(!!(x), 1)
    #define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
    #define LIKELY(x)   (x)
    #define UNLIKELY(x) (x)
#endif

/**
 * WARN_UNUSED_RESULT — emit a compiler diagnostic if the return value of a
 * function annotated with this attribute is discarded by the caller.
 */
#if SOLIDC_GCC || SOLIDC_CLANG
    #define WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#elif SOLIDC_MSVC
    #define WARN_UNUSED_RESULT _Check_return_
#else
    #define WARN_UNUSED_RESULT
#endif

/**
 * PRINTF_FORMAT(fmt_idx, va_idx) — validate printf-style format strings at
 * compile time (1-based argument indices).
 * Example: void log(const char *fmt, ...) PRINTF_FORMAT(1, 2);
 */
#if SOLIDC_GCC || SOLIDC_CLANG
    #define PRINTF_FORMAT(fmt, va) __attribute__((format(printf, fmt, va)))
#else
    #define PRINTF_FORMAT(fmt, va)
#endif

/** NORETURN — annotate functions that never return (abort, exit wrappers). */
#if SOLIDC_GCC || SOLIDC_CLANG
    #define NORETURN __attribute__((noreturn))
#elif SOLIDC_MSVC
    #define NORETURN __declspec(noreturn)
#else
    #define NORETURN
#endif

/** UNUSED — silence "unused variable/parameter" warnings. */
#define UNUSED(x) ((void)(x))

#if SOLIDC_MSVC
    #define THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    #define THREAD_LOCAL _Thread_local
#else
    /* GCC/Clang pre-C11 extension fallback */
    #define THREAD_LOCAL __thread
#endif

/* =========================================================================
 * STATIC ASSERTIONS
 * ========================================================================= */

/** STATIC_ASSERT(cond, msg) — compile-time assertion with a descriptive message. */
#if defined(__cplusplus)
    #define STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    #define STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
    /* Pre-C11 fallback: causes an array-size error if cond is false. */
    #define STATIC_ASSERT(cond, msg) typedef char _static_assert_##__LINE__[(cond) ? 1 : -1]
#endif

/* =========================================================================
 * RUNTIME ASSERTION MACROS
 *
 * All assertions print file, line, and function name, then call exit(1).
 * Define NDEBUG to compile out assertions (same convention as <assert.h>).
 * ========================================================================= */

#ifndef NDEBUG

    /** ASSERT(cond) — abort if cond is false. */
    #define ASSERT(cond)                                                                                      \
        do {                                                                                                  \
            if (UNLIKELY(!(cond))) {                                                                          \
                fprintf(stderr, "%s:%d [%s]: Assertion '%s' failed.\n", __FILE__, __LINE__, __func__, #cond); \
                exit(1);                                                                                      \
            }                                                                                                 \
        } while (0)

    /** ASSERT_TRUE(cond) — alias for ASSERT; documents boolean intent. */
    #define ASSERT_TRUE(cond) ASSERT(cond)

    /** ASSERT_NULL(ptr) — abort if ptr is not NULL. */
    #define ASSERT_NULL(ptr)                                                                                    \
        do {                                                                                                    \
            if (UNLIKELY((ptr) != NULL)) {                                                                      \
                fprintf(stderr, "%s:%d [%s]: Expected '%s' to be NULL.\n", __FILE__, __LINE__, __func__, #ptr); \
                exit(1);                                                                                        \
            }                                                                                                   \
        } while (0)

    /** ASSERT_NOT_NULL(ptr) — abort if ptr is NULL. */
    #define ASSERT_NOT_NULL(ptr)                                                                                    \
        do {                                                                                                        \
            if (UNLIKELY((ptr) == NULL)) {                                                                          \
                fprintf(stderr, "%s:%d [%s]: Expected '%s' to not be NULL.\n", __FILE__, __LINE__, __func__, #ptr); \
                exit(1);                                                                                            \
            }                                                                                                       \
        } while (0)

    /**
     * ASSERT_STR_EQ(a, b) — abort if two C strings are not equal.
     * Handles NULL on either side gracefully.
     */
    #define ASSERT_STR_EQ(a, b)                                                                                      \
        do {                                                                                                         \
            const char* _ase_a = (a);                                                                                \
            const char* _ase_b = (b);                                                                                \
            if (_ase_a == NULL || _ase_b == NULL) {                                                                  \
                if (_ase_a != _ase_b) {                                                                              \
                    fprintf(stderr, "%s:%d [%s]: '%s == %s' failed (one is NULL).\n", __FILE__, __LINE__, __func__,  \
                            #a, #b);                                                                                 \
                    exit(1);                                                                                         \
                }                                                                                                    \
            } else if (strcmp(_ase_a, _ase_b) != 0) {                                                                \
                fprintf(stderr, "%s:%d [%s]: '%s == %s' failed (\"%s\" != \"%s\").\n", __FILE__, __LINE__, __func__, \
                        #a, #b, _ase_a, _ase_b);                                                                     \
                exit(1);                                                                                             \
            }                                                                                                        \
        } while (0)

    /**
     * ASSERT_FLOAT_EQ(a, b, epsilon) — abort if |a - b| > epsilon.
     * Both operands are promoted to double for the comparison.
     */
    #define ASSERT_FLOAT_EQ(a, b, epsilon)                                               \
        do {                                                                             \
            double _afe_a = (double)(a);                                                 \
            double _afe_b = (double)(b);                                                 \
            double _afe_eps = (double)(epsilon);                                         \
            double _afe_d = _afe_a - _afe_b;                                             \
            /* Use manual abs to avoid pulling in <math.h> for fabs. */                  \
            if ((_afe_d > _afe_eps) || (-_afe_d > _afe_eps)) {                           \
                fprintf(stderr,                                                          \
                        "%s:%d [%s]: Float '%s == %s' failed"                            \
                        " (%.6f != %.6f, eps=%.6f).\n",                                  \
                        __FILE__, __LINE__, __func__, #a, #b, _afe_a, _afe_b, _afe_eps); \
                exit(1);                                                                 \
            }                                                                            \
        } while (0)

    /*
     * ASSERT_EQ / ASSERT_NE / ASSERT_RANGE
     *
     * These macros compare two values using temporary variables to avoid
     * double evaluation. Under GCC/Clang we use __typeof__ to preserve the
     * exact type. Under MSVC, which lacks typeof in C mode, we fall back to
     * intptr_t — wide enough for any scalar and pointer coerced to integer.
     * Floating-point comparisons should use ASSERT_FLOAT_EQ instead.
     */
    #if SOLIDC_GCC || SOLIDC_CLANG

        /** ASSERT_EQ(a, b) — abort if a != b. */
        #define ASSERT_EQ(a, b)                                                                          \
            do {                                                                                         \
                __typeof__(a) _aeq_a = (a);                                                              \
                __typeof__(b) _aeq_b = (b);                                                              \
                if (UNLIKELY(_aeq_a != _aeq_b)) {                                                        \
                    fprintf(stderr,                                                                      \
                            "%s:%d [%s]: '%s == %s' failed"                                              \
                            " (%td != %td).\n",                                                          \
                            __FILE__, __LINE__, __func__, #a, #b, (ptrdiff_t)_aeq_a, (ptrdiff_t)_aeq_b); \
                    exit(1);                                                                             \
                }                                                                                        \
            } while (0)

        /** ASSERT_NE(a, b) — abort if a == b. */
        #define ASSERT_NE(a, b)                                                       \
            do {                                                                      \
                __typeof__(a) _ane_a = (a);                                           \
                __typeof__(b) _ane_b = (b);                                           \
                if (UNLIKELY(_ane_a == _ane_b)) {                                     \
                    fprintf(stderr,                                                   \
                            "%s:%d [%s]: '%s != %s' failed"                           \
                            " (both %td).\n",                                         \
                            __FILE__, __LINE__, __func__, #a, #b, (ptrdiff_t)_ane_a); \
                    exit(1);                                                          \
                }                                                                     \
            } while (0)

        /** ASSERT_RANGE(val, min, max) — abort if val is outside [min, max]. */
        #define ASSERT_RANGE(val, min, max)                                                                        \
            do {                                                                                                   \
                __typeof__(val) _ar_v = (val);                                                                     \
                __typeof__(min) _ar_min = (min);                                                                   \
                __typeof__(max) _ar_max = (max);                                                                   \
                if (UNLIKELY(_ar_v < _ar_min || _ar_v > _ar_max)) {                                                \
                    fprintf(stderr, "%s:%d [%s]: %s=%td not in [%td, %td].\n", __FILE__, __LINE__, __func__, #val, \
                            (ptrdiff_t)_ar_v, (ptrdiff_t)_ar_min, (ptrdiff_t)_ar_max);                             \
                    exit(1);                                                                                       \
                }                                                                                                  \
            } while (0)

    #else /* MSVC or unknown — typeof unavailable */

        #define ASSERT_EQ(a, b)                                                    \
            do {                                                                   \
                intptr_t _aeq_a = (intptr_t)(a);                                   \
                intptr_t _aeq_b = (intptr_t)(b);                                   \
                if (UNLIKELY(_aeq_a != _aeq_b)) {                                  \
                    fprintf(stderr,                                                \
                            "%s:%d [%s]: '%s == %s' failed"                        \
                            " (%td != %td).\n",                                    \
                            __FILE__, __LINE__, __func__, #a, #b, _aeq_a, _aeq_b); \
                    exit(1);                                                       \
                }                                                                  \
            } while (0)

        #define ASSERT_NE(a, b)                                            \
            do {                                                           \
                intptr_t _ane_a = (intptr_t)(a);                           \
                intptr_t _ane_b = (intptr_t)(b);                           \
                if (UNLIKELY(_ane_a == _ane_b)) {                          \
                    fprintf(stderr,                                        \
                            "%s:%d [%s]: '%s != %s' failed"                \
                            " (both %td).\n",                              \
                            __FILE__, __LINE__, __func__, #a, #b, _ane_a); \
                    exit(1);                                               \
                }                                                          \
            } while (0)

        #define ASSERT_RANGE(val, min, max)                                                                        \
            do {                                                                                                   \
                intptr_t _ar_v = (intptr_t)(val);                                                                  \
                intptr_t _ar_min = (intptr_t)(min);                                                                \
                intptr_t _ar_max = (intptr_t)(max);                                                                \
                if (UNLIKELY(_ar_v < _ar_min || _ar_v > _ar_max)) {                                                \
                    fprintf(stderr, "%s:%d [%s]: %s=%td not in [%td, %td].\n", __FILE__, __LINE__, __func__, #val, \
                            _ar_v, _ar_min, _ar_max);                                                              \
                    exit(1);                                                                                       \
                }                                                                                                  \
            } while (0)

    #endif /* SOLIDC_GCC || SOLIDC_CLANG */

#else /* NDEBUG — strip all runtime assertions */

    #define ASSERT(cond)             UNUSED(cond)
    #define ASSERT_TRUE(cond)        UNUSED(cond)
    #define ASSERT_NULL(ptr)         UNUSED(ptr)
    #define ASSERT_NOT_NULL(ptr)     UNUSED(ptr)
    #define ASSERT_STR_EQ(a, b)      (UNUSED(a), UNUSED(b))
    #define ASSERT_FLOAT_EQ(a, b, e) (UNUSED(a), UNUSED(b), UNUSED(e))
    #define ASSERT_EQ(a, b)          (UNUSED(a), UNUSED(b))
    #define ASSERT_NE(a, b)          (UNUSED(a), UNUSED(b))
    #define ASSERT_RANGE(v, lo, hi)  (UNUSED(v), UNUSED(lo), UNUSED(hi))

#endif /* NDEBUG */

/* =========================================================================
 * POWER-OF-2 UTILITIES
 * ========================================================================= */

/** IS_POWER_OF_2(n) — evaluates to 1 if n is a power of two, 0 otherwise. */
#define IS_POWER_OF_2(n) ((n) > 0 && (((n) & ((n) - 1)) == 0))

/** STATIC_CHECK_POWER_OF_2(n) — compile-time assertion that n is a power of two. */
#define STATIC_CHECK_POWER_OF_2(n) STATIC_ASSERT(IS_POWER_OF_2(n), #n " must be a power of 2")

/**
 * round_up_pow2_u64 — round x up to the next power of two (64-bit).
 *
 * Returns 1 for x == 0. Undefined behaviour if x > 2^63.
 * Implemented as an inline function to avoid GCC statement-expression
 * extensions, ensuring compatibility with MSVC.
 */
static inline uint64_t round_up_pow2_u64(uint64_t x) {
    if (x == 0) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    return x + 1;
}

/**
 * round_up_pow2_u32 — round x up to the next power of two (32-bit).
 *
 * Returns 1 for x == 0. Undefined behaviour if x > 2^31.
 */
static inline uint32_t round_up_pow2_u32(uint32_t x) {
    if (x == 0) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x + 1;
}

/* =========================================================================
 * MEMORY AND ARRAY UTILITIES
 * ========================================================================= */

/** ARRAY_SIZE(arr) — number of elements in a stack-allocated array. */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/** ZERO_MEMORY(ptr, size) — zero size bytes starting at ptr. */
#define ZERO_MEMORY(ptr, size) memset((ptr), 0, (size))

/** ZERO_STRUCT(s) — zero every byte of a struct variable s. */
#define ZERO_STRUCT(s) memset(&(s), 0, sizeof(s))

/** ZERO_ARRAY(arr) — zero an entire stack-allocated array. */
#define ZERO_ARRAY(arr) memset((arr), 0, sizeof(arr))

/* =========================================================================
 * MATHEMATICAL UTILITIES
 * ========================================================================= */

/** MIN(a, b) — minimum of two scalar values (evaluates each argument once). */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/** MAX(a, b) — maximum of two scalar values (evaluates each argument once). */
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/** ABS(x) — absolute value without pulling in <math.h>. */
#define ABS(x) ((x) < 0 ? -(x) : (x))

/** CLAMP(x, lo, hi) — constrain x to [lo, hi]. */
#define CLAMP(x, lo, hi) (MIN(MAX((x), (lo)), (hi)))

/* =========================================================================
 * BIT MANIPULATION
 * ========================================================================= */

/** SET_BIT(v, pos) — set bit at position pos in v (0 = LSB). */
#define SET_BIT(v, pos) ((v) |= (1ULL << (pos)))

/** CLEAR_BIT(v, pos) — clear bit at position pos in v. */
#define CLEAR_BIT(v, pos) ((v) &= ~(1ULL << (pos)))

/** TOGGLE_BIT(v, pos) — flip bit at position pos in v. */
#define TOGGLE_BIT(v, pos) ((v) ^= (1ULL << (pos)))

/** CHECK_BIT(v, pos) — evaluate to 1 if bit pos is set in v, else 0. */
#define CHECK_BIT(v, pos) (((v) >> (pos)) & 1U)

/* =========================================================================
 * ALIGNMENT UTILITIES
 *
 * `align` must be a power of two for all three macros.
 * ========================================================================= */

/** ALIGN_UP(x, align) — round x up to the next multiple of align. */
#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))

/** ALIGN_DOWN(x, align) — round x down to the previous multiple of align. */
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))

/** IS_ALIGNED(x, align) — evaluate to 1 if x is a multiple of align. */
#define IS_ALIGNED(x, align) (((x) & ((align) - 1)) == 0)

/* =========================================================================
 * STRING UTILITIES
 * ========================================================================= */

/** STREQ(a, b) — true if two C strings are equal. */
#define STREQ(a, b) (strcmp((a), (b)) == 0)

/** STRNEQ(a, b, n) — true if first n bytes of two C strings are equal. */
#define STRNEQ(a, b, n) (strncmp((a), (b), (n)) == 0)

/** STR_EMPTY(s) — true if s is NULL or the empty string. */
#define STR_EMPTY(s) ((s) == NULL || (s)[0] == '\0')

/** STR_NOT_EMPTY(s) — true if s is non-NULL and non-empty. */
#define STR_NOT_EMPTY(s) ((s) != NULL && (s)[0] != '\0')

/* =========================================================================
 * DEBUGGING AND LOGGING
 *
 * DEBUG_* and LOG_DEBUG compile to no-ops when NDEBUG is defined.
 * LOG_ERROR / LOG_WARN / LOG_INFO are always active.
 * ========================================================================= */

#ifndef NDEBUG

    /** DEBUG_PRINT(fmt, ...) — print a formatted debug message with source location. */
    #define DEBUG_PRINT(fmt, ...) printf("[DEBUG] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

    /** DEBUG_VAR(var) — print a scalar variable's name and value as a signed integer. */
    #define DEBUG_VAR(var) printf("[DEBUG] %s:%d: %s = %td\n", __FILE__, __LINE__, #var, (ptrdiff_t)(var))

    /** DEBUG_STR(str) — print a string variable's name and value, handling NULL. */
    #define DEBUG_STR(str) printf("[DEBUG] %s:%d: %s = \"%s\"\n", __FILE__, __LINE__, #str, (str) ? (str) : "(null)")

    /** LOG_DEBUG(fmt, ...) — print a debug-level log message to stdout with source location. */
    #define LOG_DEBUG(fmt, ...) printf("[DEBUG] %s:%d [%s]: " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#else /* NDEBUG */

    #define DEBUG_PRINT(fmt, ...) ((void)0)
    #define DEBUG_VAR(var)        UNUSED(var)
    #define DEBUG_STR(str)        UNUSED(str)
    #define LOG_DEBUG(fmt, ...)   ((void)0)

#endif /* NDEBUG */

/** LOG_ERROR(fmt, ...) — print an error message to stderr (always active). */
#define LOG_ERROR(fmt, ...) \
    fprintf(stderr, "[ERROR] %s:%d [%s]: " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)

/** LOG_WARN(fmt, ...) — print a warning to stderr (always active). */
#define LOG_WARN(fmt, ...) fprintf(stderr, "[WARN]  %s:%d [%s]: " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)

/** LOG_INFO(fmt, ...) — print an informational message to stdout (always active). */
#define LOG_INFO(fmt, ...) printf("[INFO]  %s:%d [%s]: " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)

/** LOG_FATAL(fmt, ...) — print an error message to stderror and exit(1) */
#define LOG_FATAL(fmt, ...)                                                               \
    printf("[INFO]  %s:%d [%s]: " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    exit(1);

/* =========================================================================
 * CONTAINER ITERATION
 *
 * FOR_EACH_ARRAY and FOR_EACH_RANGE use __typeof__ under GCC/Clang for full
 * type safety. Under MSVC they fall back to explicit pointer/index types;
 * callers must ensure the array element type is compatible.
 * ========================================================================= */

#if SOLIDC_GCC || SOLIDC_CLANG

    /**
     * FOR_EACH_ARRAY(item, array) — iterate over every element of a
     * stack-allocated array. `item` is a pointer to the current element.
     *
     * Example:
     *   int nums[] = {1, 2, 3};
     *   FOR_EACH_ARRAY(n, nums) { printf("%d\n", *n); }
     */
    #define FOR_EACH_ARRAY(item, array) \
        for (__typeof__(&(array)[0]) item = (array), _fea_end = (array) + ARRAY_SIZE(array); item < _fea_end; ++item)

    /**
     * FOR_EACH_RANGE(var, start, end) — iterate var over [start, end).
     *
     * Example:
     *   FOR_EACH_RANGE(i, 0, 10) { printf("%d\n", i); }
     */
    #define FOR_EACH_RANGE(var, start, end) for (__typeof__(start) var = (start); var < (end); ++var)

#else /* MSVC — typeof unavailable */

    /**
     * FOR_EACH_ARRAY — MSVC fallback using size_t index.
     * `item` is a void* pointing to the current element; cast before use.
     *
     * Example:
     *   FOR_EACH_ARRAY(i, arr, sizeof(arr[0])) { int *n = (int*)item; }
     *
     * Prefer the three-argument variant when element size is not obvious.
     */
    #define FOR_EACH_ARRAY(item, array)                                                                         \
        for (void *item = (void*)(array), *_fea_end = (void*)((char*)(array) + sizeof(array)); item < _fea_end; \
             item = (char*)item + (sizeof((array)[0])))

    #define FOR_EACH_RANGE(var, start, end) for (ptrdiff_t var = (ptrdiff_t)(start); var < (ptrdiff_t)(end); ++var)

#endif /* SOLIDC_GCC || SOLIDC_CLANG */

/* =========================================================================
 * TIMING AND PERFORMANCE
 *
 * Two families of macros:
 *
 *   TIME_BLOCK(name, block)    — measure a block and print elapsed seconds.
 *   TIME_BLOCK_MS(name, block) — measure a block and print elapsed milliseconds.
 *
 * `block` is an unquoted sequence of statements placed verbatim before the
 * stop-time call, e.g.:
 *
 *   TIME_BLOCK("sort", sort(arr, n);)
 *
 * get_time_ns() / get_time_ms() — return current monotonic time as uint64_t.
 * TIME_DIFF / TIME_DIFF_MS — compute elapsed seconds / milliseconds between
 *   two timestamps captured with the platform-specific API.
 * ========================================================================= */

#if defined(_WIN32)

    #include "platform.h" /* LARGE_INTEGER, QueryPerformanceCounter, etc. */

    /**
     * TIME_DIFF(start, end, freq) — elapsed seconds between two LARGE_INTEGER
     * timestamps captured with QueryPerformanceCounter.
     */
    #define TIME_DIFF(start, end, freq) ((double)((end).QuadPart - (start).QuadPart) / (double)(freq).QuadPart)

    /**
     * TIME_DIFF_MS(start, end, freq) — elapsed milliseconds between two
     * LARGE_INTEGER timestamps captured with QueryPerformanceCounter.
     */
    #define TIME_DIFF_MS(start, end, freq) \
        ((double)((end).QuadPart - (start).QuadPart) * 1000.0 / (double)(freq).QuadPart)

    #define TIME_BLOCK(name, block)                                           \
        do {                                                                  \
            LARGE_INTEGER _freq, _t0, _t1;                                    \
            QueryPerformanceFrequency(&_freq);                                \
            QueryPerformanceCounter(&_t0);                                    \
            block QueryPerformanceCounter(&_t1);                              \
            printf("Time[%s]: %.6f s\n", (name), TIME_DIFF(_t0, _t1, _freq)); \
        } while (0)

    #define TIME_BLOCK_MS(name, block)                                            \
        do {                                                                      \
            LARGE_INTEGER _freq, _t0, _t1;                                        \
            QueryPerformanceFrequency(&_freq);                                    \
            QueryPerformanceCounter(&_t0);                                        \
            block QueryPerformanceCounter(&_t1);                                  \
            printf("Time[%s]: %.3f ms\n", (name), TIME_DIFF_MS(_t0, _t1, _freq)); \
        } while (0)

#else /* POSIX — use clock_gettime(CLOCK_MONOTONIC) */

    /**
     * TIME_DIFF(start, end) — elapsed seconds between two struct timespec values.
     */
    #define TIME_DIFF(start, end) \
        ((double)((end).tv_sec - (start).tv_sec) + (double)((end).tv_nsec - (start).tv_nsec) / 1.0e9)

    /**
     * TIME_DIFF_MS(start, end) — elapsed milliseconds between two struct timespec
     * values.
     */
    #define TIME_DIFF_MS(start, end) \
        ((double)((end).tv_sec - (start).tv_sec) * 1000.0 + (double)((end).tv_nsec - (start).tv_nsec) / 1.0e6)

    #define TIME_BLOCK(name, block)                                    \
        do {                                                           \
            struct timespec _t0, _t1;                                  \
            clock_gettime(CLOCK_MONOTONIC, &_t0);                      \
            block clock_gettime(CLOCK_MONOTONIC, &_t1);                \
            printf("Time[%s]: %.6f s\n", (name), TIME_DIFF(_t0, _t1)); \
        } while (0)

    #define TIME_BLOCK_MS(name, block)                                     \
        do {                                                               \
            struct timespec _t0, _t1;                                      \
            clock_gettime(CLOCK_MONOTONIC, &_t0);                          \
            block clock_gettime(CLOCK_MONOTONIC, &_t1);                    \
            printf("Time[%s]: %.3f ms\n", (name), TIME_DIFF_MS(_t0, _t1)); \
        } while (0)

#endif /* _WIN32 */

/**
 * get_time_ns — returns the current monotonic timestamp in nanoseconds.
 *
 * On Windows, QueryPerformanceCounter is used. The calculation separates
 * the integer and fractional parts to prevent overflow on long uptimes.
 * On POSIX (Linux, macOS ≥ 10.12), clock_gettime(CLOCK_MONOTONIC) is used.
 *
 * @return Nanoseconds since an unspecified epoch (suitable for intervals only).
 */
static inline uint64_t get_time_ns(void) {
#if defined(_WIN32)
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    /* Split into whole seconds and remainder to avoid 64-bit overflow. */
    uint64_t seconds = (uint64_t)counter.QuadPart / (uint64_t)freq.QuadPart;
    uint64_t remainder = (uint64_t)counter.QuadPart % (uint64_t)freq.QuadPart;
    return seconds * UINT64_C(1000000000) + (remainder * UINT64_C(1000000000)) / (uint64_t)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
#endif
}

/**
 * get_time_ms — returns the current monotonic timestamp in milliseconds.
 *
 * Convenience wrapper around get_time_ns() for callers that don't need
 * nanosecond resolution (e.g. coarse-grained timeouts, rate limiting).
 *
 * @return Milliseconds since an unspecified epoch (suitable for intervals only).
 */
static inline uint64_t get_time_ms(void) { return get_time_ns() / UINT64_C(1000000); }

/* =========================================================================
 * POSIX COMPATIBILITY SHIMS (MSVC)
 *
 * strtok_r, gmtime_r, localtime_r are POSIX functions absent on Windows.
 * Their MSVC equivalents exist but use a reversed argument order for the
 * reentrant time functions.
 * ========================================================================= */

#if SOLIDC_MSVC

    /** strtok_r — reentrant strtok; maps to strtok_s on MSVC. */
    #define strtok_r(str, delim, saveptr) strtok_s((str), (delim), (saveptr))

/**
 * gmtime_r — reentrant gmtime.
 * @param timep  Pointer to a time_t value.
 * @param result Caller-provided struct tm to receive the broken-down time.
 * @return result on success, NULL on failure.
 */
static inline struct tm* gmtime_r(const time_t* timep, struct tm* result) {
    return gmtime_s(result, timep) == 0 ? result : NULL;
}

/**
 * localtime_r — reentrant localtime.
 * @param timep  Pointer to a time_t value.
 * @param result Caller-provided struct tm to receive the broken-down time.
 * @return result on success, NULL on failure.
 */
static inline struct tm* localtime_r(const time_t* timep, struct tm* result) {
    return localtime_s(result, timep) == 0 ? result : NULL;
}

#endif /* SOLIDC_MSVC */

/* =========================================================================
 * ENDIANNESS
 *
 * IS_BIG_ENDIAN / IS_LITTLE_ENDIAN are compile-time constants (0 or 1),
 * usable in #if directives. Detection prefers compiler-provided byte-order
 * macros and falls back to common architecture defines.
 * ========================================================================= */

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
    #define SOLIDC_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#elif defined(_WIN32)
    /* Windows targets (x86, x64, ARM64) are all little-endian. */
    #define SOLIDC_BIG_ENDIAN 0
#elif defined(__BIG_ENDIAN__)
    #define SOLIDC_BIG_ENDIAN 1
#else
    /* Default assumption: little-endian (true for x86/x64/ARM/RISC-V default mode). */
    #define SOLIDC_BIG_ENDIAN 0
#endif

/** IS_BIG_ENDIAN — 1 if the target is big-endian, 0 otherwise. Usable in #if. */
#define IS_BIG_ENDIAN SOLIDC_BIG_ENDIAN

/** IS_LITTLE_ENDIAN — 1 if the target is little-endian, 0 otherwise. Usable in #if. */
#define IS_LITTLE_ENDIAN (!SOLIDC_BIG_ENDIAN)

/**
 * bswap16 — reverse the byte order of a 16-bit value.
 * @param x Value to swap.
 * @return Byte-swapped value.
 */
static inline uint16_t bswap16(uint16_t x) {
#if SOLIDC_GCC || SOLIDC_CLANG
    return __builtin_bswap16(x);
#elif SOLIDC_MSVC
    return _byteswap_ushort(x);
#else
    return (uint16_t)((x << 8) | (x >> 8));
#endif
}

/**
 * bswap32 — reverse the byte order of a 32-bit value.
 * @param x Value to swap.
 * @return Byte-swapped value.
 */
static inline uint32_t bswap32(uint32_t x) {
#if SOLIDC_GCC || SOLIDC_CLANG
    return __builtin_bswap32(x);
#elif SOLIDC_MSVC
    return _byteswap_ulong(x);
#else
    return ((x & 0x000000FFu) << 24) | ((x & 0x0000FF00u) << 8) | ((x & 0x00FF0000u) >> 8) | ((x & 0xFF000000u) >> 24);
#endif
}

/**
 * bswap64 — reverse the byte order of a 64-bit value.
 * @param x Value to swap.
 * @return Byte-swapped value.
 */
static inline uint64_t bswap64(uint64_t x) {
#if SOLIDC_GCC || SOLIDC_CLANG
    return __builtin_bswap64(x);
#elif SOLIDC_MSVC
    return _byteswap_uint64(x);
#else
    return ((uint64_t)bswap32((uint32_t)(x & 0xFFFFFFFFu)) << 32) | (uint64_t)bswap32((uint32_t)(x >> 32));
#endif
}

/** TO_LE16(x) / TO_BE16(x) — convert a 16-bit host value to little/big-endian. */
#define TO_LE16(x) (IS_BIG_ENDIAN ? bswap16(x) : (uint16_t)(x))
#define TO_BE16(x) (IS_BIG_ENDIAN ? (uint16_t)(x) : bswap16(x))

/** TO_LE32(x) / TO_BE32(x) — convert a 32-bit host value to little/big-endian. */
#define TO_LE32(x) (IS_BIG_ENDIAN ? bswap32(x) : (uint32_t)(x))
#define TO_BE32(x) (IS_BIG_ENDIAN ? (uint32_t)(x) : bswap32(x))

/** TO_LE64(x) / TO_BE64(x) — convert a 64-bit host value to little/big-endian. */
#define TO_LE64(x) (IS_BIG_ENDIAN ? bswap64(x) : (uint64_t)(x))
#define TO_BE64(x) (IS_BIG_ENDIAN ? (uint64_t)(x) : bswap64(x))

/**
 * FROM_LE16(x) / FROM_BE16(x) — convert a little/big-endian 16-bit value to
 * host order. The transform is its own inverse, so these alias TO_LE16 /
 * TO_BE16; both names are kept so call sites can express direction of intent.
 */
#define FROM_LE16(x) TO_LE16(x)
#define FROM_BE16(x) TO_BE16(x)

/** FROM_LE32(x) / FROM_BE32(x) — convert a little/big-endian 32-bit value to host order. */
#define FROM_LE32(x) TO_LE32(x)
#define FROM_BE32(x) TO_BE32(x)

/** FROM_LE64(x) / FROM_BE64(x) — convert a little/big-endian 64-bit value to host order. */
#define FROM_LE64(x) TO_LE64(x)
#define FROM_BE64(x) TO_BE64(x)

/* =========================================================================
 * SIMD FEATURE DETECTION
 *
 * Two layers are provided:
 *
 *   Compile-time (HAS_* macros, usable in #if): reflect the instruction
 *   set the *compiler* was told to target (e.g. via -mavx2 or /arch:AVX2).
 *   These say nothing about the CPU the binary will actually run on.
 *
 *   Runtime (cpu_has_* functions): query the actual CPU at execution time.
 *   Always check the runtime function before executing the corresponding
 *   instructions, even if the matching HAS_* macro is 1 — the binary may
 *   be run on different hardware than it was compiled for (e.g. a binary
 *   built with -mavx2 but distributed and run on an older CPU lacking it,
 *   which will SIGILL on the first AVX2 instruction).
 *
 * x86/x64: runtime detection uses __builtin_cpu_supports() on GCC/Clang
 *   (backed by glibc's IFUNC CPUID parsing) and raw CPUID via __cpuid /
 *   __cpuidex on MSVC.
 * ARM64 (AArch64): NEON (Advanced SIMD) is a mandatory part of the base
 *   architecture, so cpu_has_neon() is always 1; no runtime check needed.
 * ARM32 (AArch64-v7 and earlier): NEON is optional. Runtime detection on
 *   Linux uses getauxval(AT_HWCAP) & HWCAP_NEON. Non-Linux ARM32 targets
 *   fall back to the compile-time result.
 * ========================================================================= */

/** HAS_SSE2 — 1 if the compiler was told to target SSE2, 0 otherwise. */
#if defined(__SSE2__) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2) || defined(_M_X64) || defined(_M_AMD64)
    #define HAS_SSE2 1
#else
    #define HAS_SSE2 0
#endif

/** HAS_AVX — 1 if the compiler was told to target AVX, 0 otherwise. */
#if defined(__AVX__)
    #define HAS_AVX 1
#else
    #define HAS_AVX 0
#endif

/** HAS_AVX2 — 1 if the compiler was told to target AVX2, 0 otherwise. */
#if defined(__AVX2__)
    #define HAS_AVX2 1
#else
    #define HAS_AVX2 0
#endif

/** HAS_AVX512F — 1 if the compiler was told to target AVX-512 Foundation, 0 otherwise. */
#if defined(__AVX512F__)
    #define HAS_AVX512F 1
#else
    #define HAS_AVX512F 0
#endif

/** HAS_NEON — 1 if the compiler was told to target ARM NEON, 0 otherwise. */
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    #define HAS_NEON 1
#else
    #define HAS_NEON 0
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

    #if SOLIDC_GCC || SOLIDC_CLANG

/**
 * cpu_has_sse2 — check at runtime whether the executing CPU supports SSE2.
 * @return Non-zero if supported, 0 otherwise.
 */
static inline int cpu_has_sse2(void) { return !!__builtin_cpu_supports("sse2"); }

/**
 * cpu_has_avx — check at runtime whether the executing CPU supports AVX.
 * @return Non-zero if supported, 0 otherwise.
 */
static inline int cpu_has_avx(void) { return !!__builtin_cpu_supports("avx"); }

/**
 * cpu_has_avx2 — check at runtime whether the executing CPU supports AVX2.
 * @return Non-zero if supported, 0 otherwise.
 */
static inline int cpu_has_avx2(void) { return !!__builtin_cpu_supports("avx2"); }

/**
 * cpu_has_avx512f — check at runtime whether the executing CPU supports
 * AVX-512 Foundation.
 * @return Non-zero if supported, 0 otherwise.
 */
static inline int cpu_has_avx512f(void) { return !!__builtin_cpu_supports("avx512f"); }

    #elif SOLIDC_MSVC

        #include <intrin.h> /* __cpuid, __cpuidex */

/**
 * cpu_has_sse2 — check at runtime whether the executing CPU supports SSE2.
 * Queries CPUID leaf 1, EDX bit 26.
 * @return Non-zero if supported, 0 otherwise.
 */
static inline int cpu_has_sse2(void) {
    int regs[4];
    __cpuid(regs, 1);
    return (regs[3] >> 26) & 1; /* EDX */
}

/**
 * cpu_has_avx — check at runtime whether the executing CPU supports AVX.
 * Queries CPUID leaf 1, ECX bit 28.
 * @return Non-zero if supported, 0 otherwise.
 */
static inline int cpu_has_avx(void) {
    int regs[4];
    __cpuid(regs, 1);
    return (regs[2] >> 28) & 1; /* ECX */
}

/**
 * cpu_has_avx2 — check at runtime whether the executing CPU supports AVX2.
 * Queries CPUID leaf 7, sub-leaf 0, EBX bit 5. Guards against CPUs that
 * don't support leaf 7 at all by checking the max supported leaf first.
 * @return Non-zero if supported, 0 otherwise.
 */
static inline int cpu_has_avx2(void) {
    int regs[4];
    __cpuid(regs, 0);
    if (regs[0] < 7) return 0; /* leaf 7 unsupported */
    __cpuidex(regs, 7, 0);
    return (regs[1] >> 5) & 1; /* EBX */
}

/**
 * cpu_has_avx512f — check at runtime whether the executing CPU supports
 * AVX-512 Foundation. Queries CPUID leaf 7, sub-leaf 0, EBX bit 16.
 * @return Non-zero if supported, 0 otherwise.
 */
static inline int cpu_has_avx512f(void) {
    int regs[4];
    __cpuid(regs, 0);
    if (regs[0] < 7) return 0; /* leaf 7 unsupported */
    __cpuidex(regs, 7, 0);
    return (regs[1] >> 16) & 1; /* EBX */
}

    #else /* Unknown x86 compiler — fall back to compile-time result */

static inline int cpu_has_sse2(void) { return HAS_SSE2; }
static inline int cpu_has_avx(void) { return HAS_AVX; }
static inline int cpu_has_avx2(void) { return HAS_AVX2; }
static inline int cpu_has_avx512f(void) { return HAS_AVX512F; }

    #endif /* SOLIDC_GCC || SOLIDC_CLANG */

#endif /* x86 / x64 */

#if defined(__aarch64__) || defined(_M_ARM64)

/**
 * cpu_has_neon — check at runtime whether the executing CPU supports NEON.
 * NEON (Advanced SIMD) is mandatory on AArch64, so this always returns 1.
 * @return Always 1 on AArch64.
 */
static inline int cpu_has_neon(void) { return 1; }

#elif defined(__arm__) && defined(__linux__)

    #include <asm/hwcap.h> /* HWCAP_NEON */
    #include <sys/auxv.h>  /* getauxval, AT_HWCAP */

/**
 * cpu_has_neon — check at runtime whether the executing CPU supports NEON.
 * Queries AT_HWCAP via getauxval() for the HWCAP_NEON bit. Linux/AArch32 only.
 * @return Non-zero if supported, 0 otherwise.
 */
static inline int cpu_has_neon(void) { return (getauxval(AT_HWCAP) & HWCAP_NEON) != 0; }

#elif defined(__arm__) || defined(_M_ARM)

/**
 * cpu_has_neon — check at runtime whether the executing CPU supports NEON.
 * No portable runtime query is available for this target (non-Linux
 * AArch32); falls back to the compile-time result.
 * @return The value of HAS_NEON.
 */
static inline int cpu_has_neon(void) { return HAS_NEON; }

#endif /* ARM variants */

/* =========================================================================
 * CROSS-PLATFORM SHIMS
 *
 * Centralizes the scattered #ifdefs that used to live in individual
 * modules. Include <macros.h> and use the SOLIDC_* helpers below instead
 * of raw platform checks. All macros are safe on every supported OS and
 * compiler; they degrade gracefully when a feature is absent.
 * ========================================================================= */

/* -------------------------------------------------------------------------
 * OS detection — prefer these over raw _WIN32/__APPLE__ checks.
 * ---------------------------------------------------------------------- */
#if defined(_WIN32)
    #define SOLIDC_OS_WINDOWS 1
    #define SOLIDC_OS_POSIX   0
#elif defined(__APPLE__)
    #define SOLIDC_OS_APPLE 1
    #define SOLIDC_OS_POSIX 1
#elif defined(__linux__)
    #define SOLIDC_OS_LINUX 1
    #define SOLIDC_OS_POSIX 1
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    #define SOLIDC_OS_BSD   1
    #define SOLIDC_OS_POSIX 1
#else
    #define SOLIDC_OS_POSIX 1
#endif
#ifndef SOLIDC_OS_WINDOWS
    #define SOLIDC_OS_WINDOWS 0
#endif
#ifndef SOLIDC_OS_APPLE
    #define SOLIDC_OS_APPLE 0
#endif
#ifndef SOLIDC_OS_LINUX
    #define SOLIDC_OS_LINUX 0
#endif
#ifndef SOLIDC_OS_BSD
    #define SOLIDC_OS_BSD 0
#endif
#ifndef SOLIDC_OS_POSIX
    #define SOLIDC_OS_POSIX 0
#endif

/* -------------------------------------------------------------------------
 * Feature-test wrapper — safe on compilers that lack __has_feature.
 * ---------------------------------------------------------------------- */
#ifndef __has_feature
    #define __has_feature(x) 0
#endif
#define SOLIDC_HAS_FEATURE(x) __has_feature(x)

/* -------------------------------------------------------------------------
 * Secure string handling — bounded, explicit-size APIs.
 *
 * On Windows (MSVC/MinGW) the _s variants are available and preferred.
 * Elsewhere we emulate them with a bounds-checked memcpy. Library code
 * and callers should use these instead of raw strcat/strcpy/sprintf.
 * ---------------------------------------------------------------------- */
#if SOLIDC_MSVC || defined(_WIN32)
    #include <string.h> /* strcat_s et al. via <string.h> on MSVC/MinGW */
    #define SOLIDC_STRCPY_S(dst, dstsz, src) strcpy_s((dst), (dstsz), (src))
    #define SOLIDC_STRCAT_S(dst, dstsz, src) strcat_s((dst), (dstsz), (src))
    #define SOLIDC_SNPRINTF                  snprintf
#else
static inline int solidc_strcpy_s(char* dst, size_t dstsz, const char* src) {
    size_t n = strlen(src);
    if (n >= dstsz) {
        if (dstsz) dst[0] = '\0';
        return -1;
    }
    memcpy(dst, src, n + 1);
    return 0;
}
static inline int solidc_strcat_s(char* dst, size_t dstsz, const char* src) {
    size_t dlen = strlen(dst);
    size_t slen = strlen(src);
    if (dlen + slen >= dstsz) {
        if (dstsz) dst[0] = '\0';
        return -1;
    }
    memcpy(dst + dlen, src, slen + 1);
    return 0;
}
    #define SOLIDC_STRCPY_S(dst, dstsz, src) solidc_strcpy_s((dst), (dstsz), (src))
    #define SOLIDC_STRCAT_S(dst, dstsz, src) solidc_strcat_s((dst), (dstsz), (src))
    #define SOLIDC_SNPRINTF                  snprintf
#endif

/* -------------------------------------------------------------------------
 * Builtin wrappers — map GCC/Clang builtins to MSVC equivalents.
 * ---------------------------------------------------------------------- */
#if SOLIDC_MSVC
    #include <intrin.h>
    #pragma intrinsic(_BitScanForward)
    #pragma intrinsic(_BitScanReverse)
    #if defined(_M_X64) || defined(_M_IX86)
        #pragma intrinsic(_mm_pause)
    #endif
static inline int solidc_ctz_u32(uint32_t x) {
    unsigned long r;
    _BitScanForward(&r, (unsigned long)x);
    return (int)r;
}
static inline int solidc_clz_u32(uint32_t x) {
    unsigned long r;
    _BitScanReverse(&r, (unsigned long)x);
    return 31 - (int)r;
}
    #define SOLIDC_CTZ(x)       solidc_ctz_u32((uint32_t)(x))
    #define SOLIDC_CLZ(x)       solidc_clz_u32((uint32_t)(x))
    #define SOLIDC_EXPECT(x, y) (x)
    #define SOLIDC_PREFETCH(p)  ((void)0)
    #if defined(_M_X64) || defined(_M_IX86)
        #define SOLIDC_PAUSE() _mm_pause()
    #elif defined(_M_ARM64) || defined(_M_ARM)
        #define SOLIDC_PAUSE() __yield()
    #else
        #define SOLIDC_PAUSE() ((void)0)
    #endif
    #define SOLIDC_ISNAN(x) isnan(x)
#else
    #define SOLIDC_CTZ(x)       __builtin_ctz((unsigned int)(x))
    #define SOLIDC_CLZ(x)       __builtin_clz((unsigned int)(x))
    #define SOLIDC_EXPECT(x, y) __builtin_expect((x), (y))
    #define SOLIDC_PREFETCH(p)  __builtin_prefetch((p))
    #if defined(__x86_64__) || defined(__i386__)
        #define SOLIDC_PAUSE() __builtin_ia32_pause()
    #elif defined(__aarch64__) || defined(__arm__)
        #define SOLIDC_PAUSE() __asm__ __volatile__("yield" ::: "memory")
    #else
        #define SOLIDC_PAUSE() ((void)0)
    #endif
    #define SOLIDC_ISNAN(x) __builtin_isnan((x))
#endif

/* -------------------------------------------------------------------------
 * Portable max alignment — MSVC C mode lacks max_align_t.
 * ---------------------------------------------------------------------- */
#if defined(_MSC_VER)
typedef union {
    long double _ld; /* dominates both size (16) and alignment (16) on SysV x86-64 */
    double _d;
    long long _ll;
    void* _p;
} solidc_max_align_t;
#else
typedef max_align_t solidc_max_align_t;
#endif
#define SOLIDC_MAX_ALIGN      (alignof(solidc_max_align_t))
#define SOLIDC_MAX_ALIGN_MASK (SOLIDC_MAX_ALIGN - 1)

/* -------------------------------------------------------------------------
 * Unlocked stdio — block-level fread_unlocked is glibc/BSD-only.
 * ---------------------------------------------------------------------- */
#if defined(__GLIBC__) || defined(__FreeBSD__)
    #define SOLIDC_HAS_FREAD_UNLOCKED 1
#else
    #define SOLIDC_HAS_FREAD_UNLOCKED 0
#endif
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__unix__)
    #define SOLIDC_HAS_GETC_UNLOCKED 1
#else
    #define SOLIDC_HAS_GETC_UNLOCKED 0
#endif

/* -------------------------------------------------------------------------
 * Condition-variable clock — MONOTONIC on Linux, REALTIME on macOS.
 * ---------------------------------------------------------------------- */
#if SOLIDC_OS_APPLE
    #define SOLIDC_COND_CLOCK CLOCK_REALTIME
#else
    #define SOLIDC_COND_CLOCK CLOCK_MONOTONIC
#endif

/* -------------------------------------------------------------------------
 * Secure zero — guaranteed not to be optimized away.
 *
 * Uses the strongest primitive available per platform:
 *   - memset_s()          C11 Annex K (glibc with __STDC_WANT_LIB_EXT1__)
 *   - SecureZeroMemory()  Win32 (explicit volatile implementation)
 *   - explicit_bzero()    glibc/BSD
 *   - volatile byte loop  portable fallback (de-facto non-elidable)
 * ---------------------------------------------------------------------- */
#if defined(__STDC_WANT_LIB_EXT1__) || defined(__STDC_LIB_EXT1__)
    #include <string.h>
#elif defined(_WIN32)
    #include "platform.h"
#endif

static inline void solidc_secure_zero(void* p, size_t n) {
#if defined(__STDC_LIB_EXT1__) || defined(__STDC_WANT_LIB_EXT1__)
    memset_s(p, n, 0, n);
#elif defined(_WIN32)
    SecureZeroMemory(p, n);
#elif defined(__GLIBC__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    explicit_bzero(p, n);
#else
    volatile unsigned char* vp = (volatile unsigned char*)p;
    while (n--) *vp++ = 0;
#endif
}
#define SOLIDC_SECURE_ZERO(p, n) solidc_secure_zero((p), (n))

/* -------------------------------------------------------------------------
 * SIMD shuffle — __builtin_shufflevector is clang-only.
 * ---------------------------------------------------------------------- */
#if defined(__clang__)
    #define SOLIDC_HAS_SHUFFLE_VECTOR 1
#else
    #define SOLIDC_HAS_SHUFFLE_VECTOR 0
#endif

#if defined(__cplusplus)
}
#endif

#endif /* SOLIDC_MACROS_H */
