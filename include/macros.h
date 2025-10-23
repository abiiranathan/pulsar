#ifndef MACROS_H__
#define MACROS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Common assertion infrastructure
#define ASSERT_BASE(cond, fmt, ...)                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            printf("%s:%d [%s]: " fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__);                              \
            exit(EXIT_FAILURE);                                                                                        \
        }                                                                                                              \
    } while (0)

// Main assertion macro
#define ASSERT(cond) ASSERT_BASE(cond, "Assertion '%s' failed", #cond)

// Equality assertions
#define ASSERT_EQ(a, b)                                                                                                \
    do {                                                                                                               \
        typeof(a) _a = (a);                                                                                            \
        typeof(b) _b = (b);                                                                                            \
        ASSERT_BASE(_a == _b, "Assertion '%s == %s' failed (%ld != %ld)", #a, #b, (long)_a, (long)_b);                 \
    } while (0)

#define ASSERT_NE(a, b)                                                                                                \
    do {                                                                                                               \
        typeof(a) _a = (a);                                                                                            \
        typeof(b) _b = (b);                                                                                            \
        ASSERT_BASE(_a != _b, "Assertion '%s != %s' failed (both are %ld)", #a, #b, (long)_a);                         \
    } while (0)

// Boolean assertion
#define ASSERT_TRUE(cond) ASSERT_BASE(cond, "Assertion '%s' is not true", #cond)

// String comparison
#define ASSERT_STR_EQ(a, b)                                                                                            \
    do {                                                                                                               \
        const char* _a = (a);                                                                                          \
        const char* _b = (b);                                                                                          \
        if (_a == NULL || _b == NULL) {                                                                                \
            ASSERT_BASE(_a == _b, "Assertion '%s == %s' failed (one is NULL)", #a, #b);                                \
        } else {                                                                                                       \
            ASSERT_BASE(strcmp(_a, _b) == 0, "Assertion '%s == %s' failed (\"%s\" != \"%s\")", #a, #b, _a, _b);        \
        }                                                                                                              \
    } while (0)

#define IS_POWER_OF_2(n)     ((n) > 0 && ((n) & ((n) - 1)) == 0)
#define CHECK_POWER_OF_2(n)  static_assert(IS_POWER_OF_2(n), #n " is not a power of 2")
#define NEXT_POWER_OF_TWO(n) ((n) == 0 ? 1 : (1 << (32 - __builtin_clz((n) - 1))))
#define UNUSED(var)          ((void)var)

#if defined(__GNUC__) || defined(__clang__)
#define likely(x)     __builtin_expect(!!(x), 1)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#define INLINE        __attribute__((always_inline)) static inline
#define STATIC_INLINE INLINE static
#else
#define likely(x)   (x)
#define unlikely(x) (x)
#define INLINE
#define STATIC_INLINE
#endif

#define ALIGN_UP(size, alignment) (((size) + (alignment) - 1) & ~((alignment) - 1))

#endif  // MACROS_H__
