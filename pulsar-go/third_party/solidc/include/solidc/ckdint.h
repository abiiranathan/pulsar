/**
 * @file ckdint.h
 * @brief Checked integer arithmetic to prevent overflow.
 */

#ifndef SOLIDC_CKDINT_H
#define SOLIDC_CKDINT_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Detect if the compiler supports GCC/Clang style built-in overflow checks.
 * GCC 5+ and Clang 3.8+ support these.
 */
#if defined(__has_builtin)
    #if __has_builtin(__builtin_add_overflow)
        #define SOLIDC_USE_BUILTINS
    #endif
#elif defined(__GNUC__) && (__GNUC__ >= 5)
    #define SOLIDC_USE_BUILTINS
#endif

#ifdef SOLIDC_USE_BUILTINS

    /*
     * Generic Macros: These work for int, long, size_t, etc.
     * Returns true (1) if overflow occurred, false (0) otherwise.
     */
    #define ckd_add(r, a, b) __builtin_add_overflow((a), (b), (r))
    #define ckd_sub(r, a, b) __builtin_sub_overflow((a), (b), (r))
    #define ckd_mul(r, a, b) __builtin_mul_overflow((a), (b), (r))

#else

/*
 * Fallback (MSVC / ANSI C):
 * Portable implementations for size_t (unsigned arithmetic).
 */

static inline bool ckd_add(size_t* r, size_t a, size_t b) {
    *r = a + b;
    return *r < a;
}

static inline bool ckd_sub(size_t* r, size_t a, size_t b) {
    *r = a - b;
    return *r > a;
}

static inline bool ckd_mul(size_t* r, size_t a, size_t b) {
    if (a == 0 || b == 0) {
        *r = 0;
        return false;
    }
    *r = a * b;
    return (*r / a) != b;
}

#endif /* SOLIDC_USE_BUILTINS */

#undef SOLIDC_USE_BUILTINS

#endif /* SOLIDC_CKDINT_H */
