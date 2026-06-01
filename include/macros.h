#ifndef __PULSAR_MACROS_H__
#define __PULSAR_MACROS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK_POWER_OF_2(n)  static_assert(IS_POWER_OF_2(n), #n " is not a power of 2")
#define NEXT_POWER_OF_TWO(n) ((n) == 0 ? 1 : (1 << (32 - __builtin_clz((n) - 1))))

#if defined(__GNUC__) || defined(__clang__)
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

/* Compiler-specific intrinsics for bit manipulation */
#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(_BitScanForward)
#pragma intrinsic(_BitScanForward64)

static inline uint32_t ctz32(uint32_t x) {
    unsigned long index;
    _BitScanForward(&index, x);
    return (uint32_t)index;
}

static inline uint32_t ctz64(uint64_t x) {
    unsigned long index;
    _BitScanForward64(&index, x);
    return (uint32_t)index;
}

#define INLINE       __forceinline static inline
#define __restrict__ __restrict
#else
#define ctz32(x) ((uint32_t)__builtin_ctz(x))
#define ctz64(x) ((uint32_t)__builtin_ctzll(x))
#define INLINE   __attribute__((always_inline)) static inline
#endif

#endif  // __PULSAR_MACROS_H__
