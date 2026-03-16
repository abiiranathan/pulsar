/**
 * @file memmem.h
 * @brief High-performance, cross-platform implementation of memmem.
 *
 * This header provides a fast, SIMD-accelerated drop-in replacement for the
 * GNU extension `memmem`. It utilizes AVX2 on x86_64 and NEON on ARM64 to
 * search for substrings efficiently, falling back to a highly optimized
 * scalar routine when SIMD is unavailable or the inputs are too short.
 * Benchmarks show significant performance improvements over libc's memmem, especially for larger haystacks and needles
 * Otherwise the performance is on par with libc's memmem.
 * @version 2.0
 * @date 2026
 */

#ifndef MEMMEM_H
#define MEMMEM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
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
#else
#define ctz32(x) ((uint32_t)__builtin_ctz(x))
#define ctz64(x) ((uint32_t)__builtin_ctzll(x))
#endif

/**
 * @brief Endian-independent 16-bit load.
 *
 * Reads two bytes from memory and constructs a 16-bit integer where the first
 * byte is the low byte and the second is the high byte.
 *
 * @param p Pointer to the memory to read.
 * @return A mathematically consistent 16-bit integer regardless of host endianness.
 */
__attribute__((always_inline)) static inline uint16_t le_load_u16(const unsigned char* p) {
    /* Bitwise operations act on logical values, not physical memory layout.
       This safely avoids strict aliasing and unaligned access penalties. */
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * @brief Highly optimized scalar implementation of memmem.
 *
 * Uses system `memchr` to rapidly advance to the first character match,
 * then verifies the last character of the needle before calling `memcmp`.
 *
 * @param haystack Pointer to the block of memory to search.
 * @param haystack_len Size of the haystack in bytes.
 * @param needle Pointer to the byte sequence to find.
 * @param needle_len Size of the needle in bytes.
 * @return Pointer to the first occurrence of needle, or NULL if not found.
 */
__attribute__((always_inline)) static inline void* memmem_scalar(const void* __restrict__ haystack, size_t haystack_len,
                                                                 const void* __restrict__ needle, size_t needle_len) {
    if (needle_len == 0) return (void*)haystack;
    if (haystack_len < needle_len) return NULL;

    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;

    /* Fast path for single-byte needle */
    if (needle_len == 1) {
        return memchr(haystack, n[0], haystack_len);
    }

    /* Optimized path for two-byte needle */
    if (needle_len == 2) {
        uint16_t n16 = le_load_u16(n);
        size_t limit = haystack_len - 1;
        for (size_t i = 0; i < limit; i++) {
            if (le_load_u16(h + i) == n16) return (void*)(h + i);
        }
        return NULL;
    }

    /* General case: needle length >= 3 */
    const unsigned char first = n[0];
    const unsigned char last = n[needle_len - 1];
    const size_t needle_len_minus_1 = needle_len - 1;
    const size_t inner_len = needle_len - 2;
    const unsigned char* end = h + haystack_len - needle_len;

    while (h <= end) {
        /* Rapidly skip non-matching prefixes using libc's optimized memchr */
        h = (const unsigned char*)memchr(h, first, end - h + 1);
        if (!h) break;

        /* Verify the last character before committing to an expensive memcmp */
        if (h[needle_len_minus_1] == last) {
            if (inner_len == 0 || memcmp(h + 1, n + 1, inner_len) == 0) {
                return (void*)h;
            }
        }
        h++;
    }

    return NULL;
}

#if defined(__AVX2__)
#include <immintrin.h>

/**
 * @brief AVX2 accelerated implementation of memmem.
 *
 * Processes 32 bytes at a time by simultaneously comparing the first and last
 * characters of the needle using vector operations. Maximizes SIMD coverage
 * before falling back to scalar processing.
 *
 * @param haystack Pointer to the block of memory to search.
 * @param haystack_len Size of the haystack in bytes.
 * @param needle Pointer to the byte sequence to find.
 * @param needle_len Size of the needle in bytes.
 * @return Pointer to the first occurrence of needle, or NULL if not found.
 */
static inline void* memmem_simd(const void* __restrict__ haystack, size_t haystack_len, const void* __restrict__ needle,
                                size_t needle_len) {
    /* Use scalar for short needles or haystacks where SIMD overhead isn't worth it */
    if (needle_len < 3 || haystack_len < needle_len + 32) {
        return memmem_scalar(haystack, haystack_len, needle, needle_len);
    }

    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;
    const size_t end_pos = haystack_len - needle_len;
    const size_t needle_len_minus_1 = needle_len - 1;
    const size_t inner_len = needle_len - 2;

    const __m256i first_vec = _mm256_set1_epi8((char)n[0]);
    const __m256i last_vec = _mm256_set1_epi8((char)n[needle_len_minus_1]);

    size_t pos = 0;

    /* Process as much as possible with SIMD. We need to ensure:
       1. We can read 32 bytes starting at 'pos' (the first-character block)
       2. We can read 32 bytes starting at 'pos + needle_len - 1' (the last-character block)
       This means: pos + needle_len - 1 + 32 <= haystack_len
       Simplified: pos <= haystack_len - needle_len - 31 */
    const size_t simd_limit = haystack_len >= needle_len + 31 ? haystack_len - needle_len - 31 : 0;

    while (pos <= simd_limit) {
        __m256i block_first = _mm256_loadu_si256((const __m256i*)(h + pos));
        __m256i block_last = _mm256_loadu_si256((const __m256i*)(h + pos + needle_len_minus_1));

        __m256i cmp_first = _mm256_cmpeq_epi8(block_first, first_vec);
        __m256i cmp_last = _mm256_cmpeq_epi8(block_last, last_vec);

        /* Bitwise AND leaves 0xFF only where BOTH first and last characters matched */
        __m256i matched = _mm256_and_si256(cmp_first, cmp_last);

        /* Compress the 32-byte vector into a 32-bit integer mask */
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(matched);

        while (mask) {
            /* Count Trailing Zeros gives the exact byte index of the first match */
            uint32_t offset = ctz32(mask);
            if (inner_len == 0 || memcmp(h + pos + offset + 1, n + 1, inner_len) == 0) {
                return (void*)(h + pos + offset);
            }
            /* Clear the lowest set bit to process the next candidate in the mask */
            mask &= mask - 1;
        }
        pos += 32;
    }

    /* Handle remaining bytes with scalar algorithm */
    if (pos <= end_pos) {
        return memmem_scalar(h + pos, haystack_len - pos, needle, needle_len);
    }

    return NULL;
}

#elif defined(__ARM_NEON)
#include <arm_neon.h>

/**
 * @brief ARM NEON accelerated implementation of memmem.
 *
 * Processes 16 bytes at a time. Simulates AVX2's movemask by extracting
 * lanes into 64-bit integers and using trailing zero counts.
 *
 * @param haystack Pointer to the block of memory to search.
 * @param haystack_len Size of the haystack in bytes.
 * @param needle Pointer to the byte sequence to find.
 * @param needle_len Size of the needle in bytes.
 * @return Pointer to the first occurrence of needle, or NULL if not found.
 */
static inline void* memmem_simd(const void* __restrict__ haystack, size_t haystack_len, const void* __restrict__ needle,
                                size_t needle_len) {
    /* Use scalar for short needles or haystacks where SIMD overhead isn't worth it */
    if (needle_len < 3 || haystack_len < needle_len + 16) {
        return memmem_scalar(haystack, haystack_len, needle, needle_len);
    }

    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;
    const size_t end_pos = haystack_len - needle_len;
    const size_t needle_len_minus_1 = needle_len - 1;
    const size_t inner_len = needle_len - 2;

    uint8x16_t first_vec = vdupq_n_u8(n[0]);
    uint8x16_t last_vec = vdupq_n_u8(n[needle_len_minus_1]);

    size_t pos = 0;

    /* Maximum position where we can safely read both 16-byte blocks:
       pos + needle_len - 1 + 16 <= haystack_len
       pos <= haystack_len - needle_len - 15 */
    const size_t simd_limit = haystack_len >= needle_len + 15 ? haystack_len - needle_len - 15 : 0;

    while (pos <= simd_limit) {
        uint8x16_t block_first = vld1q_u8(h + pos);
        uint8x16_t block_last = vld1q_u8(h + pos + needle_len_minus_1);

        uint8x16_t cmp_first = vceqq_u8(block_first, first_vec);
        uint8x16_t cmp_last = vceqq_u8(block_last, last_vec);

        uint8x16_t matched = vandq_u8(cmp_first, cmp_last);

        /* NEON lacks movemask. Cast the 16x8-bit vector into 2x64-bit integers
           to process 8 bytes at a time in standard CPU registers. */
        uint64x2_t matched64 = vreinterpretq_u64_u8(matched);
        uint64_t low = vgetq_lane_u64(matched64, 0);
        uint64_t high = vgetq_lane_u64(matched64, 1);

        /* Process low 8 bytes */
        if (low != 0) {
            uint64_t temp = low;
            while (temp != 0) {
                /* Since each byte match is 0xFF, dividing trailing zeros by 8 yields the byte offset */
                uint32_t offset = ctz64(temp) >> 3;
                if (inner_len == 0 || memcmp(h + pos + offset + 1, n + 1, inner_len) == 0) {
                    return (void*)(h + pos + offset);
                }
                /* Create a mask of 0xFF shifted to the matched position, invert it,
                   and bitwise AND to clear the current match so ctzll finds the next one. */
                temp &= ~(0xFFULL << (offset * 8));
            }
        }

        /* Process high 8 bytes */
        if (high != 0) {
            uint64_t temp = high;
            while (temp != 0) {
                uint32_t offset = ctz64(temp) >> 3;
                /* Add 8 because we are processing the upper 8 bytes of the 16-byte vector */
                if (inner_len == 0 || memcmp(h + pos + offset + 8 + 1, n + 1, inner_len) == 0) {
                    return (void*)(h + pos + offset + 8);
                }
                temp &= ~(0xFFULL << (offset * 8));
            }
        }
        pos += 16;
    }

    /* Handle remaining bytes with scalar algorithm */
    if (pos <= end_pos) {
        return memmem_scalar(h + pos, haystack_len - pos, needle, needle_len);
    }

    return NULL;
}
#endif

/**
 * @brief Locates a substring in a block of memory.
 *
 * Dispatcher function that automatically routes to the best available
 * implementation (AVX2, NEON, or optimized scalar) based on compiler flags.
 *
 * @param haystack Pointer to the block of memory to search.
 * @param haystack_len Size of the haystack in bytes.
 * @param needle Pointer to the byte sequence to find.
 * @param needle_len Size of the needle in bytes.
 * @return Pointer to the first occurrence of needle, or NULL if not found.
 */
static inline void* pulsar_memmem(const void* __restrict__ haystack, size_t haystack_len,
                                  const void* __restrict__ needle, size_t needle_len) {
    if (needle_len == 0) return (void*)haystack;
    if (haystack_len < needle_len) return NULL;

#if defined(__AVX2__) || defined(__ARM_NEON)
    return memmem_simd(haystack, haystack_len, needle, needle_len);
#else
    return memmem_scalar(haystack, haystack_len, needle, needle_len);
#endif
}

#ifdef __cplusplus
}
#endif

#endif  // MEMMEM_H
