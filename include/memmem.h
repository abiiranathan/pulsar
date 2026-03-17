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
 * @version 3.0
 * @date 2026
 */

#ifndef MEMMEM_H
#define MEMMEM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "macros.h"

#ifdef __cplusplus
extern "C" {
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
INLINE uint16_t le_load_u16(const unsigned char* p) {
    /* Bitwise operations act on logical values, not physical memory layout.
       This safely avoids strict aliasing and unaligned access penalties. */
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * @brief Fast inline verification for interior bytes.
 * * Bypasses the overhead of setting up a `memcmp` function call for very
 * short inner strings (1 or 2 bytes). Falls back to `memcmp` for longer strings.
 */
INLINE int verify_inner(const unsigned char* candidate, const unsigned char* n_inner, size_t inner_len) {
    /* Fast-path the most likely scenario first to minimize branch prediction misses */
    if (inner_len >= 3) return memcmp(candidate, n_inner, inner_len) == 0;

    /* Short-circuit fast paths for 0, 1, and 2 byte interior lengths */
    if (inner_len == 2) return le_load_u16(candidate) == le_load_u16(n_inner);
    if (inner_len == 1) return candidate[0] == n_inner[0];
    return 1; /* inner_len == 0 */
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
INLINE void* memmem_scalar(const void* __restrict__ haystack, size_t haystack_len, const void* __restrict__ needle,
                           size_t needle_len) {
    if (needle_len == 0) return (void*)haystack;
    if (haystack_len < needle_len) return NULL;

    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;

    /* Fast path for single-byte needle */
    if (needle_len == 1) {
        return memchr((char*)haystack, n[0], haystack_len);
    }

    /* Optimized path for two-byte needle (Compiler auto-vectorizes this beautifully) */
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
        h = (const unsigned char*)memchr((char*)h, first, end - h + 1);
        if (!h) break;

        /* Verify the last character before committing to an expensive verification */
        if (h[needle_len_minus_1] == last) {
            if (verify_inner(h + 1, n + 1, inner_len)) {
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
 * Processes up to 64 bytes at a time by simultaneously comparing the first and last
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

    /* 64-byte Unrolled Loop: Maximize throughput by processing two 32-byte blocks */
    const size_t simd_limit_64 = haystack_len >= needle_len + 63 ? haystack_len - needle_len - 63 : 0;

    while (pos <= simd_limit_64) {
        __m256i block_first0 = _mm256_loadu_si256((const __m256i*)(h + pos));
        __m256i block_last0 = _mm256_loadu_si256((const __m256i*)(h + pos + needle_len_minus_1));

        __m256i block_first1 = _mm256_loadu_si256((const __m256i*)(h + pos + 32));
        __m256i block_last1 = _mm256_loadu_si256((const __m256i*)(h + pos + 32 + needle_len_minus_1));

        __m256i cmp_first0 = _mm256_cmpeq_epi8(block_first0, first_vec);
        __m256i cmp_last0 = _mm256_cmpeq_epi8(block_last0, last_vec);
        __m256i matched0 = _mm256_and_si256(cmp_first0, cmp_last0);
        uint32_t mask0 = (uint32_t)_mm256_movemask_epi8(matched0);

        __m256i cmp_first1 = _mm256_cmpeq_epi8(block_first1, first_vec);
        __m256i cmp_last1 = _mm256_cmpeq_epi8(block_last1, last_vec);
        __m256i matched1 = _mm256_and_si256(cmp_first1, cmp_last1);
        uint32_t mask1 = (uint32_t)_mm256_movemask_epi8(matched1);

        while (mask0) {
            uint32_t offset = ctz32(mask0);
            if (verify_inner(h + pos + offset + 1, n + 1, inner_len)) {
                return (void*)(h + pos + offset);
            }
            mask0 &= mask0 - 1;
        }

        while (mask1) {
            uint32_t offset = ctz32(mask1);
            if (verify_inner(h + pos + 32 + offset + 1, n + 1, inner_len)) {
                return (void*)(h + pos + 32 + offset);
            }
            mask1 &= mask1 - 1;
        }
        pos += 64;
    }

    /* 32-byte Loop: Catch the remaining large chunks before scalar fallback */
    const size_t simd_limit_32 = haystack_len >= needle_len + 31 ? haystack_len - needle_len - 31 : 0;

    while (pos <= simd_limit_32) {
        __m256i block_first = _mm256_loadu_si256((const __m256i*)(h + pos));
        __m256i block_last = _mm256_loadu_si256((const __m256i*)(h + pos + needle_len_minus_1));

        __m256i cmp_first = _mm256_cmpeq_epi8(block_first, first_vec);
        __m256i cmp_last = _mm256_cmpeq_epi8(block_last, last_vec);
        __m256i matched = _mm256_and_si256(cmp_first, cmp_last);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(matched);

        while (mask) {
            uint32_t offset = ctz32(mask);
            if (verify_inner(h + pos + offset + 1, n + 1, inner_len)) {
                return (void*)(h + pos + offset);
            }
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
 * Processes up to 32 bytes at a time. Simulates AVX2's movemask by extracting
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

    /* 32-byte Unrolled Loop: Maximize pipeline efficiency on ARM */
    const size_t simd_limit_32 = haystack_len >= needle_len + 31 ? haystack_len - needle_len - 31 : 0;

    while (pos <= simd_limit_32) {
        uint8x16_t block_first0 = vld1q_u8(h + pos);
        uint8x16_t block_last0 = vld1q_u8(h + pos + needle_len_minus_1);
        uint8x16_t block_first1 = vld1q_u8(h + pos + 16);
        uint8x16_t block_last1 = vld1q_u8(h + pos + 16 + needle_len_minus_1);

        uint8x16_t cmp_first0 = vceqq_u8(block_first0, first_vec);
        uint8x16_t cmp_last0 = vceqq_u8(block_last0, last_vec);
        uint8x16_t matched0 = vandq_u8(cmp_first0, cmp_last0);

        uint8x16_t cmp_first1 = vceqq_u8(block_first1, first_vec);
        uint8x16_t cmp_last1 = vceqq_u8(block_last1, last_vec);
        uint8x16_t matched1 = vandq_u8(cmp_first1, cmp_last1);

        /* Process first 16 bytes */
        uint64x2_t matched64_0 = vreinterpretq_u64_u8(matched0);
        uint64_t low0 = vgetq_lane_u64(matched64_0, 0);
        uint64_t high0 = vgetq_lane_u64(matched64_0, 1);

        if (low0 != 0) {
            uint64_t temp = low0;
            while (temp != 0) {
                uint32_t offset = ctz64(temp) >> 3;
                if (verify_inner(h + pos + offset + 1, n + 1, inner_len)) return (void*)(h + pos + offset);
                temp &= ~(0xFFULL << (offset * 8));
            }
        }
        if (high0 != 0) {
            uint64_t temp = high0;
            while (temp != 0) {
                uint32_t offset = ctz64(temp) >> 3;
                if (verify_inner(h + pos + offset + 8 + 1, n + 1, inner_len)) return (void*)(h + pos + offset + 8);
                temp &= ~(0xFFULL << (offset * 8));
            }
        }

        /* Process second 16 bytes */
        uint64x2_t matched64_1 = vreinterpretq_u64_u8(matched1);
        uint64_t low1 = vgetq_lane_u64(matched64_1, 0);
        uint64_t high1 = vgetq_lane_u64(matched64_1, 1);

        if (low1 != 0) {
            uint64_t temp = low1;
            while (temp != 0) {
                uint32_t offset = ctz64(temp) >> 3;
                if (verify_inner(h + pos + 16 + offset + 1, n + 1, inner_len)) return (void*)(h + pos + 16 + offset);
                temp &= ~(0xFFULL << (offset * 8));
            }
        }
        if (high1 != 0) {
            uint64_t temp = high1;
            while (temp != 0) {
                uint32_t offset = ctz64(temp) >> 3;
                if (verify_inner(h + pos + 16 + offset + 8 + 1, n + 1, inner_len))
                    return (void*)(h + pos + 16 + offset + 8);
                temp &= ~(0xFFULL << (offset * 8));
            }
        }
        pos += 32;
    }

    /* 16-byte Loop for remainder */
    const size_t simd_limit_16 = haystack_len >= needle_len + 15 ? haystack_len - needle_len - 15 : 0;

    while (pos <= simd_limit_16) {
        uint8x16_t block_first = vld1q_u8(h + pos);
        uint8x16_t block_last = vld1q_u8(h + pos + needle_len_minus_1);

        uint8x16_t cmp_first = vceqq_u8(block_first, first_vec);
        uint8x16_t cmp_last = vceqq_u8(block_last, last_vec);
        uint8x16_t matched = vandq_u8(cmp_first, cmp_last);

        uint64x2_t matched64 = vreinterpretq_u64_u8(matched);
        uint64_t low = vgetq_lane_u64(matched64, 0);
        uint64_t high = vgetq_lane_u64(matched64, 1);

        if (low != 0) {
            uint64_t temp = low;
            while (temp != 0) {
                uint32_t offset = ctz64(temp) >> 3;
                if (verify_inner(h + pos + offset + 1, n + 1, inner_len)) return (void*)(h + pos + offset);
                temp &= ~(0xFFULL << (offset * 8));
            }
        }

        if (high != 0) {
            uint64_t temp = high;
            while (temp != 0) {
                uint32_t offset = ctz64(temp) >> 3;
                if (verify_inner(h + pos + offset + 8 + 1, n + 1, inner_len)) return (void*)(h + pos + offset + 8);
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
