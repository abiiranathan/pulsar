#ifndef MEMMEM_H
#define MEMMEM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((always_inline)) static inline uint16_t le_load_u16(const unsigned char* p) {
    // load p[0] as low byte, p[1] as high byte,
    // giving a consistent little‑endian interpretation:
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

__attribute__((always_inline)) static inline void* memmem_scalar(const void* haystack, size_t haystack_len,
                                                                 const void* needle, size_t needle_len) {
    if (needle_len == 0)
        return (void*)haystack;
    if (haystack_len < needle_len)
        return NULL;

    const unsigned char* h   = (const unsigned char*)haystack;
    const unsigned char* n   = (const unsigned char*)needle;
    const unsigned char* end = h + haystack_len - needle_len;

    /* Single character needle - use optimized memchr */
    if (needle_len == 1) {
        return memchr(haystack, n[0], haystack_len);
    }

    /* Two character needle */
    if (needle_len == 2) {
        uint16_t n16 = le_load_u16(n);
        size_t limit = haystack_len - 1;
        for (size_t i = 0; i < limit; i++) {
            if (le_load_u16(h + i) == n16)
                return (void*)(h + i);
        }
        return NULL;
    }

    /* Boyer-Moore-like skip table for last character */
    size_t skip[256];
    for (int i = 0; i < 256; i++) {
        skip[i] = needle_len;
    }
    for (size_t i = 0; i < needle_len - 1; i++) {
        skip[n[i]] = needle_len - 1 - i;
    }

    const unsigned char first = n[0];
    const unsigned char last  = n[needle_len - 1];

    while (h <= end) {
        /* Quick check: compare last character first (often faster) */
        if (h[needle_len - 1] == last && h[0] == first) {
            if (needle_len == 2 || memcmp(h + 1, n + 1, needle_len - 2) == 0) {
                return (void*)h;
            }
        }

        /* Skip using the skip table */
        h += skip[h[needle_len - 1]];
    }

    return NULL;
}

#ifdef __AVX2__
#include <immintrin.h>

/* AVX2 optimized version for longer needles */
static void* memmem_avx2(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len) {
    if (needle_len == 0)
        return (void*)haystack;
    if (haystack_len < needle_len)
        return NULL;

    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;

    /* For short needles or small haystacks, scalar is faster */
    if (needle_len < 4 || haystack_len < 32) {
        return memmem_scalar(haystack, haystack_len, needle, needle_len);
    }

    const size_t end_pos      = haystack_len - needle_len;
    const unsigned char first = n[0];

    /* Create vector of first character */
    const __m256i first_vec = _mm256_set1_epi8(first);

    size_t pos = 0;

    /* SIMD search for first character with 4-byte verification */
    if (needle_len >= 4) {
        const unsigned char second = n[1];
        const unsigned char third  = n[2];
        const unsigned char fourth = n[3];

        while (pos + 32 <= end_pos + 1) {
            /* Load 32 bytes from haystack with offsets */
            __m256i block0 = _mm256_loadu_si256((const __m256i*)(h + pos));
            __m256i block1 = _mm256_loadu_si256((const __m256i*)(h + pos + 1));
            __m256i block2 = _mm256_loadu_si256((const __m256i*)(h + pos + 2));
            __m256i block3 = _mm256_loadu_si256((const __m256i*)(h + pos + 3));

            /* Compare first character */
            __m256i cmp0  = _mm256_cmpeq_epi8(block0, first_vec);
            uint32_t mask = _mm256_movemask_epi8(cmp0);

            /* If matches found, verify next three bytes */
            if (mask) {
                /* Store blocks to temp arrays for byte access */
                uint8_t temp0[32], temp1[32], temp2[32], temp3[32];
                _mm256_storeu_si256((__m256i*)temp0, block0);
                _mm256_storeu_si256((__m256i*)temp1, block1);
                _mm256_storeu_si256((__m256i*)temp2, block2);
                _mm256_storeu_si256((__m256i*)temp3, block3);

                while (mask) {
                    int offset           = __builtin_ctz(mask);
                    size_t candidate_pos = pos + offset;

                    /* Verify bytes 2,3,4 using pre-loaded blocks */
                    if (temp1[offset] == second && temp2[offset] == third && temp3[offset] == fourth) {
                        /* Full match for 4-byte needle */
                        if (needle_len == 4) {
                            return (void*)(h + candidate_pos);
                        }
                        /* Verify remainder with memcmp */
                        if (memcmp(h + candidate_pos + 4, n + 4, needle_len - 4) == 0) {
                            return (void*)(h + candidate_pos);
                        }
                    }
                    mask &= mask - 1; /* Clear lowest set bit */
                }
            }
            pos += 32;
        }
    }

    /* Handle remaining bytes with scalar version */
    if (pos <= end_pos) {
        void* result = memmem_scalar(h + pos, haystack_len - pos, needle, needle_len);
        return result;
    }
    return NULL;
}
#endif

static inline void* pulsar_memmem(const void* haystack, size_t haystack_len, const void* needle,
                                  size_t needle_len) {
#ifdef __AVX2__
    return memmem_avx2(haystack, haystack_len, needle, needle_len);
#else
    return memmem_scalar(haystack, haystack_len, needle, needle_len);
#endif
}

#ifdef __cplusplus
}
#endif

#endif  // MEMMEM_H
