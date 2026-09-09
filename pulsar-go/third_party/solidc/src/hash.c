#include "../include/hash.h"

#include <stddef.h>
#include <string.h>

#ifndef _WIN32
    #include <pthread.h>
#else
    #include "../include/platform.h"
#endif

#if defined(__x86_64__) || defined(__i386__)
    #define HASH_ARCH_X86 1
    #if defined(__GNUC__)
        #include <nmmintrin.h> /* _mm_crc32_u64 (SSE4.2) */
        #define HASH_GNU_TARGET_ATTR 1
    #endif
#endif

/*
 * All string-hash functions treat a NULL key uniformly: they return 0
 * instead of dereferencing it.  Hashing NULL is almost always a caller
 * bug, but crashing a library over an empty bucket key is worse than
 * returning a well-defined (and documented) value.
 */

/**
 * DJB2 hash function implementation.
 * Simple and effective hash created by Daniel J. Bernstein.
 */
uint32_t solidc_djb2_hash(const void* key) {
    if (!key) return 0;
    const unsigned char* str = (const unsigned char*)key;
    uint32_t hash = 5381;
    int c;

    while ((c = *str++) != '\0') {
        hash = ((hash << 5) + hash) + (uint32_t)c;  // hash * 33 + c
    }

    return hash;
}

/**
 * DJB2A hash function implementation (XOR variant).
 * Uses XOR instead of addition for mixing.
 */
uint32_t solidc_djb2a_hash(const void* key) {
    if (!key) return 0;
    const unsigned char* str = (const unsigned char*)key;
    uint32_t hash = 5381;
    int c;

    while ((c = *str++) != '\0') {
        hash = ((hash << 5) + hash) ^ (unsigned)c;  // hash * 33 ^ c
    }

    return hash;
}

/**
 * FNV-1a 32-bit hash function implementation.
 * Fowler-Noll-Vo hash with good distribution.
 */
uint32_t solidc_fnv1a_hash(const void* key) {
    if (!key) return 0;
    const unsigned char* str = (const unsigned char*)key;
    uint32_t hash = 2166136261u;  // FNV offset basis

    while (*str) {
        hash ^= (uint32_t)(*str++);
        hash *= 16777619u;  // FNV prime
    }

    return hash;
}

/**
 * FNV-1a 64-bit hash function implementation.
 * 64-bit version providing larger hash space.
 */
uint64_t solidc_fnv1a_hash64(const void* key) {
    if (!key) return 0;
    const unsigned char* str = (const unsigned char*)key;
    uint64_t hash = 14695981039346656037ULL;  // FNV offset basis

    while (*str) {
        hash ^= (uint64_t)(*str++);
        hash *= 1099511628211ULL;  // FNV prime
    }

    return hash;
}

/**
 * ELF hash function implementation.
 * Used in ELF object file format.
 */
uint32_t solidc_elf_hash(const void* key) {
    if (!key) return 0;
    const unsigned char* str = (const unsigned char*)key;
    uint32_t hash = 0;
    uint32_t x = 0;

    while (*str) {
        hash = (hash << 4) + (*str++);
        x = hash & 0xF0000000UL;
        if (x != 0) {
            hash ^= (x >> 24);
        }
        hash &= ~x;
    }

    return hash;
}

/**
 * SDBM hash function implementation.
 * Used in SDBM database library.
 */
uint32_t solidc_sdbm_hash(const void* key) {
    if (!key) return 0;
    const unsigned char* str = (const unsigned char*)key;
    uint32_t hash = 0;
    int c;

    while ((c = *str++) != '\0') {
        hash = (unsigned char)c + (hash << 6) + (hash << 16) - hash;
    }
    return hash;
}

/* ---------------------------------------------------------------------------
 * CRC32 (IEEE 802.3, polynomial 0xEDB88320 reflected), slice-by-sixteen.
 *
 * Produces bit-identical results to the naive bitwise loop.  Each extra
 * table column adds one more independent lookup per iteration, so the
 * inner loop consumes 16 bytes with 16 L1-resident lookups (tables total
 * 16 KiB).  Further scaling (slice-by-32) would spill the tables out of
 * L1 on smaller cores; the next real ceiling for THIS polynomial is a
 * PCLMULQDQ folding pipeline.  The CPU also exposes the SSE4.2 `crc32`
 * instruction, but that computes CRC-32C (Castagnoli) -- see
 * solidc_crc32c_hash() below.
 *
 * Tables are initialized exactly once, thread-safely:
 *   - POSIX:   pthread_once
 *   - Windows: InitOnceExecuteOnce
 * ------------------------------------------------------------------------- */
#define CRC_TABLE_COLS 16
static uint32_t crc_slice_table[CRC_TABLE_COLS][256];

static void crc32_build_tables(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int k = 0; k < 8; k++) {
            /* (-crc & 1) avoids implementation-defined int->uint conversions. */
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
        crc_slice_table[0][i] = crc;
    }
    for (int t = 1; t < CRC_TABLE_COLS; t++) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t prev = crc_slice_table[t - 1][i];
            crc_slice_table[t][i] = (prev >> 8) ^ crc_slice_table[0][prev & 0xFF];
        }
    }
}

#ifdef _WIN32
static INIT_ONCE crc_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK crc_once_cb(PINIT_ONCE once, PVOID param, PVOID* ctx) {
    (void)once;
    (void)param;
    (void)ctx;
    crc32_build_tables();
    return TRUE;
}
#else
static pthread_once_t crc_once = PTHREAD_ONCE_INIT;

static void crc_once_cb(void) { crc32_build_tables(); }
#endif

static inline void crc32_init_once(void) {
#ifdef _WIN32
    InitOnceExecuteOnce(&crc_once, crc_once_cb, NULL, NULL);
#else
    pthread_once(&crc_once, crc_once_cb);
#endif
}

/**
 * CRC32 hash function implementation.
 * Standard CRC32 with polynomial 0xEDB88320, computed with the
 * slice-by-sixteen technique (bit-identical to the naive bitwise loop).
 */
uint32_t solidc_crc32_hash(const void* key, size_t len) {
    if (!key && len > 0) return 0;

    crc32_init_once();

    const unsigned char* data = (const unsigned char*)key;
    uint32_t crc = 0xFFFFFFFFu;

    /* Bulk: consume 16 bytes per iteration. */
    while (len >= 16) {
        uint64_t lo, hi;
        memcpy(&lo, data, 8);
        memcpy(&hi, data + 8, 8);
        lo ^= (uint64_t)crc;

        crc = crc_slice_table[15][lo & 0xFF] ^ crc_slice_table[14][(lo >> 8) & 0xFF] ^
              crc_slice_table[13][(lo >> 16) & 0xFF] ^ crc_slice_table[12][(lo >> 24) & 0xFF] ^
              crc_slice_table[11][(lo >> 32) & 0xFF] ^ crc_slice_table[10][(lo >> 40) & 0xFF] ^
              crc_slice_table[9][(lo >> 48) & 0xFF] ^ crc_slice_table[8][(lo >> 56) & 0xFF] ^
              crc_slice_table[7][hi & 0xFF] ^ crc_slice_table[6][(hi >> 8) & 0xFF] ^
              crc_slice_table[5][(hi >> 16) & 0xFF] ^ crc_slice_table[4][(hi >> 24) & 0xFF] ^
              crc_slice_table[3][(hi >> 32) & 0xFF] ^ crc_slice_table[2][(hi >> 40) & 0xFF] ^
              crc_slice_table[1][(hi >> 48) & 0xFF] ^ crc_slice_table[0][(hi >> 56) & 0xFF];

        data += 16;
        len -= 16;
    }

    /* Tail: remaining bytes through the first table. */
    while (len--) {
        crc = (crc >> 8) ^ crc_slice_table[0][(crc ^ *data++) & 0xFF];
    }

    return ~crc;
}

/**
 * MurmurHash3 32-bit implementation.
 * Excellent general-purpose hash with good distribution.
 *
 * Block loads go through memcpy() so they are alignment- and
 * strict-aliasing-safe; every mainstream compiler folds them into a
 * single unaligned load instruction.
 */
uint32_t solidc_murmur_hash(const char* key, uint32_t len, uint32_t seed) {
    if (!key && len > 0) return 0;

    const uint8_t* data = (const uint8_t*)key;
    const uint32_t nblocks = len / 4;

    uint32_t h1 = seed;

    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    // Body: process 4-byte blocks
    for (uint32_t i = 0; i < nblocks; i++) {
        uint32_t k1;
        memcpy(&k1, data + i * 4, sizeof(k1));

        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> (32 - 15));
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> (32 - 13));
        h1 = h1 * 5 + 0xe6546b64;
    }

    // Tail: process remaining bytes
    const uint8_t* tail = data + nblocks * 4;
    uint32_t k1 = 0;

    switch (len & 3) {
        case 3:
            k1 ^= (uint32_t)tail[2] << 16u;
            // fallthrough
        case 2:
            k1 ^= (uint32_t)tail[1] << 8u;
            // fallthrough
        case 1:
            k1 ^= tail[0];
            k1 *= c1;
            k1 = (k1 << 15) | (k1 >> (32 - 15));
            k1 *= c2;
            h1 ^= k1;
    }

    // Finalization
    h1 ^= len;

    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

/* ---------------------------------------------------------------------------
 * CRC-32C (Castagnoli, polynomial 0x82F63B78 reflected).
 *
 * This is a DIFFERENT algorithm from the IEEE CRC32 above: it is the
 * polynomial used by iSCSI, ext4, Btrfs and hardware CRC engines.
 *
 * On x86 with SSE4.2 the hardware `crc32` instruction computes exactly
 * this polynomial at ~1-2 bytes/cycle; we dispatch to it at runtime via
 * __builtin_cpu_supports() so the same binary serves every machine.
 * Portable fallback is a standard table-driven implementation sharing
 * the once-only init discipline of the IEEE tables.
 * ------------------------------------------------------------------------- */
static uint32_t crc32c_table[8][256];

static void crc32c_build_tables(void) {
    const uint32_t poly = 0x82F63B78u;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (poly & (0u - (crc & 1u)));
        }
        crc32c_table[0][i] = crc;
    }
    for (int t = 1; t < 8; t++) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t prev = crc32c_table[t - 1][i];
            crc32c_table[t][i] = (prev >> 8) ^ crc32c_table[0][prev & 0xFF];
        }
    }
}

#ifdef _WIN32
static INIT_ONCE crc32c_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK crc32c_once_cb(PINIT_ONCE once, PVOID param, PVOID* ctx) {
    (void)once;
    (void)param;
    (void)ctx;
    crc32c_build_tables();
    return TRUE;
}
#else
static pthread_once_t crc32c_once = PTHREAD_ONCE_INIT;

static void crc32c_once_cb(void) { crc32c_build_tables(); }
#endif

static inline void crc32c_init_once(void) {
#ifdef _WIN32
    InitOnceExecuteOnce(&crc32c_once, crc32c_once_cb, NULL, NULL);
#else
    pthread_once(&crc32c_once, crc32c_once_cb);
#endif
}

#if defined(HASH_GNU_TARGET_ATTR)
__attribute__((target("sse4.2"))) static uint32_t crc32c_hw(const unsigned char* data, size_t len) {
    uint64_t crc = 0xFFFFFFFFu;

    /* 16 bytes per iteration via two crc32q ops keeps the dependency
     * chain short enough to saturate the unit. */
    while (len >= 16) {
        uint64_t a, b;
        memcpy(&a, data, 8);
        memcpy(&b, data + 8, 8);
        crc = _mm_crc32_u64(crc, a);
        crc = _mm_crc32_u64(crc, b);
        data += 16;
        len -= 16;
    }
    while (len >= 8) {
        uint64_t v;
        memcpy(&v, data, 8);
        crc = _mm_crc32_u64(crc, v);
        data += 8;
        len -= 8;
    }
    if (len >= 4) {
        uint32_t v;
        memcpy(&v, data, 4);
        crc = _mm_crc32_u32((uint32_t)crc, v);
        data += 4;
        len -= 4;
    }
    if (len >= 2) {
        uint16_t v;
        memcpy(&v, data, 2);
        crc = _mm_crc32_u16((uint32_t)crc, v);
        data += 2;
        len -= 2;
    }
    if (len) {
        crc = _mm_crc32_u8((uint32_t)crc, *data);
    }

    return (uint32_t)~crc;
}
#endif

#if defined(HASH_ARCH_X86) && defined(HASH_GNU_TARGET_ATTR)
static int crc32c_have_hw = -1;

static inline int crc32c_use_hw(void) {
    if (crc32c_have_hw < 0) {
    #if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)) || defined(__clang__)
        crc32c_have_hw = __builtin_cpu_supports("sse4.2") ? 1 : 0;
    #else
        crc32c_have_hw = 0;
    #endif
    }
    return crc32c_have_hw;
}
#endif

uint32_t solidc_crc32c_hash(const void* key, size_t len) {
    if (!key && len > 0) return 0;
    if (len == 0) return 0;

#if defined(HASH_ARCH_X86) && defined(HASH_GNU_TARGET_ATTR)
    if (crc32c_use_hw()) {
        return crc32c_hw((const unsigned char*)key, len);
    }
#endif

    crc32c_init_once();

    const unsigned char* data = (const unsigned char*)key;
    uint32_t crc = 0xFFFFFFFFu;

    while (len >= 8) {
        uint64_t v;
        memcpy(&v, data, 8);
        v ^= (uint64_t)crc;
        crc = crc32c_table[7][v & 0xFF] ^ crc32c_table[6][(v >> 8) & 0xFF] ^ crc32c_table[5][(v >> 16) & 0xFF] ^
              crc32c_table[4][(v >> 24) & 0xFF] ^ crc32c_table[3][(v >> 32) & 0xFF] ^
              crc32c_table[2][(v >> 40) & 0xFF] ^ crc32c_table[1][(v >> 48) & 0xFF] ^ crc32c_table[0][(v >> 56) & 0xFF];
        data += 8;
        len -= 8;
    }
    while (len--) {
        crc = (crc >> 8) ^ crc32c_table[0][(crc ^ *data++) & 0xFF];
    }

    return ~crc;
}
