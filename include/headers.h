#ifndef __HEADERS_H__
#define __HEADERS_H__

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "arena.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def MAX_HEADERS
 * @brief Maximum number of headers that can be stored
 */
#define MAX_HEADERS 64

/**
 * @def MAX_INLINE_HEADERS
 * @brief Number of headers stored inline (avoiding arena allocation for small cases)
 */
#define MAX_INLINE_HEADERS 4

/**
 * @def BUCKET_COUNT
 * @brief Number of buckets in the hash table (must be power of two)
 */
#define BUCKET_COUNT 64

/**
 * @def NAME_BITMAP_BITS
 * @brief Size of the name bitmap in bits (for fast existence checks)
 */
#define NAME_BITMAP_BITS 256

/**
 * @def NAME_BITMAP_SIZE
 * @brief Size of the name bitmap in 64-bit words
 */
#define NAME_BITMAP_SIZE (NAME_BITMAP_BITS / 64)

// Compile-time check for power of two bucket count
static_assert((BUCKET_COUNT & (BUCKET_COUNT - 1)) == 0, "BUCKET_COUNT must be power of two");

/**
 * @brief Case-insensitive ASCII hash function for header names
 * @param name Header name to hash
 * @return 32-bit hash value
 *
 * Uses DJB2 hash algorithm with XOR variant. Performs ASCII-only lowercase conversion.
 * This is optimized for HTTP header names which are ASCII and case-insensitive.
 */
static inline uint32_t header_name_hash(const char* name) {
    uint32_t hash = 5381;
    char c;
    while ((c = *name++)) {
        // name is already canonicalized to lower-case in header_name_canonicalize.
        // if (c >= 'A' && c <= 'Z')
        //     c |= 0x20;                    // Fast ASCII tolower using bitwise OR
        hash = ((hash << 5) + hash) ^ c;  // hash * 33 ^ c
    }
    return hash;
}

/**
 * @brief Canonicalize header name to lowercase in-place
 * @param name Header name to modify
 *
 * Converts ASCII uppercase letters to lowercase directly in the buffer.
 * This is safe for HTTP header names which are ASCII only.
 */
static inline void header_name_canonicalize(char* name) {
    for (; *name; ++name) {
        if (*name >= 'A' && *name <= 'Z')
            *name |= 0x20;  // Fast ASCII lowercase conversion
    }
}

/**
 * @brief HTTP header key-value pair
 */
typedef struct header_t {
    char* name;             ///< Header name (must be allocated in arena)
    char* value;            ///< Header value (must be allocated in arena)
    uint32_t hash;          ///< Precomputed name hash for faster lookups
    struct header_t* next;  ///< Next header in bucket chain
} header_t;

/**
 * @brief Collection of HTTP headers with optimized storage
 */
typedef struct {
    header_t* buckets[BUCKET_COUNT];              ///< Hash table buckets with chaining
    uint64_t used_buckets_bitmap;                 ///< Bitmap of non-empty buckets
    uint64_t name_bitmap[NAME_BITMAP_SIZE];       ///< Bitmap of seen header name hashes
    size_t count;                                 ///< Current number of headers
    header_t inline_headers[MAX_INLINE_HEADERS];  ///< Inline storage for small cases
    size_t inline_used;                           ///< Number of inline headers used
} headers_t;

/**
 * @brief Initialize a new headers collection
 * @param arena Memory arena for allocations
 * @return New headers instance or NULL on failure
 */
static inline headers_t* headers_new(Arena* arena) {
    headers_t* headers = arena_alloc(arena, sizeof(headers_t));
    if (!headers)
        return NULL;
    headers->count               = 0;
    headers->inline_used         = 0;
    headers->used_buckets_bitmap = 0;
    memset(headers->buckets, 0, sizeof(headers->buckets));
    memset(headers->name_bitmap, 0, sizeof(headers->name_bitmap));
    return headers;
}

/**
 * @brief Check if a header name exists in the collection
 * @param headers Headers collection to check
 * @param hash Precomputed name hash
 * @return True if name exists, false otherwise
 *
 * Uses a probabilistic bitmap for fast negative checks.
 */
#ifdef __AVX2__
#include <immintrin.h>
static inline bool header_name_exists(const headers_t* headers, uint32_t hash) {
    __m256i bitmap = _mm256_loadu_si256((__m256i*)headers->name_bitmap);
    uint32_t mask  = 1 << (hash & 0x1F);
    return _mm256_testz_si256(bitmap, _mm256_set1_epi32(mask)) == 0;
}
#else
// Optimized header_name_exists check
static inline bool header_name_exists(const headers_t* headers, uint32_t hash) {
    // Replace modulo with bitwise AND (since NAME_BITMAP_BITS=256=2^8)
    uint32_t slot = (hash & 0xFF) >> 6;  // Equivalent to (hash % 256)/64
    uint32_t bit  = hash & 0x3F;         // Equivalent to hash % 64
    return (headers->name_bitmap[slot] & (1ULL << bit)) != 0;
}
#endif

/**
 * @brief Mark a header name as existing in the collection
 * @param headers Headers collection to modify
 * @param hash Precomputed name hash
 */
static inline void mark_header_name(headers_t* headers, uint32_t hash) {
    headers->name_bitmap[(hash % NAME_BITMAP_BITS) / 64] |= (1ULL << (hash % 64));
}

/**
 * @brief Allocate a new header structure
 * @param arena Memory arena for allocations
 * @param headers Headers collection
 * @return New header or NULL on failure
 *
 * Uses inline storage first, then falls back to arena allocation.
 */
static inline header_t* alloc_header(Arena* arena, headers_t* headers) {
    if (headers->inline_used < MAX_INLINE_HEADERS) {
        return &headers->inline_headers[headers->inline_used++];
    }
    return arena_alloc(arena, sizeof(header_t));
}

/**
 * @brief Set or replace a header
 * @param arena Memory arena for allocations
 * @param headers Headers collection to modify
 * @param name Header name (will be canonicalized)
 * @param value Header value
 * @return True on success, false on failure (max headers reached or allocation failed)
 */
static inline bool headers_set(Arena* arena, headers_t* headers, char* name, char* value) {
    assert(arena && headers && name && value);

    // Canonicalize name to lowercase in-place
    header_name_canonicalize(name);
    uint32_t hash = header_name_hash(name);
    size_t index  = hash % BUCKET_COUNT;

    // Fast path: check if name exists using bitmap
    if (header_name_exists(headers, hash)) {
        // Search bucket chain for exact match
        for (header_t* h = headers->buckets[index]; h; h = h->next) {
            if (h->hash == hash && strcmp(h->name, name) == 0) {
                h->value = value;  // Update existing header
                return true;
            }
        }
    }

    // Reject if we've reached maximum headers
    if (headers->count >= MAX_HEADERS)
        return false;

    // Allocate new header
    header_t* hdr = alloc_header(arena, headers);
    if (!hdr)
        return false;

    // Initialize new header
    hdr->name  = name;
    hdr->value = value;
    hdr->hash  = hash;
    hdr->next  = headers->buckets[index];  // Insert at head of chain

    // Update collection state
    headers->buckets[index] = hdr;
    headers->used_buckets_bitmap |= (1ULL << index);
    mark_header_name(headers, hash);
    headers->count++;

    return true;
}

/**
 * @brief Get a header value by name
 * @param headers Headers collection to search
 * @param name Header name to find (case-insensitive)
 * @return Header value if found, NULL otherwise
 */
static inline const char* headers_get(const headers_t* headers, const char* name) {
    uint32_t hash = header_name_hash(name);
    size_t index  = hash % BUCKET_COUNT;

    // Fast negative check using bitmap
    if (!header_name_exists(headers, hash))
        return NULL;

    // Search bucket chain for case-insensitive match
    for (header_t* h = headers->buckets[index]; h; h = h->next) {
        if (h->hash == hash && strcasecmp(h->name, name) == 0) {
            return h->value;
        }
    }
    return NULL;
}

/**
 * @brief Clear all headers while keeping storage allocated
 * @param headers Headers collection to clear
 */
static inline void headers_clear(headers_t* headers) {
    memset(headers->buckets, 0, sizeof(headers->buckets));
    headers->used_buckets_bitmap = 0;
    memset(headers->name_bitmap, 0, sizeof(headers->name_bitmap));
    headers->count       = 0;
    headers->inline_used = 0;
}

/**
 * @brief Iterate through all headers in the collection
 * @param headers Headers collection to iterate
 * @param item Current header in iteration
 *
 * Usage:
 * headers_foreach(headers, hdr) {
 *     printf("%s: %s\n", hdr->name, hdr->value);
 * }
 */
#define headers_foreach(headers, item)                                                                       \
    for (uint64_t _bm = (headers)->used_buckets_bitmap; _bm; _bm &= (_bm - 1))                               \
        for (uint32_t _pos = __builtin_ctzll(_bm), _done = 0; !_done; _done = 1)                             \
            for (header_t* item = (headers)->buckets[_pos]; item; item = item->next)

#ifdef __cplusplus
}
#endif

#endif  // __HEADERS_H__
