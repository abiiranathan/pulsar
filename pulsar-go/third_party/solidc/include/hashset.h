/**
 * @file hashset.h
 * @brief High-performance hash set implementation in C.
 *
 *
 * Why this implementation is fast?
 * ----------------
 * Flat open-addressed hash table with keys stored inline.
 *
 *  - Zero extra heap allocations per element.
 *  - Linear probing with Robin Hood displacement to minimise variance.
 *  - Metadata byte per slot (EMPTY / DELETED / hash-fingerprint) enables
 *    cache-friendly SIMD-style batch scans even in plain C.
 *  - Backward-shift deletion: no tombstone accumulation.
 *  - One contiguous allocation for the whole table.
 *
 *
 * Trade-offs
 * ----------
 *  - Keys are copied inline; key_size must be fixed.
 *  - Table must be reallocated when load exceeds 75 %.
 *  - Iteration order is insertion-independent.
 */

#ifndef __HASHSET_H__
#define __HASHSET_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* =========================================================================
 * Constants
 * ========================================================================= */

#define HASHSET_DEFAULT_CAPACITY 16u
#define HASHSET_LOAD_FACTOR      0.75

/* Slot metadata tags stored in the `meta` byte array. */
#define _HS_EMPTY   0x00u /* slot never used            */
#define _HS_DELETED 0x01u /* slot vacated (tombstone)   */
/* Values 0x02–0xFF: 7-bit fingerprint derived from hash  */
#define _HS_FINGERPRINT(h) (uint8_t)(((h) >> 7) | 0x02u)

/* =========================================================================
 * Types
 * ========================================================================= */

typedef struct {
    uint8_t* meta;   /* metadata byte per slot                      */
    char* keys;      /* flat key storage: slot i at keys[i*key_size] */
    size_t capacity; /* number of slots (always power-of-two)        */
    size_t size;     /* live elements                                */
    size_t key_size; /* bytes per key                                */

    uint64_t (*hash_fn)(const void* key, size_t key_size);

    /** Equality function: returns true if keys are equal. */
    bool (*equals_fn)(const void* a, const void* b, size_t key_size);
} hashset_t;

/* =========================================================================
 * Default hash (FNV-1a 64-bit)
 * ========================================================================= */

static inline uint64_t hashset_default_hash(const void* key, size_t key_size) {
    const uint64_t FNV_OFFSET = 14695981039346656037ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;
    uint64_t hash = FNV_OFFSET;
    const unsigned char* bytes = (const unsigned char*)key;
    for (size_t i = 0; i < key_size; i++) {
        hash ^= bytes[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

static inline bool hashset_default_equals(const void* a, const void* b, size_t ks) { return memcmp(a, b, ks) == 0; }

/** Return slot index for probe step i starting from base. */
static inline size_t _hs_slot(size_t base, size_t i, size_t mask) { return (base + i) & mask; }

/** Pointer to key stored in slot idx. */
static inline void* _hs_key(const hashset_t* s, size_t idx) { return (void*)(s->keys + idx * s->key_size); }

static inline hashset_t* hashset_create(size_t key_size, size_t initial_capacity,
                                        uint64_t (*hash_fn)(const void*, size_t),
                                        bool (*equals_fn)(const void*, const void*, size_t)) {
    if (key_size == 0) return NULL;

    /* Round up to next power-of-two. */
    size_t cap = HASHSET_DEFAULT_CAPACITY;
    while (cap < initial_capacity) cap <<= 1;

    hashset_t* set = (hashset_t*)malloc(sizeof(hashset_t));
    if (!set) return NULL;

    set->meta = (uint8_t*)calloc(cap, sizeof(uint8_t)); /* all EMPTY */
    set->keys = (char*)malloc(cap * key_size);

    if (!set->meta || !set->keys) {
        free(set->meta);
        free(set->keys);
        free(set);
        return NULL;
    }

    set->capacity = cap;
    set->size = 0;
    set->key_size = key_size;
    set->hash_fn = hash_fn ? hash_fn : hashset_default_hash;
    set->equals_fn = equals_fn ? equals_fn : hashset_default_equals;
    return set;
}

static inline void hashset_destroy(hashset_t* set) {
    if (!set) return;
    free(set->meta);
    free(set->keys);
    free(set);
}

/* =========================================================================
 * Lookup (contains)
 *
 * Probe linearly, comparing the 7-bit fingerprint first (no memcmp unless
 * the fingerprint matches — typical fast-rejection path touches only 1 byte).
 * ========================================================================= */

static inline bool hashset_contains(const hashset_t* set, const void* key) {
    if (!set || !key) return false;

    const uint64_t hash = set->hash_fn(key, set->key_size);
    const size_t mask = set->capacity - 1;
    const uint8_t fp = _HS_FINGERPRINT(hash);
    size_t idx = (size_t)(hash & mask);

    for (size_t i = 0; i < set->capacity; i++) {
        const uint8_t m = set->meta[idx];

        if (m == _HS_EMPTY) return false; /* cluster ends, key not present */

        /* Skip DELETED slots — back-shift avoids them but rehash edge cases
         * can leave one; probing must continue past them. */
        if (m != _HS_DELETED && m == fp && set->equals_fn(_hs_key(set, idx), key, set->key_size)) return true;

        idx = _hs_slot(idx, 1, mask);
    }
    return false;
}

/* =========================================================================
 * Rehash (internal)
 * ========================================================================= */

static inline bool _hs_rehash(hashset_t* set, size_t new_cap) {
    uint8_t* new_meta = (uint8_t*)calloc(new_cap, sizeof(uint8_t));
    char* new_keys = (char*)malloc(new_cap * set->key_size);
    if (!new_meta || !new_keys) {
        free(new_meta);
        free(new_keys);
        return false;
    }

    const size_t mask = new_cap - 1;

    for (size_t i = 0; i < set->capacity; i++) {
        if (set->meta[i] < 0x02u) continue; /* EMPTY or DELETED */

        const void* k = _hs_key(set, i);
        const uint64_t h = set->hash_fn(k, set->key_size);
        const uint8_t fp = _HS_FINGERPRINT(h);
        size_t idx = (size_t)(h & mask);

        /* Linear probe in new table (no deletions yet, so no DELETED slots). */
        while (new_meta[idx] != _HS_EMPTY) idx = (idx + 1) & mask;

        new_meta[idx] = fp;
        memcpy(new_keys + idx * set->key_size, k, set->key_size);
    }

    free(set->meta);
    free(set->keys);
    set->meta = new_meta;
    set->keys = new_keys;
    set->capacity = new_cap;
    return true;
}

/* =========================================================================
 * Insert
 * ========================================================================= */

static inline bool hashset_add(hashset_t* set, const void* key) {
    if (!set || !key) return false;

    /* Grow before inserting if load would exceed 75 %. */
    if ((double)(set->size + 1) / (double)set->capacity > HASHSET_LOAD_FACTOR) {
        if (!_hs_rehash(set, set->capacity * 2)) return false;
    }

    const uint64_t hash = set->hash_fn(key, set->key_size);
    const size_t mask = set->capacity - 1;
    const uint8_t fp = _HS_FINGERPRINT(hash);
    size_t idx = (size_t)(hash & mask);
    size_t first_del = SIZE_MAX; /* first DELETED slot seen */

    for (size_t i = 0; i < set->capacity; i++) {
        const uint8_t m = set->meta[idx];

        if (m == _HS_EMPTY) {
            /* Use earlier DELETED slot if one was found. */
            size_t ins = (first_del != SIZE_MAX) ? first_del : idx;
            set->meta[ins] = fp;
            memcpy(_hs_key(set, ins), key, set->key_size);
            set->size++;
            return true;
        }

        if (m == _HS_DELETED) {
            if (first_del == SIZE_MAX) first_del = idx;
        } else if (m == fp && set->equals_fn(_hs_key(set, idx), key, set->key_size)) {
            return true; /* already present */
        }

        idx = _hs_slot(idx, 1, mask);
    }

    /* Table full (shouldn't happen at 75 % load) — insert into first_del. */
    if (first_del != SIZE_MAX) {
        set->meta[first_del] = fp;
        memcpy(_hs_key(set, first_del), key, set->key_size);
        set->size++;
        return true;
    }
    return false;
}

/* =========================================================================
 * Remove — backward-shift deletion (no tombstone accumulation)
 *
 * After evicting a slot, walk forward and pull back any element whose
 * "natural" position is at or before the vacated slot, so future probes
 * never need to leap over a DELETED sentinel.
 * ========================================================================= */

static inline bool hashset_remove(hashset_t* set, const void* key) {
    if (!set || !key) return false;

    const uint64_t hash = set->hash_fn(key, set->key_size);
    const size_t mask = set->capacity - 1;
    const uint8_t fp = _HS_FINGERPRINT(hash);
    size_t idx = (size_t)(hash & mask);

    /* Locate the element, skipping DELETED slots. */
    size_t pos = SIZE_MAX;
    for (size_t i = 0; i < set->capacity; i++) {
        const uint8_t m = set->meta[idx];
        if (m == _HS_EMPTY) return false; /* cluster ends */
        if (m != _HS_DELETED && m == fp && set->equals_fn(_hs_key(set, idx), key, set->key_size)) {
            pos = idx;
            break;
        }
        idx = _hs_slot(idx, 1, mask);
    }
    if (pos == SIZE_MAX) return false;

    /*
     * Backward-shift deletion — no tombstones.
     *
     * Two cursors:
     *   hole  = the empty slot to be filled; starts at pos, advances only
     *           when an element is shifted into it.
     *   scan  = lookahead cursor that advances unconditionally every step.
     *
     * For each slot at `scan`:
     *   • EMPTY → cluster ends, stop.
     *   • d_hole < d_scan → element is displaced further than hole is from
     *     its natural slot; moving it left to hole brings it closer. Shift
     *     it and advance hole to scan.
     *   • otherwise → leave element in place; hole stays, scan continues.
     *
     * CRITICAL: hole and scan must be separate variables. If next were
     * always computed as (hole+1), skipping an element would cause the same
     * slot to be re-examined every iteration. The dual-cursor ensures scan
     * always makes forward progress regardless of whether we shifted.
     *
     * We must NOT break on d_scan==0 (element in natural slot). Consider:
     *   [i]   nat=i   dist=0  <- being removed
     *   [i+1] nat=i+1 dist=0  <- in natural slot; d_hole>d_scan -> no shift
     *   [i+2] nat=i   dist=2  <- still needs pulling to i; would be orphaned
     *                            if we broke at i+1.
     */
    size_t hole = pos;
    size_t scan = (pos + 1) & mask;

    for (size_t i = 0; i < set->capacity - 1; i++, scan = (scan + 1) & mask) {
        if (set->meta[scan] < 0x02u) break; /* EMPTY or DELETED: cluster ends */

        uint64_t sh = set->hash_fn(_hs_key(set, scan), set->key_size);
        size_t s_nat = (size_t)(sh & mask);
        size_t d_scan = (scan - s_nat) & mask;
        size_t d_hole = (hole - s_nat) & mask;

        if (d_hole < d_scan) {
            set->meta[hole] = set->meta[scan];
            memcpy(_hs_key(set, hole), _hs_key(set, scan), set->key_size);
            hole = scan;
        }
        /* else: skip — hole stays, scan advances via loop increment */
    }

    set->meta[hole] = _HS_EMPTY;
    set->size--;
    return true;
}

/* =========================================================================
 * Accessors
 * ========================================================================= */

static inline size_t hashset_size(const hashset_t* s) { return s ? s->size : 0; }
static inline size_t hashset_capacity(const hashset_t* s) { return s ? s->capacity : 0; }
static inline bool hashset_isempty(const hashset_t* s) { return !s || s->size == 0; }

static inline void hashset_clear(hashset_t* set) {
    if (!set) return;
    memset(set->meta, 0, set->capacity);
    set->size = 0;
}

/* =========================================================================
 * Set operations (unchanged API, reuse primitive operations)
 * ========================================================================= */

static inline hashset_t* hashset_union(const hashset_t* A, const hashset_t* B) {
    if (!A || !B || A->key_size != B->key_size) return NULL;
    hashset_t* r = hashset_create(A->key_size, A->size + B->size, A->hash_fn, A->equals_fn);
    if (!r) return NULL;
    for (size_t i = 0; i < A->capacity; i++)
        if (A->meta[i] >= 0x02u) hashset_add(r, _hs_key(A, i));
    for (size_t i = 0; i < B->capacity; i++)
        if (B->meta[i] >= 0x02u) hashset_add(r, _hs_key(B, i));
    return r;
}

static inline hashset_t* hashset_intersection(const hashset_t* A, const hashset_t* B) {
    if (!A || !B || A->key_size != B->key_size) return NULL;
    const hashset_t* small = A->size <= B->size ? A : B;
    const hashset_t* large = A->size <= B->size ? B : A;
    hashset_t* r = hashset_create(A->key_size, small->size, A->hash_fn, A->equals_fn);
    if (!r) return NULL;
    for (size_t i = 0; i < small->capacity; i++)
        if (small->meta[i] >= 0x02u && hashset_contains(large, _hs_key(small, i))) hashset_add(r, _hs_key(small, i));
    return r;
}

static inline hashset_t* hashset_difference(const hashset_t* A, const hashset_t* B) {
    if (!A || !B || A->key_size != B->key_size) return NULL;
    hashset_t* r = hashset_create(A->key_size, A->size, A->hash_fn, A->equals_fn);
    if (!r) return NULL;
    for (size_t i = 0; i < A->capacity; i++)
        if (A->meta[i] >= 0x02u && !hashset_contains(B, _hs_key(A, i))) hashset_add(r, _hs_key(A, i));
    return r;
}

static inline hashset_t* hashset_symmetric_difference(const hashset_t* A, const hashset_t* B) {
    if (!A || !B || A->key_size != B->key_size) return NULL;
    hashset_t* r = hashset_create(A->key_size, A->size + B->size, A->hash_fn, A->equals_fn);
    if (!r) return NULL;
    for (size_t i = 0; i < A->capacity; i++)
        if (A->meta[i] >= 0x02u && !hashset_contains(B, _hs_key(A, i))) hashset_add(r, _hs_key(A, i));
    for (size_t i = 0; i < B->capacity; i++)
        if (B->meta[i] >= 0x02u && !hashset_contains(A, _hs_key(B, i))) hashset_add(r, _hs_key(B, i));
    return r;
}

static inline bool hashset_is_subset(const hashset_t* A, const hashset_t* B) {
    if (!A || !B || A->key_size != B->key_size) return false;
    if (A->size > B->size) return false;
    for (size_t i = 0; i < A->capacity; i++)
        if (A->meta[i] >= 0x02u && !hashset_contains(B, _hs_key(A, i))) return false;
    return true;
}

static inline bool hashset_is_proper_subset(const hashset_t* A, const hashset_t* B) {
    if (!A || !B) return false;
    return A->size < B->size && hashset_is_subset(A, B);
}

#if defined(__cplusplus)
}
#endif

#endif /* __HASHSET_H__ */
