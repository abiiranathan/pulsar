#ifndef LOCALS_H
#define LOCALS_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Callback function type for freeing values. */
typedef void (*ValueFreeFunc)(void* value);

/** Maximum number of inline locals entries before spilling to heap. */
#define LOCALS_INLINE_CAPACITY 8

/**
 * Inline key buffer size (excluding the null terminator).
 * Keys up to this length are stored inline in the Locals entry, with no
 * heap allocation. Longer keys are malloc'd to a buffer sized exactly to the key.
 */
#define LOCALS_INLINE_KEY_LEN 15

/**
 * Computes the length of a string literal at compile time.
 */
#define LOCALS_KEY_LEN(s) (sizeof(s) - 1)

/**
 * Sets a local using a compile-time-known key literal.
 *
 * Expands to a call to LocalsSetValueLen with the key length computed at
 * compile time, skipping the runtime strlen() that LocalsSetValue pays.
 * `key` MUST be a string literal (or something sizeof-compatible with
 * one); use LocalsSetValue directly for dynamically-built keys (e.g.
 * snprintf'd identifiers) — it works identically, just pays one strlen().
 */
#define LocalsSet(locals, key, value, free_func) \
    LocalsSetValueLen((locals), (key), LOCALS_KEY_LEN(key), (value), (free_func))

/**
 * Gets a local using a compile-time-known key literal.
 *
 * Expands to a call to LocalsGetValueLen with the key length computed at
 * compile time. `key` MUST be a string literal; use LocalsGetValue
 * directly for dynamically-built keys.
 */
#define LocalsGet(locals, key) LocalsGetValueLen((locals), (key), LOCALS_KEY_LEN(key))

/**
 * FNV-1a hash, 32-bit.
 *
 * Used to give every entry a single cheap-to-compare fingerprint so the
 * hot scan (LocalsGetValue/LocalsSetValue/LocalsRemove) can reject
 * almost all non-matching entries with an integer compare instead of a
 * memcmp — independent of key length, so long dynamically-built keys are
 * exactly as fast to look up as short literal ones.
 *
 * Not cryptographic. Collisions are handled correctly (memcmp still runs
 * on a hash match) but should be rare enough in practice to keep the
 * scan effectively O(1) for realistic key sets.
 */
static inline uint32_t LocalsHashKey(const char* key, size_t key_len) {
    uint32_t hash = 2166136261u; /* FNV offset basis */
    for (size_t i = 0; i < key_len; ++i) {
        hash ^= (uint8_t)key[i];
        hash *= 16777619u; /* FNV prime */
    }
    return hash;
}

/**
 * Storage for one key: inline for short keys, heap-allocated for long ones.
 *
 * A union, not a struct: `inline_buf` and `heap` are never live at the
 * same time, so overlapping them shrinks each entry from 24 bytes (with
 * padding) to 16. There is deliberately no separate tag field here —
 * `key_lens[i] > LOCALS_INLINE_KEY_LEN` in the owning Locals is the tag
 * (set by LocalsKeyAssign, the only place that decides where a key
 * lives), and key_lens is already loaded on every hash-matched
 * comparison, so the discriminant costs nothing extra to check.
 */
typedef union {
    char inline_buf[LOCALS_INLINE_KEY_LEN + 1]; /**< Live when the entry's key_len <= LOCALS_INLINE_KEY_LEN. */
    char* heap;                                 /**< Live (malloc'd, exact-length) when key_len is larger. */
} KeyStorage;

/**
 * Per-request context store, structure-of-arrays layout.
 *
 * Fields are grouped by access pattern rather than by logical entry:
 * `hashes` is read on every LocalsGetValue/LocalsSetValue/LocalsRemove
 * call (the hot scan) and is small enough — 32 bytes at
 * LOCALS_INLINE_CAPACITY == 8 — to sit in half a cache line, so the
 * initial rejection pass touches almost no memory regardless of how many
 * entries are stored or how long their keys are. `key_lens` and `keys`
 * are only consulted once a hash matches, to rule out (rare) collisions
 * via memcmp; `values` and `free_funcs` are only touched on a confirmed
 * match.
 *
 * Keys are always copied, never referenced by pointer, so there is no
 * dependency on the caller's storage outliving the entry. Keys up to
 * LOCALS_INLINE_KEY_LEN are stored with no allocation; longer keys use
 * one malloc sized exactly to the key (see KeyStorage). This makes
 * dynamically-built keys (e.g. snprintf'd request-scoped identifiers)
 * correct rather than rejected, while keeping the common short-key case
 * allocation-free.
 *
 * The common case (0-3 short-keyed entries, no managed values) costs:
 *   - LocalsClear: one store of size=0, one store of managed_count=0.
 *   - LocalsGetValue: N hash compares (vectorizable, no pointer chase)
 *     + a memcmp only on a hash hit, N <= 3 in practice.
 *   - No malloc, no arena touch, no pointer chasing.
 *
 * Overflow beyond LOCALS_INLINE_CAPACITY is an assert in debug builds
 * and a silent drop in release — handlers setting 9+ locals is a design
 * problem, not a runtime condition to handle gracefully.
 *
 * NOT safe for concurrent use.
 */
typedef struct {
    uint32_t hashes[LOCALS_INLINE_CAPACITY];          /**< FNV-1a hash of each key; scanned first. */
    KeyStorage keys[LOCALS_INLINE_CAPACITY];          /**< Inline-or-heap key storage per entry. */
    uint16_t key_lens[LOCALS_INLINE_CAPACITY];        /**< strlen(key) per entry (16-bit: no cap on key length). */
    void* values[LOCALS_INLINE_CAPACITY];             /**< Caller-owned value pointers. */
    ValueFreeFunc free_funcs[LOCALS_INLINE_CAPACITY]; /**< Optional destructors. NULL for unmanaged values. */
    uint8_t size;                                     /**< Number of live entries. */
    uint8_t managed_count;                            /**< Entries with non-NULL free_func. */
} Locals;

/** Returns a read-only pointer to entry i's key bytes, wherever they live. */
static inline const char* LocalsKeyPtr(const Locals* locals, uint8_t i) {
    return locals->key_lens[i] > LOCALS_INLINE_KEY_LEN ? locals->keys[i].heap : locals->keys[i].inline_buf;
}

/** Frees entry i's heap buffer, if key_len indicates it has one. Caller is responsible for updating key_len/size
 * afterward. */
static inline void LocalsKeyDestroyAt(Locals* locals, uint8_t i) {
    if (locals->key_lens[i] > LOCALS_INLINE_KEY_LEN) {
        free(locals->keys[i].heap);
    }
}

/**
 * Copies `key` (length `key_len`) into `ks`, choosing inline storage or a
 * fresh heap allocation. Returns false on allocation failure for a long
 * key; `ks` is left unmodified in that case. The caller is responsible
 * for freeing whatever `ks` previously held (via LocalsKeyDestroyAt,
 * using the *old* key_len) before calling this, and for recording the
 * *new* key_len as the union's tag afterward.
 */
static inline bool LocalsKeyAssign(KeyStorage* ks, const char* key, uint16_t key_len) {
    if (key_len <= LOCALS_INLINE_KEY_LEN) {
        memcpy(ks->inline_buf, key, key_len);
        ks->inline_buf[key_len] = '\0';
        return true;
    }

    char* buf = malloc((size_t)key_len + 1);
    if (buf == NULL) return false;
    memcpy(buf, key, key_len);
    buf[key_len] = '\0';
    ks->heap = buf;
    return true;
}

/** Initialise an already-allocated Locals (embedded in PulsarConn). */
static inline void LocalsInit(Locals* locals) {
    locals->size = 0;
    locals->managed_count = 0;
}

/** Releases heap-backed keys and managed values, then resets to empty. Safe to call on an already-empty Locals. */
static inline void LocalsClear(Locals* locals) {
    for (uint8_t i = 0; i < locals->size; ++i) {
        if (locals->free_funcs[i] != NULL) {
            locals->free_funcs[i](locals->values[i]);
        }
        LocalsKeyDestroyAt(locals, i);
    }
    locals->size = 0;
    locals->managed_count = 0;
}

/**
 * Sets a local given an explicit key length. No limit on key_len: keys up
 * to LOCALS_INLINE_KEY_LEN are stored inline, longer keys spill to a
 * single heap allocation sized exactly to the key.
 *
 * Prefer the LocalsSet() macro at call sites where the key is a string
 * literal, to avoid the caller having to compute key_len manually. Use
 * this function directly when the key length is already known (e.g. from
 * a prior strlen() the caller needs anyway).
 *
 * Returns false if locals or key is NULL, if a long key's allocation
 * fails, or if the table is full and key is not an update to an existing
 * entry.
 */
static inline bool LocalsSetValueLen(Locals* locals, const char* key, size_t key_len, void* value,
                                     ValueFreeFunc free_func) {
    if (!locals || !key) return false;

    assert(key_len <= UINT16_MAX && "Locals key implausibly long — check the caller");
    const uint16_t klen = (uint16_t)key_len;
    const uint32_t khash = LocalsHashKey(key, klen);

    /* Update existing entry if key matches. Hash first: rejects nearly all
     * non-matching entries with a cheap integer compare, so memcmp only
     * runs on a hash hit (or collision) regardless of key length. */
    for (uint8_t i = 0; i < locals->size; ++i) {
        if (locals->hashes[i] == khash && locals->key_lens[i] == klen &&
            memcmp(LocalsKeyPtr(locals, i), key, klen) == 0) {
            if (locals->free_funcs[i] != NULL) {
                locals->free_funcs[i](locals->values[i]);
                locals->managed_count--;
            }
            locals->values[i] = value;
            locals->free_funcs[i] = free_func;
            if (free_func != NULL) locals->managed_count++;
            return true;
        }
    }

    /* New entry. */
    assert(locals->size < LOCALS_INLINE_CAPACITY && "Too many locals — increase LOCALS_INLINE_CAPACITY");

    if (locals->size >= LOCALS_INLINE_CAPACITY) return false;

    const uint8_t idx = locals->size;
    KeyStorage new_key; /* Union: no old key_len to free yet, this slot has never been written. */
    if (!LocalsKeyAssign(&new_key, key, klen)) return false; /* Allocation failed; nothing mutated yet. */

    locals->keys[idx] = new_key;
    locals->hashes[idx] = khash;
    locals->key_lens[idx] = klen; /* Sets the union's tag for this slot. */
    locals->values[idx] = value;
    locals->free_funcs[idx] = free_func;
    locals->size++;
    if (free_func != NULL) locals->managed_count++;
    return true;
}

/** Sets a local, computing the key length at runtime via strlen(). Prefer LocalsSet() for literal keys. */
static inline bool LocalsSetValue(Locals* locals, const char* key, void* value, ValueFreeFunc free_func) {
    if (!key) return false;
    return LocalsSetValueLen(locals, key, strlen(key), value, free_func);
}

/**
 * Gets a local given an explicit key length.
 *
 * Prefer the LocalsGet() macro at call sites where the key is a string
 * literal.
 */
static inline void* LocalsGetValueLen(const Locals* locals, const char* key, size_t key_len) {
    if (!locals || !key) return NULL;
    assert(key_len <= UINT16_MAX && "Locals key implausibly long — check the caller");
    const uint16_t klen = (uint16_t)key_len;
    const uint32_t khash = LocalsHashKey(key, klen);
    for (uint8_t i = 0; i < locals->size; ++i) {
        if (locals->hashes[i] == khash && locals->key_lens[i] == klen &&
            memcmp(LocalsKeyPtr(locals, i), key, klen) == 0)
            return locals->values[i];
    }
    return NULL;
}

/** Gets a local, computing the key length at runtime via strlen(). Prefer LocalsGet() for literal keys. */
static inline void* LocalsGetValue(const Locals* locals, const char* key) {
    if (!key) return NULL;
    return LocalsGetValueLen(locals, key, strlen(key));
}

/** Removes a local by key, if present, freeing its managed value and any heap-backed key. No-op if not found. */
static inline void LocalsRemove(Locals* locals, const char* key) {
    if (!locals || !key) return;
    const size_t key_len = strlen(key);
    assert(key_len <= UINT16_MAX && "Locals key implausibly long — check the caller");
    const uint16_t klen = (uint16_t)key_len;
    const uint32_t khash = LocalsHashKey(key, klen);

    for (uint8_t i = 0; i < locals->size; ++i) {
        if (locals->hashes[i] == khash && locals->key_lens[i] == klen &&
            memcmp(LocalsKeyPtr(locals, i), key, klen) == 0) {
            if (locals->free_funcs[i] != NULL) {
                locals->free_funcs[i](locals->values[i]);
                locals->managed_count--;
            }
            LocalsKeyDestroyAt(locals, i); /* Uses key_lens[i], which the shift below hasn't overwritten yet. */

            /* Shift remaining entries down to fill the gap. */
            for (uint8_t j = i; j < locals->size - 1u; ++j) {
                locals->hashes[j] = locals->hashes[j + 1];
                locals->keys[j] = locals->keys[j + 1];
                locals->key_lens[j] = locals->key_lens[j + 1];
                locals->values[j] = locals->values[j + 1];
                locals->free_funcs[j] = locals->free_funcs[j + 1];
            }
            locals->size--;
            return;
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif  // LOCALS_H
