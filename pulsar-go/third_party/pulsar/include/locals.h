#ifndef LOCALS_H
#define LOCALS_H

#include <stdbool.h>  // for bool
#include <stddef.h>   // for NULL, size_t
#include <stdint.h>   // for uint32_t
#include <stdio.h>    // for fprintf, stderr
#include <stdlib.h>   // for malloc, realloc, free
#include <string.h>   // for strcmp, memcpy

/** Number of inline entries stored directly in a Locals before spilling to heap. */
#define LOCALS_INLINE_CAPACITY 8

/** Growth factor applied to heap capacity when the array must grow. */
#define LOCALS_GROWTH_FACTOR 2

#ifdef __cplusplus
extern "C" {
#endif

/** Callback function type for freeing values. */
typedef void (*ValueFreeFunc)(void* value);

/** Key-Value pair for Locals. */
typedef struct {
    const char* key;         /**< Should be a literal or you control its lifetime. */
    void* value;             /**< Caller-owned value pointer. */
    ValueFreeFunc free_func; /**< Optional destructor. NULL for unmanaged values. */
} KeyValue;

/**
 * Key-value store for per-request context.
 *
 * Starts backed by a small inline array. If a request needs more than
 * LOCALS_INLINE_CAPACITY entries, storage spills to a heap-allocated array
 * that grows by LOCALS_GROWTH_FACTOR as needed. locals_reset() frees managed
 * values and either keeps the heap array for reuse by the next request or,
 * if its capacity has grown past shrink_threshold, frees it and falls back
 * to the inline array. Not safe for concurrent use; each Locals is intended
 * to be owned by a single connection/request at a time.
 */
typedef struct {
    KeyValue inline_entries[LOCALS_INLINE_CAPACITY]; /**< First-tier storage. */
    KeyValue* heap_entries;    /**< Second-tier storage. NULL until first spill. */
    uint32_t heap_capacity;    /**< Allocated capacity of heap_entries, in entries. */
    uint32_t shrink_threshold; /**< If heap_capacity exceeds this after a reset, heap_entries is
                                  freed. */
    uint32_t size;             /**< Number of live entries (in inline_entries or heap_entries). */
} Locals;

/**
 * Returns a pointer to entry i, whether it currently lives in the inline
 * array or the heap array. Internal helper — callers should not need to
 * know which tier an entry lives in.
 */
static inline KeyValue* locals_entry_at(Locals* locals, uint32_t i) {
    return locals->heap_entries != NULL ? &locals->heap_entries[i] : &locals->inline_entries[i];
}

static inline const KeyValue* locals_entry_at_const(const Locals* locals, uint32_t i) {
    return locals->heap_entries != NULL ? &locals->heap_entries[i] : &locals->inline_entries[i];
}

/**
 * Initialises an already-allocated Locals (e.g. embedded in a connection struct).
 * @param locals Locals to initialise. Must not be NULL.
 * @param shrink_threshold If, after a reset, the heap array's capacity exceeds
 *        this many entries, it is freed and the Locals falls back to its
 *        inline array on next use. Pass 0 to never shrink (keep whatever
 *        capacity was grown into for the lifetime of this Locals).
 */
static inline void locals_init(Locals* locals, uint32_t shrink_threshold) {
    locals->heap_entries = NULL;
    locals->heap_capacity = 0;
    locals->shrink_threshold = shrink_threshold;
    locals->size = 0;
}

/**
 * Frees all managed values, resets size to zero, and — if the heap array's
 * capacity exceeds shrink_threshold (and shrink_threshold is nonzero) —
 * frees the heap array so subsequent use falls back to the inline tier.
 * Safe to call repeatedly. Does not free the Locals struct itself.
 */
static inline void locals_reset(Locals* locals) {
    for (uint32_t i = 0; i < locals->size; ++i) {
        KeyValue* kv = locals_entry_at(locals, i);
        if (kv->free_func != NULL) kv->free_func(kv->value);
    }
    locals->size = 0;

    if (locals->shrink_threshold != 0 && locals->heap_capacity > locals->shrink_threshold) {
        free(locals->heap_entries);
        locals->heap_entries = NULL;
        locals->heap_capacity = 0;
    }
}

/**
 * Ensures capacity for at least one more entry beyond locals->size, spilling
 * to (or growing) the heap array if the inline tier is full. Returns false
 * on allocation failure, leaving locals unchanged.
 */
static inline bool locals_ensure_capacity(Locals* locals) {
    /* Still room inline (only reachable before the first spill). */
    if (locals->heap_entries == NULL && locals->size < LOCALS_INLINE_CAPACITY) {
        return true;
    }

    uint32_t needed = locals->size + 1;
    if (needed <= locals->heap_capacity) {
        return true;
    }

    uint32_t new_capacity = locals->heap_capacity == 0
                                ? (uint32_t)(LOCALS_INLINE_CAPACITY * LOCALS_GROWTH_FACTOR)
                                : locals->heap_capacity * LOCALS_GROWTH_FACTOR;
    if (new_capacity < needed) new_capacity = needed;

    KeyValue* new_entries = (KeyValue*)malloc(new_capacity * sizeof(KeyValue));
    if (new_entries == NULL) {
        fprintf(stderr, "locals: allocation of %u entries failed\n", new_capacity);
        return false;
    }

    /* Copy existing live entries from whichever tier currently holds them. */
    const KeyValue* src =
        locals->heap_entries != NULL ? locals->heap_entries : locals->inline_entries;
    memcpy(new_entries, src, locals->size * sizeof(KeyValue));

    free(locals->heap_entries); /* No-op if still NULL (first spill). */
    locals->heap_entries = new_entries;
    locals->heap_capacity = new_capacity;
    return true;
}

/**
 * Finds the index of key in locals, or -1 if not present.
 * Internal helper shared by set/get/remove to avoid duplicating the scan.
 */
static inline int locals_find(const Locals* locals, const char* key) {
    for (uint32_t i = 0; i < locals->size; ++i) {
        if (strcmp(locals_entry_at_const(locals, i)->key, key) == 0) return (int)i;
    }
    return -1;
}

/**
 * Sets key to value, replacing any existing entry for key (freeing its old
 * value first if it had a free_func). Grows into (or within) the heap tier
 * if the inline tier is full. Returns false only on allocation failure.
 */
static inline bool locals_setvalue(Locals* locals, const char* key, void* value,
                                   ValueFreeFunc free_func) {
    if (!locals || !key) return false;

    int idx = locals_find(locals, key);
    if (idx >= 0) {
        KeyValue* kv = locals_entry_at(locals, (uint32_t)idx);
        if (kv->free_func != NULL) kv->free_func(kv->value);
        kv->value = value;
        kv->free_func = free_func;
        return true;
    }

    if (!locals_ensure_capacity(locals)) return false;

    KeyValue* slot = locals_entry_at(locals, locals->size);
    *slot = (KeyValue){
        .key = key, /* caller owns; typically a string literal */
        .value = value,
        .free_func = free_func,
    };
    locals->size++;
    return true;
}

/** Returns the value for key, or NULL if not present. */
static inline void* locals_getvalue(const Locals* locals, const char* key) {
    if (!locals || !key) return NULL;
    int idx = locals_find(locals, key);
    return idx >= 0 ? locals_entry_at_const(locals, (uint32_t)idx)->value : NULL;
}

/** Removes key, freeing its value if it had a free_func. No-op if absent. */
static inline void locals_remove(Locals* locals, const char* key) {
    if (!locals || !key) return;

    int idx = locals_find(locals, key);
    if (idx < 0) return;

    KeyValue* kv = locals_entry_at(locals, (uint32_t)idx);
    if (kv->free_func != NULL) kv->free_func(kv->value);

    /* Shift remaining entries down to fill the gap. */
    for (uint32_t i = (uint32_t)idx; i < locals->size - 1; ++i) {
        *locals_entry_at(locals, i) = *locals_entry_at(locals, i + 1);
    }
    locals->size--;
}

/**
 * Releases all resources owned by locals, including the heap array if one
 * was allocated. Call this when the Locals itself is being torn down
 * (e.g. the owning connection is being destroyed), not between requests —
 * use locals_reset() for that.
 */
static inline void locals_destroy(Locals* locals) {
    if (locals == NULL) return;
    for (uint32_t i = 0; i < locals->size; ++i) {
        KeyValue* kv = locals_entry_at(locals, i);
        if (kv->free_func != NULL) kv->free_func(kv->value);
    }
    free(locals->heap_entries);
    locals->heap_entries = NULL;
    locals->heap_capacity = 0;
    locals->size = 0;
}

#ifdef __cplusplus
}
#endif

#endif  // LOCALS_H
