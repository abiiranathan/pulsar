#ifndef LOCALS_H
#define LOCALS_H

#include <assert.h>
#include <solidc/arena.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Callback function type for freeing values. */
typedef void (*ValueFreeFunc)(void* value);

/** Maximum number of inline locals entries before spilling to heap. */
#define LOCALS_INLINE_CAPACITY 8

/** Key-Value pair for Locals. */
typedef struct {
    const char* key;         /**< Points into arena (set path) or literal (common path). */
    void* value;             /**< Caller-owned value pointer. */
    ValueFreeFunc free_func; /**< Optional destructor. NULL for unmanaged values. */
    uint16_t key_len;        /**< Cached strlen(key) for faster comparison. */
} KeyValue;

/**
 * Flat inline key-value store for per-request context.
 *
 * The common case (0-3 entries, no managed values) costs exactly:
 *   - LocalsClear: one store of size=0, one store of managed_count=0.
 *   - LocalsGetValue: N strcmp calls, N <= 3 in practice.
 *   - No malloc, no arena touch, no pointer chasing.
 *
 * The inline array holds LOCALS_INLINE_CAPACITY entries without any
 * allocation. Overflow beyond that capacity is an assert in debug builds
 * and a silent drop in release — handlers setting 9+ locals is a design
 * problem, not a runtime condition to handle gracefully.
 *
 * NOT safe for concurrent use.
 */
typedef struct {
    KeyValue entries[LOCALS_INLINE_CAPACITY]; /**< Inline storage. */
    uint8_t size;                             /**< Number of live entries. */
    uint8_t managed_count;                    /**< Entries with non-NULL free_func. */
} Locals;

/** Initialise an already-allocated Locals (embedded in PulsarConn). */
static inline void LocalsInit(Locals* locals) {
    locals->size = 0;
    locals->managed_count = 0;
}

static inline void LocalsClear(Locals* locals) {
    if (locals->managed_count > 0) {
        for (uint8_t i = 0; i < locals->size; ++i) {
            if (locals->entries[i].free_func != NULL) locals->entries[i].free_func(locals->entries[i].value);
        }
    }
    locals->size = 0;
    locals->managed_count = 0;
}

static inline bool LocalsSetValue(Locals* locals, const char* key, void* value, ValueFreeFunc free_func) {
    if (!locals || !key) return false;

    const uint16_t klen = (uint16_t)strlen(key);

    /* Update existing entry if key matches. */
    for (uint8_t i = 0; i < locals->size; ++i) {
        if (locals->entries[i].key_len == klen && memcmp(locals->entries[i].key, key, klen) == 0) {
            if (locals->entries[i].free_func != NULL) {
                locals->entries[i].free_func(locals->entries[i].value);
                locals->managed_count--;
            }
            locals->entries[i].value = value;
            locals->entries[i].free_func = free_func;
            if (free_func != NULL) locals->managed_count++;
            return true;
        }
    }

    /* New entry. */
    assert(locals->size < LOCALS_INLINE_CAPACITY && "Too many locals — increase LOCALS_INLINE_CAPACITY");

    if (locals->size >= LOCALS_INLINE_CAPACITY) return false;

    locals->entries[locals->size] = (KeyValue){
        .key = key, /* caller owns; typically a string literal */
        .value = value,
        .free_func = free_func,
        .key_len = klen,
    };
    locals->size++;
    if (free_func != NULL) locals->managed_count++;
    return true;
}

static inline void* LocalsGetValue(const Locals* locals, const char* key) {
    if (!locals || !key) return NULL;
    const uint16_t klen = (uint16_t)strlen(key);
    for (uint8_t i = 0; i < locals->size; ++i) {
        if (locals->entries[i].key_len == klen && memcmp(locals->entries[i].key, key, klen) == 0)
            return locals->entries[i].value;
    }
    return NULL;
}

static inline void LocalsRemove(Locals* locals, const char* key) {
    if (!locals || !key) return;
    const uint16_t klen = (uint16_t)strlen(key);
    for (uint8_t i = 0; i < locals->size; ++i) {
        if (locals->entries[i].key_len == klen && memcmp(locals->entries[i].key, key, klen) == 0) {
            if (locals->entries[i].free_func != NULL) {
                locals->entries[i].free_func(locals->entries[i].value);
                locals->managed_count--;
            }

            /* Shift remaining entries down to fill the gap. */
            for (uint8_t j = i; j < locals->size - 1; ++j) {
                locals->entries[j] = locals->entries[j + 1];
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
