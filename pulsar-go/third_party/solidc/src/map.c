/**
 * @file map.c
 * @brief Robin Hood hash map — open addressing with linear probing.
 *
 * Design
 * ------
 *
 * Layout
 *   keys_values[i*2]   key pointer for slot i    (NULL == empty slot)
 *   keys_values[i*2+1] value pointer for slot i
 *   deleted[i]         DIB (distance-from-initial-bucket) of the element
 *                      in slot i; 0 means "in its natural slot".  The
 *                      field name is historical — no tombstones exist.
 *
 * Probing
 *   Linear probing over a power-of-two capacity (index = (hash + step)
 *   & mask).  Sequential slots share cache lines, so a probe step usually
 *   costs no additional memory access.
 *
 * Robin Hood invariant
 *   An element never displaces an element whose DIB is smaller than its
 *   own current displacement — on insertion, the incoming element swaps
 *   with any "richer" (closer-to-home) resident and continues.  This keeps
 *   probe-length variance tight instead of letting early insertions hog
 *   their natural slots.
 *
 * Lookup early exit
 *   While probing for a key at displacement `d`, a resident with DIB < d
 *   proves the key is absent (it would have been robbed further along).
 *
 * Deletion
 *   Backward-shift: after removing an element, forward neighbours move
 *   into the hole while their DIB is nonzero (moving them shortens their
 *   probe).  The table therefore never contains tombstones and never
 *   degrades under deletion-heavy churn.
 *
 * Resizing
 *   Doubles capacity when load reaches max_load_factor (default 0.75).
 *   Rehash re-inserts every element using the same Robin Hood logic.
 *   Note: elements are re-hashed with the key_len of the call that
 *   triggered the resize — use consistent key_len values per logical key
 *   (see the contract comment on map_set in map.h).
 *
 * Hashing
 *   Keys of <= 8 bytes hash by identity (zero-padded little-endian read),
 *   which preserves integer ordering in bucket assignment; larger keys go
 *   through XXH3-64.
 */
#include <limits.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XXH_INLINE_ALL
#include "../include/cmp.h"
#include "../include/lock.h"
#include "../include/map.h"
#include "../include/platform.h"

#include <xxhash.h>

// Default maximum load factor
#define DEFAULT_MAX_LOAD_FACTOR 0.75f
#define MIN_CAPACITY            8  // Minimum capacity to avoid frequent resizing
#define MAX(a, b)               ((a) > (b) ? (a) : (b))

/* DIB (distance-from-initial-bucket) accessors. */
#define _RH_DIB(m, i)        ((m)->deleted[i])
#define _RH_SET_DIB(m, i, d) ((m)->deleted[i] = (size_t)(d))
/* Slot is empty when the key pointer is NULL. */
#define _RH_EMPTY(m, i) ((m)->keys_values[(i) * 2] == NULL)

typedef struct hash_map {
    void** keys_values;            // Interleaved keys and values for better cache locality
    size_t* deleted;               // DIB (distance-from-initial-bucket) array
    size_t size;                   // Number of active entries
    size_t capacity;               // Map capacity
    float max_load_factor;         // Configurable load factor threshold
    HashFunction hash;             // Hash function
    KeyCmpFunction key_compare;    // Key comparison function
    KeyFreeFunction key_free;      // Key free function (optional)
    ValueFreeFunction value_free;  // Value free function (optional)
    Lock lock;                     // Lock for thread safety
} HashMap;

// Hash for small keys (up to 8 bytes): zero-padded little-endian read.
// Identity for integers, which suits linear probing.  Measured note:
// memcpy-based and unrolled-load variants performed identically or worse
// through the indirect HashFunction call — keep the simple loop.
static inline uint64_t fast_small_hash(const void* key, size_t size) {
    // Use union to avoid strict aliasing violations
    union {
        uint64_t u64;
        uint32_t u32[2];
        uint16_t u16[4];
        uint8_t u8[8];
    } value = {0};

    // Copy only the needed bytes
    const uint8_t* src = (const uint8_t*)key;
    for (size_t i = 0; i < size && i < sizeof(value); i++) {
        value.u8[i] = src[i];
    }
    return value.u64;
}

// xxHash implementation with small key optimization
static inline unsigned long xxhash(const void* key, size_t size) {
    if (size <= sizeof(uint64_t)) {
        return fast_small_hash(key, size);
    }
    return XXH3_64bits(key, size);
}

// Helper function to calculate next power of two for better hashing
static inline size_t next_power_of_two(size_t n) {
    if (n == 0) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
#if SIZE_MAX > UINT32_MAX
    n |= n >> 32;
#endif
    return n + 1;
}

// Safe capacity growth calculation
static inline size_t calculate_new_capacity(size_t current) {
    if (current > SIZE_MAX / 2) {
        return SIZE_MAX;
    }
    size_t new_cap = current * 2;
    return (new_cap < current) ? SIZE_MAX : new_cap;
}

// Wrapper to match HashFunction signature
static inline size_t xxhash_wrapper(const void* key, size_t len) { return (size_t)xxhash(key, (size_t)len); }

// Map creation with better error handling and memory optimization
HashMap* map_create(const MapConfig* config) {
    if (!config || !config->key_compare) {
        return NULL;
    }

    size_t capacity = MAX(
        MIN_CAPACITY, config->initial_capacity > 0 ? next_power_of_two(config->initial_capacity) : INITIAL_MAP_SIZE);

    if (capacity > SIZE_MAX / 2) {
        return NULL;
    }

    float max_load_factor = config->max_load_factor > 0.1f && config->max_load_factor <= 0.95f
                                ? config->max_load_factor
                                : DEFAULT_MAX_LOAD_FACTOR;

    HashMap* m = (HashMap*)malloc(sizeof(HashMap));
    if (!m) {
        return NULL;
    }

    // Allocate interleaved keys and values for better cache locality
    m->keys_values = (void**)calloc(capacity * 2, sizeof(void*));
    m->deleted = (size_t*)calloc(capacity, sizeof(size_t));

    if (!m->keys_values || !m->deleted) {
        free(m->keys_values);
        free(m->deleted);
        free(m);
        return NULL;
    }

    m->size = 0;
    m->capacity = capacity;
    m->max_load_factor = max_load_factor;
    m->hash = config->hash_func ? config->hash_func : xxhash_wrapper;
    m->key_compare = config->key_compare;
    m->key_free = config->key_free;
    m->value_free = config->value_free;

    lock_init(&m->lock);
    return m;
}

// Helper to get key pointer from interleaved array
static inline void** get_key_ptr(HashMap* m, size_t index) { return &m->keys_values[index * 2]; }

// Helper to get value pointer from interleaved array
static inline void** get_value_ptr(HashMap* m, size_t index) { return &m->keys_values[index * 2 + 1]; }

// map_resize — grow to @p new_capacity and re-insert every element.
// Allocation failure leaves the original table untouched.
static bool map_resize(HashMap* m, size_t new_capacity, size_t key_len) {
    if (new_capacity <= m->capacity || new_capacity > SIZE_MAX / 2) {
        return false;
    }

    void** new_keys_values = (void**)calloc(new_capacity * 2, sizeof(void*));
    size_t* new_deleted = (size_t*)calloc(new_capacity, sizeof(size_t));

    if (!new_keys_values || !new_deleted) {
        free(new_keys_values);
        free(new_deleted);
        return false;
    }

    // Save old data
    void** old_keys_values = m->keys_values;
    size_t* old_deleted = m->deleted;
    size_t old_capacity = m->capacity;

    // Swap in new arrays
    m->keys_values = new_keys_values;
    m->deleted = new_deleted;
    m->capacity = new_capacity;
    m->size = 0;

    // Rehash all active entries using Robin Hood linear probing (matching map_set)
    const size_t mask = new_capacity - 1;
    for (size_t i = 0; i < old_capacity; i++) {
        if (old_keys_values[i * 2] && old_keys_values[i * 2] != NULL) {
            void* ins_key = old_keys_values[i * 2];
            void* ins_value = old_keys_values[i * 2 + 1];

            size_t hash = m->hash(ins_key, key_len);
            size_t idx = hash & mask;
            size_t ins_dist = 0;

            for (size_t j = 0; j < new_capacity; j++) {
                if (_RH_EMPTY(m, idx)) {
                    *get_key_ptr(m, idx) = ins_key;
                    *get_value_ptr(m, idx) = ins_value;
                    _RH_SET_DIB(m, idx, ins_dist);
                    m->size++;
                    break;
                }

                // Robin Hood: steal from richer elements
                size_t cur_dist = _RH_DIB(m, idx);
                if (cur_dist < ins_dist) {
                    void* tmp_k = *get_key_ptr(m, idx);
                    void* tmp_v = *get_value_ptr(m, idx);
                    *get_key_ptr(m, idx) = ins_key;
                    *get_value_ptr(m, idx) = ins_value;
                    _RH_SET_DIB(m, idx, ins_dist);
                    ins_key = tmp_k;
                    ins_value = tmp_v;
                    ins_dist = cur_dist;
                }

                idx = (idx + 1) & mask;
                ins_dist++;
            }
        }
    }

    free(old_keys_values);
    free(old_deleted);
    return true;
}

size_t map_length(HashMap* m) { return m->size; }

// map_set — insert or update.  Grows the table first when the insert
// would push load past max_load_factor.
bool map_set(HashMap* m, void* key, size_t key_len, void* value) {
    if (!m || !key) return false;

    /* Grow before inserting if load would exceed threshold. */
    size_t total_used = m->size; /* no tombstones in Robin Hood */
    if ((float)total_used / (float)m->capacity >= m->max_load_factor) {
        size_t new_cap = calculate_new_capacity(m->capacity);
        if (new_cap <= m->capacity || !map_resize(m, new_cap, key_len)) return false;
    }

    const size_t mask = m->capacity - 1;
    size_t hash = m->hash(key, key_len);
    size_t idx = hash & mask;

    /* The element we're about to insert. */
    void* ins_key = key;
    void* ins_value = value;
    size_t ins_dist = 0;

    for (size_t i = 0; i < m->capacity; i++) {
        if (_RH_EMPTY(m, idx)) {
            /* Empty slot — place the element here. */
            *get_key_ptr(m, idx) = ins_key;
            *get_value_ptr(m, idx) = ins_value;
            _RH_SET_DIB(m, idx, ins_dist);
            m->size++;
            return true;
        }

        /* Slot occupied.  Check for key match (update). */
        void** cur_kp = get_key_ptr(m, idx);
        if (m->key_compare(*cur_kp, ins_key)) {
            /* Key already exists — update value. */
            if (m->value_free) m->value_free(*get_value_ptr(m, idx));
            *get_value_ptr(m, idx) = ins_value;
            return true;
        }

        /* Robin Hood: if resident has smaller DIB ("richer"), steal its slot. */
        size_t cur_dist = _RH_DIB(m, idx);
        if (cur_dist < ins_dist) {
            /* Swap incoming element with resident. */
            void* tmp_k = *cur_kp;
            void* tmp_v = *get_value_ptr(m, idx);

            *get_key_ptr(m, idx) = ins_key;
            *get_value_ptr(m, idx) = ins_value;
            _RH_SET_DIB(m, idx, ins_dist);

            ins_key = tmp_k;
            ins_value = tmp_v;
            ins_dist = cur_dist;
        }

        idx = (idx + 1) & mask;
        ins_dist++;
    }

    return false; /* table full (shouldn't happen at <75% load) */
}

// map_get — lookup using the Robin Hood early exit.
void* map_get(HashMap* m, void* key, size_t key_len) {
    if (!m || !key) return NULL;

    const size_t hash = m->hash(key, key_len);
    const size_t mask = m->capacity - 1;
    size_t idx = hash & mask;

    for (size_t dist = 0; dist < m->capacity; dist++) {
        if (_RH_EMPTY(m, idx)) return NULL;

        /* Robin Hood early exit: element would have robbed this slot. */
        if (_RH_DIB(m, idx) < dist) return NULL;

        void** kp = get_key_ptr(m, idx);
        if (m->key_compare(*kp, key)) return *get_value_ptr(m, idx);

        idx = (idx + 1) & mask;
    }
    return NULL;
}

// map_remove — locate, then backward-shift displaced neighbours into
// the vacated run so no tombstone is left behind.
bool map_remove(HashMap* m, void* key, size_t key_len) {
    if (!m || !key) return false;

    const size_t mask = m->capacity - 1;
    size_t hash = m->hash(key, key_len);
    size_t idx = hash & mask;

    /* Locate the element. */
    size_t pos = SIZE_MAX;
    for (size_t dist = 0; dist < m->capacity; dist++) {
        if (_RH_EMPTY(m, idx)) return false;
        if (_RH_DIB(m, idx) < dist) return false; /* Robin Hood miss */

        if (m->key_compare(*get_key_ptr(m, idx), key)) {
            pos = idx;
            break;
        }
        idx = (idx + 1) & mask;
    }
    if (pos == SIZE_MAX) return false;

    /* Free key/value if cleanup functions were provided. */
    if (m->key_free) m->key_free(*get_key_ptr(m, pos));
    if (m->value_free) m->value_free(*get_value_ptr(m, pos));

    /* Backward-shift: pull forward any displaced neighbours. */
    size_t hole = pos;
    for (;;) {
        size_t next = (hole + 1) & mask;
        if (_RH_EMPTY(m, next) || _RH_DIB(m, next) == 0) break;

        /* Move next into hole and decrement its DIB. */
        *get_key_ptr(m, hole) = *get_key_ptr(m, next);
        *get_value_ptr(m, hole) = *get_value_ptr(m, next);
        _RH_SET_DIB(m, hole, _RH_DIB(m, next) - 1);

        hole = next;
    }

    /* Mark the last vacated slot as empty. */
    *get_key_ptr(m, hole) = NULL;
    *get_value_ptr(m, hole) = NULL;
    _RH_SET_DIB(m, hole, 0);
    m->size--;
    return true;
}

void map_destroy(HashMap* m) {
    if (!m) return;

    // no cleanup functions are provided
    if (!m->key_free && !m->value_free) {
        goto cleanup;
    }

    void** keys_values = m->keys_values;
    size_t capacity = m->capacity;
    KeyFreeFunction key_free = m->key_free;
    ValueFreeFunction value_free = m->value_free;

    for (size_t i = 0; i < capacity; i++) {
        void* key = keys_values[i * 2];
        if (key) {
            if (key_free) key_free(key);
            if (value_free) value_free(keys_values[i * 2 + 1]);
        }
    }

cleanup:
    free(m->keys_values);
    free(m->deleted);
    lock_free(&m->lock);
    free(m);
}

map_iterator map_iter(HashMap* map) {
    map_iterator it = {.map = map, .index = 0};
    return it;
}

bool map_next(map_iterator* it, void** key, void** value) {
    HashMap* map = it->map;
    size_t capacity = map->capacity;
    void** keys_values = map->keys_values;
    size_t index = it->index;

    while (index < capacity) {
        void* current_key = keys_values[index * 2];
        if (current_key) {
            if (key) *key = current_key;
            if (value) *value = keys_values[index * 2 + 1];
            it->index = index + 1;
            return true;
        }
        index++;
    }
    it->index = capacity;
    return false;
}

// Thread-safe operations
bool map_set_safe(HashMap* m, void* key, size_t key_len, void* value) {
    lock_acquire(&m->lock);
    bool result = map_set(m, key, key_len, value);
    lock_release(&m->lock);
    return result;
}

void* map_get_safe(HashMap* m, void* key, size_t key_len) {
    lock_acquire(&m->lock);
    void* value = map_get(m, key, key_len);
    lock_release(&m->lock);
    return value;
}

bool map_remove_safe(HashMap* m, void* key, size_t key_len) {
    lock_acquire(&m->lock);
    bool result = map_remove(m, key, key_len);
    lock_release(&m->lock);
    return result;
}
