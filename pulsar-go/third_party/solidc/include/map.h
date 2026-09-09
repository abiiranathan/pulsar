/**
 * @file map.h
 * @brief Generic hash map implementation with customizable hashing and load balancing.
 */

#ifndef SOLIDC_MAP_H
#define SOLIDC_MAP_H

#include "./cmp.h"

#include <float.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Allow user to customize initial map size and load factor threshold
#ifndef INITIAL_MAP_SIZE
    #define INITIAL_MAP_SIZE (size_t)16
#endif

#ifndef LOAD_FACTOR_THRESHOLD
    #define LOAD_FACTOR_THRESHOLD (double)0.75
#endif

// Define alignment for cache line optimization
#define CACHE_LINE_SIZE 64

// Cross-platform prefetch macros
#if defined(__GNUC__) || defined(__clang__)
    #define PREFETCH_READ(addr)  __builtin_prefetch((addr), 0, 3)
    #define PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
    #include <intrin.h>
    #define PREFETCH_READ(addr)  _mm_prefetch((char*)(addr), _MM_HINT_T0)
    #define PREFETCH_WRITE(addr) _mm_prefetch((char*)(addr), _MM_HINT_T0)
#elif defined(__has_builtin)
    #if __has_builtin(__builtin_prefetch)
        #define PREFETCH_READ(addr)  __builtin_prefetch((addr), 0, 3)
        #define PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)
    #else
        #define PREFETCH_READ(addr)  ((void)0)
        #define PREFETCH_WRITE(addr) ((void)0)
    #endif
#else
    #define PREFETCH_READ(addr)  ((void)0)
    #define PREFETCH_WRITE(addr) ((void)0)
#endif

typedef size_t (*HashFunction)(const void* key, size_t size);
typedef bool (*KeyCmpFunction)(const void* key1, const void* key2);
typedef void (*KeyFreeFunction)(void* key);
typedef void (*ValueFreeFunction)(void* value);

typedef struct {
    size_t initial_capacity;       // Initial size of the map. If zero, the default size
                                   // is used.
    KeyCmpFunction key_compare;    // Required: Key comparison function
    KeyFreeFunction key_free;      // Optional: Key cleanup function. Default is free from libc.
    ValueFreeFunction value_free;  // Optional: Value cleanup function. Default is
                                   // free from libc.
    float max_load_factor;         // Optional: When to resize (default 0.75)
    HashFunction hash_func;        // Optional: Custom hash function
} MapConfig;

#define MapConfigInt    (&(MapConfig){.key_compare = key_compare_int})
#define MapConfigFloat  (&(MapConfig){.key_compare = key_compare_float})
#define MapConfigDouble (&(MapConfig){.key_compare = key_compare_double})
#define MapConfigStr    (&(MapConfig){.key_compare = key_compare_char_ptr})

// Generic map implementation using xxhash as the hash function.
typedef struct hash_map HashMap;

// Create a new map and initialize it. If the initial capacity is 0, a default
// capacity is used, otherwise its used as it.
// key_compare is a function pointer used to compare 2 keys for equality.
// If free_entries is true, the keys and values are also freed.
HashMap* map_create(const MapConfig* config);

// Destroy the map and free the memory.
void map_destroy(HashMap* m);

// Set a key-value pair in the map
// This is idempotent. Returns true on success, false on failure.
//
// OWNERSHIP & LIFETIME CONTRACT (critical):
//   - The map stores @p key BY POINTER.  The pointed-to key must remain
//     valid and UNMODIFIED for as long as the entry lives, because both
//     the hash on resize and every equality probe re-read its contents.
//     Passing `&local_var` whose value changes between calls aliases all
//     previously inserted entries (they share one address) and degrades
//     the table into duplicate-key chains — measured 500x slowdown at
//     N=200k in benchmarks.  Use stable storage (heap, static, or a
//     container that outlives the map).
//   - If key_free/value_free are configured they take ownership of the
//     stored pointers; otherwise the caller retains ownership.
//
// key_len is the number of bytes to hash from @p key.  All keys in one map
// must be hashed consistently: use the same key_len for identical logical
// keys, and note that resize re-hashes stored keys with the key_len of the
// call that triggered it.
bool map_set(HashMap* m, void* key, size_t key_len, void* value);

// A thread-safe version of map_set. Returns true on success, false on failure.
bool map_set_safe(HashMap* m, void* key, size_t key_len, void* value);

// Get the value for a key in the map without locking
void* map_get(HashMap* m, void* key, size_t key_len);

// Get the value for a key in the map with locking
void* map_get_safe(HashMap* m, void* key, size_t key_len);

// Remove a key from the map without locking. Returns true if key was found and removed.
bool map_remove(HashMap* m, void* key, size_t key_len);

// Remove a key from the map with locking. Returns true if key was found and removed.
bool map_remove_safe(HashMap* m, void* key, size_t key_len);

// Iterator implementation
typedef struct {
    HashMap* map;
    size_t index;
} map_iterator;

// Create a map iterator.
map_iterator map_iter(HashMap* m);

// Advance to the next valid entry in the map.
bool map_next(map_iterator* it, void** key, void** value);

// Get the number of key-value pairs in the map
size_t map_length(HashMap* m);

// Get the capacity of the map
size_t map_capacity(HashMap* m);

static inline bool key_compare_int(const void* a, const void* b) { return a && b && *(const int*)a == *(const int*)b; }

static inline bool key_compare_char_ptr(const void* a, const void* b) {
    return a && b && strcmp((const char*)a, (const char*)b) == 0;
}

static inline bool key_compare_float(const void* a, const void* b) {
    return a && b && cmp_float(*(const float*)a, *(const float*)b, (cmp_config_t){.epsilon = FLT_EPSILON});
}

static inline bool key_compare_double(const void* a, const void* b) {
    return a && b && cmp_double(*(const double*)a, *(const double*)b, (cmp_config_t){.epsilon = DBL_EPSILON});
}

#if defined(__cplusplus)
}
#endif

#endif /* SOLIDC_MAP_H */
