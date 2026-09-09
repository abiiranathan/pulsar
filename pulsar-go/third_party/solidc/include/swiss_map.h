/**
 * @file swiss_map.h
 * @brief Swiss table hash map (SIMD group probing) — experimental sibling
 *        of HashMap in map.h, sharing its semantics and ownership contract.
 *
 * Design (abseil-style flat table, simplified):
 *   - Power-of-two capacity, always a multiple of 16.
 *   - One control byte per slot: 0x80 = empty, 0xFE = tombstone,
 *     otherwise bits 0..6 of the hash ("H2").  A 16-byte SIMD group
 *     scan tests 16 slots per probe step; an extra mirrored group at
 *     the end of the array removes wraparound branches.
 *   - H1 = hash >> 7 selects the starting group; groups are visited in
 *     a triangular stride so long probe chains still terminate.
 *   - Deletion leaves a tombstone; when tombstone pressure builds the
 *     table rehashes in place instead of growing.
 *
 * The public contract (pointer-stored keys, key_len consistency,
 * optional free callbacks) matches map.h exactly — see the ownership
 * note on map_set().
 */

#ifndef SOLIDC_SWISS_MAP_H
#define SOLIDC_SWISS_MAP_H

#include "./map.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct swiss_map SwissMap;

typedef struct {
    size_t initial_capacity;
    KeyCmpFunction key_compare;   /* Required */
    KeyFreeFunction key_free;     /* Optional */
    ValueFreeFunction value_free; /* Optional */
    float max_load_factor;        /* Optional, clamped to (0.1, 0.875] */
    HashFunction hash_func;       /* Optional, defaults to xxhash3/small-key identity */
} SwissConfig;

#define SwissConfigInt    (&(SwissConfig){.key_compare = key_compare_int})
#define SwissConfigFloat  (&(SwissConfig){.key_compare = key_compare_float})
#define SwissConfigDouble (&(SwissConfig){.key_compare = key_compare_double})
#define SwissConfigStr    (&(SwissConfig){.key_compare = key_compare_char_ptr})

SwissMap* swiss_create(const SwissConfig* config);
void swiss_destroy(SwissMap* m);
bool swiss_set(SwissMap* m, void* key, size_t key_len, void* value);
void* swiss_get(SwissMap* m, void* key, size_t key_len);
bool swiss_remove(SwissMap* m, void* key, size_t key_len);

typedef struct {
    SwissMap* map;
    size_t index;
} swiss_iterator;

swiss_iterator swiss_iter(SwissMap* m);
bool swiss_next(swiss_iterator* it, void** key, void** value);

size_t swiss_length(SwissMap* m);
size_t swiss_capacity(SwissMap* m);

/** Thread-safe variants (whole-operation locking). */
bool swiss_set_safe(SwissMap* m, void* key, size_t key_len, void* value);
void* swiss_get_safe(SwissMap* m, void* key, size_t key_len);
bool swiss_remove_safe(SwissMap* m, void* key, size_t key_len);

#if defined(__cplusplus)
}
#endif

#endif /* SOLIDC_SWISS_MAP_H */
