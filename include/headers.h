#ifndef __HEADERS_H__
#define __HEADERS_H__

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <xxhash.h>
#include "arena.h"
#include "mimetype.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HEADERS_CAPACITY 64  // Must be power of 2
static_assert(IS_POWER_OF_TWO(HEADERS_CAPACITY));

#define HEADERS_MASK (HEADERS_CAPACITY - 1)

typedef struct {
    char* name;
    char* value;
    uint64_t hash;
} header_entry;

typedef struct {
    header_entry entries[HEADERS_CAPACITY];
    uint64_t occupied_bitmask;  // Tracks occupied slots
    Arena* arena;
} headers_t;

// Initialize headers map
static inline headers_t* headers_new(Arena* arena) {
    headers_t* map = arena_alloc(arena, sizeof(headers_t));
    if (!map)
        return NULL;

    memset(map, 0, sizeof(headers_t));
    map->arena = arena;
    return map;
}

// Fast ASCII lowercase conversion
static inline void strtolower(char* s) {
    for (; *s; ++s) {
        *s = (*s >= 'A' && *s <= 'Z') ? (*s | 0x20) : *s;
    }
}

// Find entry using quadratic probing
static inline header_entry* headers_find_entry(headers_t* map, const char* name, uint64_t hash) {
    uint32_t index = hash & HEADERS_MASK;
    uint32_t probe = 0;

    while (1) {
        header_entry* entry = &map->entries[index];

        // Empty slot or matching entry
        if (!(map->occupied_bitmask & (1ULL << index))) {
            return entry;
        }
        if (entry->hash == hash && strcasecmp(entry->name, name) == 0) {
            return entry;
        }

        // Quadratic probing
        probe++;
        index = (index + probe) & HEADERS_MASK;
    }
}

// Set a header
static inline bool headers_set(headers_t* map, char* name, char* value) {
    strtolower(name);
    uint64_t hash = XXH3_64bits(name, strlen(name));

    // Special case: Set-Cookie can have multiple entries
    if (unlikely(strcasecmp(name, "set-cookie") == 0)) {
        // Find an empty slot by linear probing.
        for (uint32_t probe = 0; probe < HEADERS_CAPACITY; probe++) {
            uint32_t index = (hash + probe) & HEADERS_MASK;
            if (!(map->occupied_bitmask & (1ULL << index))) {
                // Found an empty slot
                header_entry* entry = &map->entries[index];
                entry->name         = name;
                entry->value        = value;
                entry->hash         = hash;
                map->occupied_bitmask |= (1ULL << index);
                return true;
            }
        }
        return false;  // No space left
    }

    header_entry* entry = headers_find_entry(map, name, hash);
    uint32_t index      = entry - map->entries;

    if (likely(!(map->occupied_bitmask & (1ULL << index)))) {
        // New entry
        if (map->occupied_bitmask == ~0ULL) {
            return false;  // Full
        }
        entry->name  = name;
        entry->value = value;
        entry->hash  = hash;
        map->occupied_bitmask |= (1ULL << index);
    } else {
        // Update existing
        entry->value = value;
    }

    return true;
}

// Get a header
static inline const char* headers_get(const headers_t* map, const char* name) {
    char lower_name[256];
    size_t len = strlen(name);
    if (len >= sizeof(lower_name))
        return NULL;

    // Convert to lowercase (ASCII only)
    for (size_t i = 0; i < len; i++) {
        char c        = name[i];
        lower_name[i] = (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
    }
    lower_name[len] = '\0';

    uint64_t hash  = XXH3_64bits(lower_name, len);
    uint32_t index = hash & HEADERS_MASK;
    uint32_t probe = 0;

    while (1) {
        const header_entry* entry = &map->entries[index];

        if (!(map->occupied_bitmask & (1ULL << index))) {
            return NULL;
        }
        if (entry->hash == hash && strcmp(entry->name, lower_name) == 0) {
            return entry->value;
        }

        probe++;
        index = (index + probe) & HEADERS_MASK;
    }
}

// Clear all headers
static inline void headers_clear(headers_t* map) {
    memset(map->entries, 0, sizeof(map->entries));
    map->occupied_bitmask = 0;
}

// Iterator
#define headers_foreach(map, item)                                                                           \
    for (uint64_t _mask = (map)->occupied_bitmask; _mask; _mask &= _mask - 1)                                \
        for (uint32_t _pos = __builtin_ctzll(_mask), _done = 0; !_done; _done = 1)                           \
            for (header_entry* item = &(map)->entries[_pos]; item; item = NULL)

#ifdef __cplusplus
}
#endif

#endif  // __HEADERS_H__
