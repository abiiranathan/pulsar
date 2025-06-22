#ifndef HEADERS_H
#define HEADERS_H

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>

#include "arena.h"

#define MAX_HEADERS 64  // Maximum req/res headers.

typedef struct header_t {
    char* name;
    char* value;
    struct header_t* next;  // For chaining collisions
} header_t;

typedef struct {
    header_t* buckets[MAX_HEADERS];  // Hash buckets with chaining
    size_t count;
} headers_t;

// Case-insensitive hash function for header names
static inline uint32_t header_name_hash(const char* name) {
    uint32_t hash = 5381;
    int c;
    while ((c = *name++)) {
        hash = ((hash << 5) + hash) ^ tolower(c);
    }
    return hash % MAX_HEADERS;
}

static inline headers_t* headers_new(Arena* arena) {
    headers_t* headers = arena_alloc(arena, sizeof(headers_t));
    if (!headers) return NULL;

    headers->count = 0;

    // Initialize all buckets to NULL
    for (size_t i = 0; i < MAX_HEADERS; i++) {
        headers->buckets[i] = NULL;
    }
    return headers;
}

// Insert/replace header. Will fails if no more room for the new header.
// In our impl: name and value MUST point to owned memory (arena in our case) and will not be duplicated.
static inline bool headers_set(Arena* arena, headers_t* headers, char* name, char* value) {
    assert(arena && name && value);

    uint32_t hash_pos  = header_name_hash(name);
    header_t* existing = NULL;
    header_t* current  = headers->buckets[hash_pos];

    // Check if header already exists in this bucket
    while (current) {
        if (strcasecmp(name, current->name) == 0) {
            existing = current;
            break;
        }
        current = current->next;
    }

    // If it's a new header and we're at capacity, bail
    if (!existing && headers->count >= MAX_HEADERS) {
        return false;
    }

    // Create new header (or reuse existing)
    header_t* hdr;
    if (existing) {
        hdr = existing;
        // We would free old value here if we weren't using an arena.
        hdr->value = value;
    } else {
        // new header.
        hdr = arena_alloc(arena, sizeof(header_t));
        if (!hdr) return false;

        hdr->name  = name;   // already allocated in the arena (so not copied)
        hdr->value = value;  // already allocated in the arena (so not copied)
        hdr->next  = NULL;

        // Add to bucket
        if (headers->buckets[hash_pos]) {
            // Add to end of chain
            header_t* last = headers->buckets[hash_pos];
            while (last->next) {
                last = last->next;
            }
            last->next = hdr;
        } else {
            // First in bucket
            headers->buckets[hash_pos] = hdr;
        }

        headers->count++;
    }
    return true;
}

static inline const char* headers_get(headers_t* headers, const char* name) {
    uint32_t hash_pos = header_name_hash(name);
    header_t* current = headers->buckets[hash_pos];

    while (current) {
        if (strcasecmp(name, current->name) == 0) {
            return current->value;
        }
        current = current->next;
    }
    return NULL;
}

// Optional: Function to clean up headers
static inline void headers_clear(headers_t* headers) {
    // With arena allocation, this might not be needed
    // as the arena will handle cleanup
    for (size_t i = 0; i < MAX_HEADERS; i++) {
        headers->buckets[i] = NULL;
    }
    headers->count = 0;
}

// Iterator macro
// Outer loop iterates through all buckets
// Inner loop traverses each chain in a bucket
#define headers_foreach(headers, item)                                                                                 \
    for (size_t _bucket = 0; _bucket < MAX_HEADERS; _bucket++)                                                         \
        for (header_t* item = (headers)->buckets[_bucket]; item != NULL; item = item->next)

#endif /* HEADERS_H */
