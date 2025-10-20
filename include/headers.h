#ifndef HEADERS_H
#define HEADERS_H

#include <solidc/arena.h>
#include <stdbool.h>
#include <stddef.h>
#include <strings.h>
#include "constants.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char* name;
    char* value;
} header_entry;

typedef struct {
    header_entry entries[HEADERS_CAPACITY];
    size_t count;
    Arena* arena;
} headers_t;

// Initialize headers
INLINE headers_t* headers_new(Arena* arena) {
    headers_t* headers = arena_alloc(arena, sizeof(headers_t));
    if (!headers) return NULL;
    headers->arena = arena;
    headers->count = 0;
    // headers->entries not zeroed as an optimization.
    return headers;
}

// Set a header (case-insensitive)
INLINE bool headers_set(headers_t* headers, const char* name, const char* value) {
    if (headers->count >= HEADERS_CAPACITY) return false;

    // Check if header already exists (update if found)
    for (size_t i = 0; i < headers->count; i++) {
        if (strcasecmp(headers->entries[i].name, name) == 0) {
            char* new_value = arena_strdup(headers->arena, value);
            if (!new_value) return false;

            headers->entries[i].value = new_value;

            // Set-Cookie is a special header that can be set multiple times.
            if ((strcasecmp(name, "Set-Cookie") == 0)) {
                goto new_header;
            }
            return true;
        }
    }

new_header:
    bool state = false;
    // Add new header with copied strings
    char* new_name  = arena_strdup(headers->arena, name);
    char* new_value = arena_strdup(headers->arena, value);
    if (new_name && new_value) {
        headers->entries[headers->count].name  = new_name;
        headers->entries[headers->count].value = new_value;
        headers->count++;
        state = true;
    }

    return state;
}

// Get a header (case-insensitive)
INLINE const char* headers_get(const headers_t* headers, const char* name) {
    for (size_t i = 0; i < headers->count; i++) {
        if (strcasecmp(headers->entries[i].name, name) == 0) {
            return headers->entries[i].value;
        }
    }
    return NULL;
}

// Iterator
#define headers_foreach(headers, item)                                                             \
    if (headers)                                                                                   \
        for (size_t _i = 0; _i < (headers)->count && ((item) = &(headers)->entries[_i], 1); _i++)

#ifdef __cplusplus
}
#endif

#endif /* HEADERS_H */
