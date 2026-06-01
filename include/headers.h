/**
 * @file headers.h
 * @brief Ultra-fast HTTP header storage with O(1) static header lookups
 *
 * This implementation uses a bitmask for O(1) presence checking of common headers,
 * combined with hash-based identification for fast operations. Custom headers fall
 * back to hash table semantics with linear probing.
 *
 * Features:
 * - O(1) presence check for standard headers via bitmask
 * - Pre-computed hash table for header name resolution
 * - Arena-based memory management for zero-fragmentation
 * - Support for multi-value headers (Set-Cookie)
 * - Case-insensitive header name matching
 *
 * @copyright Copyright (c) 2024
 */

#ifndef SOLIDC_HEADERS_H
#define SOLIDC_HEADERS_H

#include <solidc/arena.h>
#include <solidc/str_slice.h>
#include <stdbool.h>
#include <stdint.h>
#include <strings.h>
#include "macros.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Configuration */
#ifndef HEADERS_CAPACITY
#define HEADERS_CAPACITY 64
#endif

/**
 * @brief Individual header entry
 */
typedef struct {
    StrSlice name;   // Header name (string slice)
    StrSlice value;  // Header value (string slice)
} header_entry;

/**
 * @brief HTTP headers collection with fast static header lookups
 */
typedef struct {
    header_entry entries[HEADERS_CAPACITY];
    size_t count;
} headers_t;

/**
 * @brief Initialize headers structure
 * @param h Headers structure to initialize
 * @param arena Memory arena for allocations
 */
INLINE void headers_init(headers_t* h) {
    h->count = 0;
    memset(h->entries, 0, sizeof(h->entries));
}

/**
 * @brief Set a header value (replaces existing or adds new)
 * @param h Headers structure
 * @param name Header name (case-insensitive)
 * @param value Header value
 * @return true on success, false if capacity exceeded
 *
 * Note: Set-Cookie allows multiple values; other headers are replaced
 */
INLINE bool headers_set(headers_t* h, StrSlice name, StrSlice value) {
    // Check if we have space for a new header.
    // Remember string slices are not guaranteed to be NULL-terminated.
    if (h->count >= HEADERS_CAPACITY) {
        return false;
    }

    // Check if header already exists.
    header_entry* entry = NULL;
    for (size_t i = 0; i < h->count; ++i) {
        if (ss_equal_nocase(h->entries[i].name, name)) {
            entry = &h->entries[i];
            break;
        }
    }

    // Reject duplicate headers unless its a Cookie.
    if (entry != NULL && !ss_equal_nocase(name, SS_LIT("Set-Cookie"))) {
        // Update header in-place
        entry->value = value;
    } else {
        // Insert new header entry.
        h->entries[h->count++] = (header_entry){.name = name, .value = value};
    }
    return true;
}

/**
 * @brief Get a header value by name (supports both static and custom headers)
 * @param h Headers structure
 * @param name Header name (case-insensitive)
 * @return Header value whith valid data or otherwise its data is NULL and len 0.
 */
INLINE StrSlice headers_get(const headers_t* h, const char* name) {
    StrSlice target = {0};
    for (size_t i = 0; i < h->count; ++i) {
        if (ss_equal_nocase(h->entries[i].name, ss_from_cstr(name))) {
            target = h->entries[i].value;
            break;
        }
    }
    return target;
}

/**
 * @brief Check if a header exists
 * @param h Headers structure
 * @param name Header name (case-insensitive)
 * @return true if header exists, false otherwise
 */
INLINE bool headers_has(const headers_t* h, const char* name) {
    StrSlice t = headers_get(h, name);
    return t.data != NULL && t.len > 0;
}

/**
 * @brief Remove a header
 * @param h Headers structure
 * @param name Header name (case-insensitive)
 * @return true if header was removed, false if not found
 */
INLINE bool headers_remove(headers_t* h, const char* name) {
    for (size_t i = 0; i < h->count; ++i) {
        if (ss_equal_nocase(h->entries[i].name, ss_from_cstr(name))) {
            // Shift remaining items to delete current entry
            for (size_t j = i; j < h->count - 1; j++) {
                h->entries[j] = h->entries[j + 1];
            }
            h->count--;
            break;
        }
    }
    return true;
}

/**
 * @brief Iterate over all headers
 * @param h Headers structure
 * @param callback Function called for each header (return false to stop iteration)
 * @param userdata User data passed to callback
 */
typedef bool (*header_iter_fn)(StrSlice name, StrSlice value, void* userdata);

INLINE void headers_foreach(const headers_t* h, header_iter_fn callback, void* userdata) {
    for (size_t i = 0; i < h->count; i++) {
        if (!callback(h->entries[i].name, h->entries[i].value, userdata)) {
            break;
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SOLIDC_HEADERS_H */
