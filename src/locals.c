#include "../include/locals.h"
#include <stdio.h>   // for fprintf, stderr
#include <stdlib.h>  // for malloc, free
#include <string.h>  // for strcmp, strlen, memcpy

/** Default initial capacity if not specified */
static const size_t DEFAULT_CAPACITY = 8;

/** Growth factor when resizing */
static const size_t GROWTH_FACTOR = 2;

/**
 * Grow the entries array to accommodate more entries.
 * @param locals Pointer to Locals structure.
 * @return true on success, false on allocation failure.
 */
static inline bool grow_capacity(Locals* locals) {
    const size_t new_capacity = locals->capacity * GROWTH_FACTOR;

    // Allocate new entries array from arena
    KeyValue* new_entries = ARENA_ALLOC_ARRAY(locals->arena, KeyValue, new_capacity);
    if (new_entries == NULL) {
        return false;
    }

    // Copy existing entries to new array
    if (locals->entries != NULL && locals->size > 0) {
        memcpy(new_entries, locals->entries, locals->size * sizeof(KeyValue));
    }

    // Update to new array (old array is arena-allocated, no need to free)
    locals->entries  = new_entries;
    locals->capacity = new_capacity;
    return true;
}

Locals* LocalsInit(size_t initial_capacity, Arena* arena) {
    if (arena == NULL) {
        return NULL;
    }

    // Use default capacity if not specified
    const size_t capacity = (initial_capacity > 0) ? initial_capacity : DEFAULT_CAPACITY;

    // Allocate the Locals structure itself (NOT from arena)
    Locals* locals = malloc(sizeof(*locals));
    if (locals == NULL) {
        return NULL;
    }

    // Allocate initial entries array from arena
    locals->entries = ARENA_ALLOC_ARRAY(arena, KeyValue, capacity);
    if (locals->entries == NULL) {
        free(locals);
        return NULL;
    }

    locals->size     = 0;
    locals->capacity = capacity;
    locals->arena    = arena;
    return locals;
}

bool LocalsSetValue(Locals* locals, const char* key, void* value, ValueFreeFunc free_func) {
    if (locals == NULL || key == NULL) {
        return false;
    }

    // Check if key already exists and replace if found
    for (size_t i = 0; i < locals->size; ++i) {
        if (strcmp(locals->entries[i].key, key) == 0) {
            // Free old value if it has a free function
            if (locals->entries[i].free_func != NULL) {
                locals->entries[i].free_func(locals->entries[i].value);
            }

            // Update with new value and free function
            // Key remains the same (arena-allocated, no need to duplicate again)
            locals->entries[i].value     = value;
            locals->entries[i].free_func = free_func;
            return true;
        }
    }

    // Key doesn't exist - need to add new entry
    // Check if we need to grow capacity
    if (locals->size >= locals->capacity) {
        if (!grow_capacity(locals)) {
            return false;
        }
    }

    // Duplicate the key string into arena
    const char* key_copy = arena_strdup(locals->arena, key);
    if (key_copy == NULL) {
        fprintf(stderr, "Failed to duplicate key: %s\n", key);
        return false;
    }

    // Add new entry
    locals->entries[locals->size].key       = key_copy;
    locals->entries[locals->size].value     = value;
    locals->entries[locals->size].free_func = free_func;
    locals->size++;
    return true;
}

void* LocalsGetValue(const Locals* locals, const char* key) {
    if (locals == NULL || key == NULL) {
        return NULL;
    }

    // Linear search through entries
    for (size_t i = 0; i < locals->size; ++i) {
        if (strcmp(locals->entries[i].key, key) == 0) {
            return locals->entries[i].value;
        }
    }

    return NULL;
}

bool LocalsRemove(Locals* locals, const char* key) {
    if (locals == NULL || key == NULL) {
        return false;
    }

    // Find the entry to remove
    for (size_t i = 0; i < locals->size; ++i) {
        if (strcmp(locals->entries[i].key, key) == 0) {
            // Free the value if it has a free function
            if (locals->entries[i].free_func != NULL) {
                locals->entries[i].free_func(locals->entries[i].value);
            }

            // Key is arena-allocated, no need to free individually

            // Shift remaining entries down to fill the gap
            for (size_t j = i; j < locals->size - 1; ++j) {
                locals->entries[j] = locals->entries[j + 1];
            }

            locals->size--;
            return true;
        }
    }

    return false;  // Key not found
}

void LocalsClear(Locals* locals) {
    if (locals == NULL) {
        return;
    }

    // Free all values that have free functions
    for (size_t i = 0; i < locals->size; ++i) {
        if (locals->entries[i].free_func != NULL) {
            locals->entries[i].free_func(locals->entries[i].value);
        }
    }

    // Reset size to 0 (reuse existing entries array)
    locals->size = 0;
}

bool LocalsReinitAfterArenaReset(Locals* locals) {
    if (locals == NULL || locals->arena == NULL) {
        return false;
    }

    // Reallocate entries array from fresh arena
    locals->entries = ARENA_ALLOC_ARRAY(locals->arena, KeyValue, locals->capacity);
    if (locals->entries == NULL) {
        return false;
    }

    locals->size = 0;
    return true;
}

void LocalsDestroy(Locals* locals) {
    if (locals == NULL) {
        return;
    }

    // Free all values that have free functions
    for (size_t i = 0; i < locals->size; ++i) {
        if (locals->entries[i].free_func != NULL) {
            locals->entries[i].free_func(locals->entries[i].value);
        }
    }

    // Zero out the structure for safety
    locals->entries  = NULL;
    locals->arena    = NULL;
    locals->capacity = 0;
    locals->size     = 0;

    // Free the Locals structure itself
    free(locals);
}
