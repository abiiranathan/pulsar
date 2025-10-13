#include "../include/locals.h"
#include <stdint.h>
#include <stdio.h>   // for fprintf, stderr
#include <stdlib.h>  // for calloc, free, reallocarray
#include <string.h>  // for strcmp, strncpy, memset

#define LOCALS_DEFAULT_CAPACITY 4

bool LocalsInit(Locals* locals) {
    if (!locals) {
        fprintf(stderr, "LocalsInit: NULL locals pointer\n");
        return false;
    }

    locals->size     = 0;
    locals->capacity = LOCALS_DEFAULT_CAPACITY;
    locals->entries  = calloc(locals->capacity, sizeof(KeyValue));
    if (!locals->entries) {
        fprintf(stderr, "LocalsInit: Memory allocation failed(capacity => %zu)\n",
                locals->capacity);
        return false;
    }

    return true;
}

bool LocalsSetValue(Locals* locals, const char* key, void* value, ValueFreeFunc free_func) {
    if (!locals || !key) {
        fprintf(stderr, "LocalsSetValue: NULL parameter\n");
        return false;
    }

    // Validate key length early before any modifications
    const size_t keylen = strlen(key);
    if (keylen >= LOCALS_KEY_CAPACITY) {
        fprintf(stderr, "LocalsSetValue: Key too long (max %d, got %zu): %s\n",
                LOCALS_KEY_CAPACITY - 1, keylen, key);
        return false;
    }

    // Check if key exists and update in-place
    for (size_t i = 0; i < locals->size; ++i) {
        if (strcmp(locals->entries[i].key, key) == 0) {
            // Free old value if it has a destructor
            if (locals->entries[i].free_func && locals->entries[i].value) {
                locals->entries[i].free_func(locals->entries[i].value);
            }
            // Update with new value
            locals->entries[i].value     = value;
            locals->entries[i].free_func = free_func;
            return true;
        }
    }

    // Need to add new entry - check capacity and grow if needed
    if (locals->size >= locals->capacity) {
        size_t new_capacity = locals->capacity * 2;

        // Check for overflow
        if (new_capacity < locals->capacity) {
            fprintf(stderr, "LocalsSetValue: Capacity overflow\n");
            return false;
        }

        KeyValue* new_entries = reallocarray(locals->entries, new_capacity, sizeof(KeyValue));
        if (!new_entries) {  // ✓ Check the NEW pointer
            fprintf(stderr, "LocalsSetValue: Memory reallocation failed\n");
            return false;
        }

        locals->entries  = new_entries;
        locals->capacity = new_capacity;
    }

    // Add new entry at the end
    KeyValue* kv = &locals->entries[locals->size];
    strncpy(kv->key, key, LOCALS_KEY_CAPACITY - 1);
    kv->key[LOCALS_KEY_CAPACITY - 1] = '\0';  // Ensure NUL termination
    kv->value                        = value;
    kv->free_func                    = free_func;

    locals->size++;
    return true;
}

void* LocalsGetValue(Locals* locals, const char* key) {
    if (!locals || !key) {
        return NULL;
    }

    for (size_t i = 0; i < locals->size; ++i) {
        if (strcmp(locals->entries[i].key, key) == 0) {
            return locals->entries[i].value;
        }
    }

    return NULL;
}

void LocalsRemove(Locals* locals, const char* key) {
    if (!locals || !key) {
        return;
    }

    for (size_t i = 0; i < locals->size; ++i) {
        if (strcmp(locals->entries[i].key, key) == 0) {
            // Free the value if it has a destructor
            if (locals->entries[i].free_func && locals->entries[i].value) {
                locals->entries[i].free_func(locals->entries[i].value);
            }

            // Shift remaining entries down (memmove is safe for overlapping memory)
            if (i < locals->size - 1) {
                memmove(&locals->entries[i], &locals->entries[i + 1],
                        (locals->size - i - 1) * sizeof(KeyValue));
            }

            locals->size--;
            return;
        }
    }
}

void LocalsReset(Locals* locals) {
    if (!locals) {
        return;
    }

    // Free all values with registered destructors
    for (size_t i = 0; i < locals->size; ++i) {
        if (locals->entries[i].free_func && locals->entries[i].value) {
            locals->entries[i].free_func(locals->entries[i].value);
        }
    }

    locals->size = 0;
    // Note: Memset skipped for performance - entries will be overwritten
}

void LocalsDestroy(Locals* locals) {
    if (!locals || !locals->entries) {
        return;
    }

    LocalsReset(locals);
    free(locals->entries);

    // mark as destroyed
    locals->entries  = NULL;
    locals->size     = 0;
    locals->capacity = 0;
}
