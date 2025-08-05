#include "../include/locals.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void LocalsInit(Locals* locals) {
    memset(locals->entries, 0, sizeof(locals->entries));
    locals->size = 0;
}

bool LocalsSetValue(Locals* locals, const char* key, void* value, ValueFreeFunc free_func) {
    // Check if key already exists and replace if found
    for (size_t i = 0; i < locals->size; ++i) {
        if (strcmp(locals->entries[i].key, key) == 0) {
            // Free the existing value if it has a free function
            if (locals->entries[i].free_func) {
                locals->entries[i].free_func((void*)locals->entries[i].value);
            }

            // Replace with new value
            locals->entries[i].value     = value;
            locals->entries[i].free_func = free_func;
            return true;
        }
    }

    // Key doesn't exist, validate key length before adding
    const size_t keylen = strlen(key);
    if (keylen >= LOCALS_KEY_CAPACITY) {
        fprintf(stderr, "Key length must not exceed: %d, %s is %lu bytes\n", LOCALS_KEY_CAPACITY - 1, key,
                keylen);
        return false;
    }

    // Check capacity
    if (locals->size >= LOCALS_CAPACITY) {
        fprintf(stderr, "Exceeded maximum capacity for locals: Key '%s' not stored\n", key);
        return false;
    }

    KeyValue kv = {.value = value, .free_func = free_func};
    strncpy(kv.key, key, LOCALS_KEY_CAPACITY - 1);
    kv.key[keylen] = '\0';

    locals->entries[locals->size++] = kv;
    return true;
}

void* LocalsGetValue(Locals* locals, const char* key) {
    for (size_t i = 0; i < locals->size; ++i) {
        if (strcmp(locals->entries[i].key, key) == 0) {
            return locals->entries[i].value;
        }
    }
    return NULL;
}

void LocalsRemove(Locals* locals, const char* key) {
    for (size_t i = 0; i < locals->size; ++i) {
        if (strcmp(locals->entries[i].key, key) == 0) {
            // Free the value if it has a free function
            if (locals->entries[i].free_func) {
                locals->entries[i].free_func((void*)locals->entries[i].value);
            }

            // Shift remaining entries down to fill the gap
            for (size_t j = i; j < locals->size - 1; ++j) {
                locals->entries[j] = locals->entries[j + 1];
            }

            // Clear the last entry and decrement size
            memset(&locals->entries[locals->size - 1], 0, sizeof(KeyValue));
            locals->size--;
            return;
        }
    }
}

void LocalsReset(Locals* locals) {
    if (!locals) return;

    // Free all values.
    for (size_t i = 0; i < locals->size; ++i) {
        if (locals->entries[i].free_func) {
            locals->entries[i].free_func((void*)locals->entries[i].value);
        }
    }
    LocalsInit(locals);
}
