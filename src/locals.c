#include "../include/locals.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// FNV-1a hash function for strings - fast and good distribution
static inline uint32_t hash_string(const char* str) {
    uint32_t hash = 2166136261u;
    for (const char* p = str; *p; ++p) {
        hash ^= (uint32_t)*p;
        hash *= 16777619u;
    }
    return hash;
}

// Find slot for key, returns index or SIZE_MAX if table is full
static size_t find_slot(const Locals* locals, const char* key, bool for_insert) {
    if (locals->size == LOCALS_CAPACITY && for_insert) {
        return SIZE_MAX;  // Table full
    }

    const uint32_t hash = hash_string(key);
    size_t index        = hash & (LOCALS_CAPACITY - 1);  // Assumes LOCALS_CAPACITY is power of 2

    for (size_t i = 0; i < LOCALS_CAPACITY; ++i) {
        const size_t current  = (index + i) & (LOCALS_CAPACITY - 1);
        const KeyValue* entry = &locals->entries[current];

        if (!entry->key) {
            // Empty slot found
            return for_insert ? current : SIZE_MAX;
        }

        if (strcmp(entry->key, key) == 0) {
            // Key found
            return current;
        }
    }

    return SIZE_MAX;  // Should never reach here if table isn't full
}

void LocalsInit(Locals* locals, ValueFreeFunc value_free_func, void* user_data) {
    if (!locals) {
        return;
    }

    // Zero out all entries
    memset(locals->entries, 0, sizeof(locals->entries));
    locals->size            = 0;
    locals->value_free_func = value_free_func;
    locals->user_data       = user_data;
}

Locals* LocalsNew(ValueFreeFunc value_free_func, void* user_data) {
    Locals* locals = malloc(sizeof(Locals));
    if (!locals) {
        return nullptr;
    }

    LocalsInit(locals, value_free_func, user_data);
    return locals;
}

bool LocalsSetValue(Locals* locals, const char* key, const void* value) {
    const size_t slot = find_slot(locals, key, false);

    if (slot != SIZE_MAX) {
        // Key exists, replace value
        KeyValue* entry = &locals->entries[slot];
        void* old_value = (void*)entry->value;

        // Free the old value using callback if provided
        if (locals->value_free_func && old_value) {
            locals->value_free_func(key, old_value, locals->user_data);
        }

        entry->value = value;
        return old_value;  // Return for compatibility, but it's been freed
    }

    // Key doesn't exist, find insertion slot
    const size_t insert_slot = find_slot(locals, key, true);
    if (insert_slot == SIZE_MAX) {
        return false;  // Table full
    }

    // Allocate and copy key
    const size_t key_len = strlen(key) + 1;
    char* key_copy       = malloc(key_len);
    if (!key_copy) {
        return false;
    }
    memcpy(key_copy, key, key_len);

    // Insert new entry
    KeyValue* entry = &locals->entries[insert_slot];
    entry->key      = key_copy;
    entry->value    = value;

    // Track this slot as used
    locals->used_slots[locals->size] = insert_slot;
    ++locals->size;
    return true;  // No old value
}

void* LocalsGetValue(Locals* locals, const char* key) {
    if (!locals || !key) {
        return nullptr;
    }

    const size_t slot = find_slot(locals, key, false);
    if (slot == SIZE_MAX) {
        return nullptr;
    }

    return (void*)locals->entries[slot].value;
}

void* LocalsRemove(Locals* locals, const char* key) {
    if (!locals || !key) {
        return nullptr;
    }

    const size_t slot = find_slot(locals, key, false);
    if (slot == SIZE_MAX) {
        return nullptr;  // Key not found
    }

    KeyValue* entry = &locals->entries[slot];
    void* old_value = (void*)entry->value;

    // Free the value using callback if provided
    if (locals->value_free_func && old_value) {
        locals->value_free_func(key, old_value, locals->user_data);
    }

    // Remove from used_slots array
    for (size_t i = 0; i < locals->size; ++i) {
        if (locals->used_slots[i] == slot) {
            // Move last element to fill the gap
            locals->used_slots[i] = locals->used_slots[locals->size - 1];
            break;
        }
    }

    // Free the key and mark slot as empty
    free(entry->key);
    entry->key   = nullptr;
    entry->value = nullptr;
    --locals->size;

    // Rehash entries that might have been displaced by linear probing
    // This maintains the hash table invariant after deletion
    size_t current_slot = slot;
    for (size_t i = 1; i < LOCALS_CAPACITY; ++i) {
        const size_t next_slot = (slot + i) & (LOCALS_CAPACITY - 1);
        KeyValue* next_entry   = &locals->entries[next_slot];

        if (!next_entry->key) {
            break;  // End of probe sequence
        }

        // Check if this entry can be moved to fill the gap
        const uint32_t hash         = hash_string(next_entry->key);
        const size_t preferred_slot = hash & (LOCALS_CAPACITY - 1);

        // If the preferred slot is between the deleted slot and current position,
        // we need to move this entry back
        bool should_move;
        if (current_slot <= next_slot) {
            should_move = (preferred_slot <= current_slot) || (preferred_slot > next_slot);
        } else {
            should_move = (preferred_slot <= current_slot) && (preferred_slot > next_slot);
        }

        if (should_move) {
            // Move entry to fill the gap
            locals->entries[current_slot] = *next_entry;
            next_entry->key               = nullptr;
            next_entry->value             = nullptr;

            // Update used_slots array
            for (size_t j = 0; j < locals->size; ++j) {
                if (locals->used_slots[j] == next_slot) {
                    locals->used_slots[j] = current_slot;
                    break;
                }
            }

            // Continue from the slot we just cleared
            i            = 0;
            current_slot = next_slot;
        }
    }

    return old_value;  // Return for compatibility, but it's been freed
}

void LocalsReset(Locals* locals) {
    if (!locals) {
        return;
    }

    // Only iterate over slots that actually contain data
    for (size_t i = 0; i < locals->size; ++i) {
        const size_t slot_index = locals->used_slots[i];
        KeyValue* entry         = &locals->entries[slot_index];

        // Free the value using callback if provided
        if (locals->value_free_func && entry->value) {
            locals->value_free_func(entry->key, (void*)entry->value, locals->user_data);
        }

        free(entry->key);
        entry->key   = nullptr;
        entry->value = nullptr;
    }

    locals->size = 0;
}

void LocalsDestroy(Locals* locals) {
    if (!locals) {
        return;
    }

    LocalsReset(locals);
    free(locals);
}
