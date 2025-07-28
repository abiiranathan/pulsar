#ifndef LOCALS_H
#define LOCALS_H

#include "constants.h"

#ifdef __cplusplus
extern "C" {
#endif

// Key-Value pair for the Locals.
typedef struct {
    char* key;          // Unique string for key.
    const void* value;  // Value associated with key
} KeyValue;

// Callback function type for freeing values
// key: the key associated with the value (for context)
// value: the value to be freed
// user_data: user-provided context passed during LocalsNew
typedef void (*ValueFreeFunc)(const char* key, void* value, void* user_data);

// map-like data structure that stores connection context values.
// The keys are managed by the Locals structure.
// Values are freed using the provided callback function.
typedef struct {
    KeyValue entries[LOCALS_CAPACITY];   // LOCALS_CAPACITY is a power of 2.
    size_t size;                         // Number of entries.
    size_t used_slots[LOCALS_CAPACITY];  // Indices of non-empty slots
    ValueFreeFunc value_free_func;       // Callback to free values
    void* user_data;                     // User context for the callback
} Locals;

// Create a new locals structure.
// value_free_func: callback to free values (can be NULL if no freeing needed)
// user_data: context passed to the callback function
Locals* LocalsNew(ValueFreeFunc value_free_func, void* user_data);

// Store value with unique key. If key already exists, it will be freed using
// the ValueFreeFunc passed during creation.
// Returns true on success or false if Locals is full or an error occurs.
bool LocalsSetValue(Locals* locals, const char* key, const void* value);

// Get the value associated with the key.
void* LocalsGetValue(Locals* locals, const char* key);

// Delete key-value pair from locals. This only deleted the key.
// Since value is managed by caller its returned from the function
// so its your responsibility to free it. If no key exists, it returns NULL.
void* LocalsRemove(Locals* locals, const char* key);

// Reset locals for reuse - clears all entries but keeps allocated memory
void LocalsReset(Locals* locals);

// Free memory used by locals.
void LocalsDestroy(Locals* locals);

#ifdef __cplusplus
}
#endif

#endif  // LOCALS_H
