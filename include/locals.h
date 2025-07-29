#ifndef LOCALS_H
#define LOCALS_H

#include "constants.h"

#ifdef __cplusplus
extern "C" {
#endif

// Callback function type for freeing values
typedef void (*ValueFreeFunc)(void* value);

// Key-Value pair for the Locals.
typedef struct {
    char key[LOCALS_KEY_CAPACITY];  // Unique string for key.
    void* value;                    // Value associated with key
    ValueFreeFunc free_func;        // Function pointer to free values.
} KeyValue;

// The keys are managed by the Locals structure.
// Values are freed using the provided free function or NULL if they are not
// to be free'd.
typedef struct {
    KeyValue entries[LOCALS_CAPACITY];
    size_t size;
} Locals;

// Initialize locals structure.
void LocalsInit(Locals* locals);

// Store value with unique key. If key already exists, it will be freed using
// the ValueFreeFunc passed.
// Returns true on success or false if Locals is full or an error occurs.
bool LocalsSetValue(Locals* locals, const char* key, void* value, ValueFreeFunc value_free_func);

// Get the value associated with the key.
void* LocalsGetValue(Locals* locals, const char* key);

// Delete key-value pair from locals.
void LocalsRemove(Locals* locals, const char* key);

// Reset locals for reuse - clears all entries but keeps allocated memory
void LocalsReset(Locals* locals);

#ifdef __cplusplus
}
#endif

#endif  // LOCALS_H
