#ifndef LOCALS_H
#define LOCALS_H

#include <stdbool.h>
#include <stddef.h>
#include "constants.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback function type for freeing dynamically allocated values.
 * @param value Pointer to the value to free. Must handle NULL gracefully.
 */
typedef void (*ValueFreeFunc)(void* value);

/**
 * Key-value pair entry in the Locals storage.
 * Keys are stored inline with fixed capacity for cache locality.
 */
typedef struct {
    char key[LOCALS_KEY_CAPACITY]; /** Fixed-size key buffer (NUL-terminated) */
    void* value;                   /** Associated value pointer (nullable) */
    ValueFreeFunc free_func;       /** Optional destructor for value (nullable) */
} KeyValue;

/**
 * Dynamic key-value storage with automatic growth.
 * Thread-safety: NOT thread-safe. Caller must synchronize access.
 * Memory management: Owns the entries array. Values are freed via free_func.
 */
typedef struct {
    KeyValue* entries; /** Dynamic array of key-value pairs */
    size_t size;       /** Current number of entries */
    size_t capacity;   /** Allocated capacity */
} Locals;

/**
 * Initializes a Locals structure with default capacity.
 *
 * @param locals Pointer to uninitialized Locals structure. Must not be NULL.
 * @return true on success, false on allocation failure.
 * @note Caller must call LocalsDestroy() to free resources.
 */
bool LocalsInit(Locals* locals);

/**
 * Stores or updates a key-value pair.
 * If key exists, the old value is freed and replaced.
 * If key is new and capacity is exceeded, the array automatically grows.
 *
 * @param locals Pointer to initialized Locals. Must not be NULL.
 * @param key Key string. Must not be NULL. Length must be < LOCALS_KEY_CAPACITY.
 * @param value Value pointer. Can be NULL. Ownership transferred to Locals.
 * @param free_func Destructor for value. Pass NULL if value should not be freed.
 * @return true on success, false if key too long or allocation fails.
 */
bool LocalsSetValue(Locals* locals, const char* key, void* value, ValueFreeFunc free_func);

/**
 * Retrieves the value associated with a key.
 *
 * @param locals Pointer to initialized Locals. Must not be NULL.
 * @param key Key string to search for. Must not be NULL.
 * @return Associated value pointer, or NULL if key not found.
 * @note Returns the value pointer directly - caller must not free it.
 */
void* LocalsGetValue(Locals* locals, const char* key);

/**
 * Removes a key-value pair from the storage.
 * If the key exists, its value is freed and the entry is removed.
 * Remaining entries are shifted down to fill the gap (O(n) operation).
 *
 * @param locals Pointer to initialized Locals. Must not be NULL.
 * @param key Key string to remove. Must not be NULL.
 * @note No-op if key does not exist.
 */
void LocalsRemove(Locals* locals, const char* key);

/**
 * Clears all entries but retains allocated memory for reuse.
 * All values are freed via their registered free_func.
 * After reset, size is 0 but capacity unchanged.
 *
 * @param locals Pointer to initialized Locals. Must not be NULL.
 */
void LocalsReset(Locals* locals);

/**
 * Destroys the Locals structure and frees all resources.
 * All values are freed, then the entries array is freed.
 * After destruction, the Locals structure is in an undefined state.
 *
 * @param locals Pointer to initialized Locals. NULL-safe (no-op if NULL).
 * @note Caller should not use locals after this call without re-initializing.
 */
void LocalsDestroy(Locals* locals);

#ifdef __cplusplus
}
#endif

#endif  // LOCALS_H
