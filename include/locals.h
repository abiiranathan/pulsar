#ifndef LOCALS_H
#define LOCALS_H

#include <solidc/arena.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Callback function type for freeing values. */
typedef void (*ValueFreeFunc)(void* value);

/** Key-Value pair for the Locals. */
typedef struct {
    const char* key;          // Arena-allocated key string (immutable)
    void* value;              // Value associated with key
    ValueFreeFunc free_func;  // Function pointer to free values
} KeyValue;

/**
 * Dynamic array-based key-value store with linear search.
 * Uses externally-provided arena allocator for keys and entries array.
 *
 * IMPORTANT: Locals does NOT own the arena. The arena must outlive the Locals
 * structure. LocalsClear() only frees values, not arena memory.
 */
typedef struct {
    KeyValue* entries;  // Arena-allocated array of entries
    size_t size;        // Number of occupied entries
    size_t capacity;    // Total allocated capacity
    Arena* arena;       // External arena (NOT owned by Locals)
} Locals;

/**
 * Allocate and initialize locals structure using an external arena.
 * @param initial_capacity Initial number of entries to allocate (use 0 for default).
 * @param arena External arena for allocations. Must not be NULL and must outlive this Locals.
 * @return Pointer to the structure on success, NULL on allocation failure.
 * @note The Locals structure itself is heap-allocated. The arena is NOT owned by Locals.
 */
Locals* LocalsInit(size_t initial_capacity, Arena* arena);

/**
 * Store value with unique key. If key already exists, its value will be freed
 * using the ValueFreeFunc and replaced with the new value.
 * The key string is duplicated into the arena - caller retains ownership of the original.
 * @param locals Pointer to Locals structure.
 * @param key String identifier (will be duplicated into arena).
 * @param value Pointer to value to store.
 * @param value_free_func Function to free the value, or NULL if no cleanup needed.
 * @return true on success, false on allocation failure.
 * @note Automatically grows capacity when needed. Time complexity: O(n) for lookup.
 */
bool LocalsSetValue(Locals* locals, const char* key, void* value, ValueFreeFunc value_free_func);

/**
 * Get the value associated with the key.
 * @param locals Pointer to Locals structure.
 * @param key String identifier to look up.
 * @return Pointer to value if found, NULL otherwise.
 * @note Time complexity: O(n) linear search.
 */
void* LocalsGetValue(const Locals* locals, const char* key);

/**
 * Delete key-value pair from locals.
 * @param locals Pointer to Locals structure.
 * @param key String identifier to remove.
 * @return true if key was found and removed, false otherwise.
 * @note The key memory is NOT reclaimed (arena-allocated). Only the value is freed.
 *       Time complexity: O(n) for find + shift.
 */
bool LocalsRemove(Locals* locals, const char* key);

/**
 * Clear all entries - frees all values but keeps arena memory allocated.
 * @param locals Pointer to Locals structure to clear.
 * @note Does NOT reset the arena (arena is externally owned). Keys and entries
 *       array remain in arena memory. Only frees the managed values.
 *       Use this to reuse Locals without invalidating other arena allocations.
 */
void LocalsClear(Locals* locals);

/**
 * @brief Re-initialize locals after arena reset to avoid dangling pointer for entries.
 *
 * @param locals Pointer to Locals structure.
 * @return true on success, false otherwise.
 */
bool LocalsReinitAfterArenaReset(Locals* locals);

/**
 * Free the Locals structure itself. Does NOT free arena or arena-allocated memory.
 * @param locals Pointer to Locals structure to destroy.
 * @note Frees all managed values, then frees the Locals structure.
 *       The arena and all arena-allocated memory (keys, entries) remain valid.
 *       Call this when done with Locals but the arena is still in use.
 */
void LocalsDestroy(Locals* locals);

#ifdef __cplusplus
}
#endif

#endif  // LOCALS_H
