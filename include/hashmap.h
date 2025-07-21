#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @file hashmap.h
 * @brief A robust, production-ready bounded hashmap implementation
 *
 * This hashmap uses separate chaining for collision resolution and maintains
 * a configurable load factor through automatic resizing. It stores string keys
 * and void pointer values, making it suitable for generic data storage.
 *
 * Key features:
 * - Separate chaining collision resolution
 * - Automatic resizing based on load factor
 * - Configurable maximum capacity (bounded)
 * - Thread-safe option available
 * - Memory-efficient string key storage
 * - Comprehensive error handling
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
typedef enum {
    HASHMAP_OK = 0,
    HASHMAP_ERROR_NULL_POINTER,
    HASHMAP_ERROR_INVALID_CAPACITY,
    HASHMAP_ERROR_INVALID_LOAD_FACTOR,
    HASHMAP_ERROR_OUT_OF_MEMORY,
    HASHMAP_ERROR_KEY_NOT_FOUND,
    HASHMAP_ERROR_CAPACITY_EXCEEDED,
    HASHMAP_ERROR_INVALID_ITERATOR
} hashmap_error_t;

/* Forward declarations */
typedef struct hashmap hashmap_t;
typedef struct hashmap_entry hashmap_entry_t;

/**
 * @brief Hash map iterator structure
 */
typedef struct hashmap_iterator {
    hashmap_t* map;           /* Reference to the hashmap */
    size_t bucket_index;      /* Current bucket index */
    hashmap_entry_t* current; /* Current entry */
    bool valid;               /* Iterator validity flag */
} hashmap_iterator_t;

/**
 * @brief Create a new hashmap with default settings
 * @return Pointer to new hashmap or NULL on failure
 */
hashmap_t* hashmap_create(void);

/**
 * @brief Create a new hashmap with custom settings
 * @param initial_capacity Initial bucket array size (must be > 0)
 * @param max_capacity Maximum allowed capacity (0 = unlimited)
 * @param load_factor Target load factor (0.1 - 0.9)
 * @return Pointer to new hashmap or NULL on failure
 */
hashmap_t* hashmap_create_ex(size_t initial_capacity, size_t max_capacity, float load_factor);

/**
 * @brief Destroy a hashmap and free all memory
 * @param map Hashmap to destroy
 */
void hashmap_destroy(hashmap_t* map);

/**
 * @brief Insert or update a key-value pair
 * @param map Target hashmap
 * @param key Key string (will be copied)
 * @param value Value pointer (not copied)
 * @return HASHMAP_OK on success, error code on failure
 */
hashmap_error_t hashmap_put(hashmap_t* map, const char* key, void* value);

/**
 * @brief Retrieve a value by key
 * @param map Target hashmap
 * @param key Key string to search for
 * @param value Output parameter for the value pointer
 * @return HASHMAP_OK on success, HASHMAP_ERROR_KEY_NOT_FOUND if not found
 */
hashmap_error_t hashmap_get(hashmap_t* map, const char* key, void** value);

/**
 * @brief Remove a key-value pair
 * @param map Target hashmap
 * @param key Key string to remove
 * @return HASHMAP_OK on success, HASHMAP_ERROR_KEY_NOT_FOUND if not found
 */
hashmap_error_t hashmap_remove(hashmap_t* map, const char* key);

/**
 * @brief Check if a key exists in the hashmap
 * @param map Target hashmap
 * @param key Key string to check
 * @return true if key exists, false otherwise
 */
bool hashmap_contains(hashmap_t* map, const char* key);

/**
 * @brief Clear all entries from the hashmap
 * @param map Target hashmap
 */
void hashmap_clear(hashmap_t* map);

/* Information and statistics */

/**
 * @brief Get the number of key-value pairs
 * @param map Target hashmap
 * @return Number of entries, or 0 if map is NULL
 */
size_t hashmap_size(const hashmap_t* map);

/**
 * @brief Get the current capacity (number of buckets)
 * @param map Target hashmap
 * @return Current capacity, or 0 if map is NULL
 */
size_t hashmap_capacity(const hashmap_t* map);

/**
 * @brief Get the current load factor
 * @param map Target hashmap
 * @return Current load factor, or 0.0 if map is NULL
 */
float hashmap_load_factor_current(const hashmap_t* map);

/**
 * @brief Check if the hashmap is empty
 * @param map Target hashmap
 * @return true if empty, false otherwise
 */
bool hashmap_is_empty(const hashmap_t* map);

/* Iterator support */

/**
 * @brief Create an iterator for the hashmap
 * @param map Target hashmap
 * @return Iterator structure (check valid field)
 */
hashmap_iterator_t hashmap_iterator_create(hashmap_t* map);

/**
 * @brief Advance iterator to next entry
 * @param it Iterator to advance
 * @return true if advanced to valid entry, false if at end
 */
bool hashmap_iterator_next(hashmap_iterator_t* it);

/**
 * @brief Get the current entry's key
 * @param it Iterator
 * @return Current key string, or NULL if invalid
 */
const char* hashmap_iterator_key(const hashmap_iterator_t* it);

/**
 * @brief Get the current entry's value
 * @param it Iterator
 * @return Current value pointer, or NULL if invalid
 */
void* hashmap_iterator_value(const hashmap_iterator_t* it);

/**
 * @brief Check if iterator is valid
 * @param it Iterator to check
 * @return true if valid, false otherwise
 */
bool hashmap_iterator_valid(const hashmap_iterator_t* it);

/* Utility functions */

/**
 * @brief Convert error code to human-readable string
 * @param error Error code
 * @return Error description string
 */
const char* hashmap_error_string(hashmap_error_t error);

/**
 * @brief Manually trigger a resize operation
 * @param map Target hashmap
 * @param new_capacity New capacity (must be >= current size)
 * @return HASHMAP_OK on success, error code on failure
 */
hashmap_error_t hashmap_resize(hashmap_t* map, size_t new_capacity);

#ifdef __cplusplus
}
#endif

#endif /* HASHMAP_H */
