/**
 * @file hashmap.h
 * @brief High-performance thread-safe hashmap implementation
 *
 * This header provides a fast, thread-safe hashmap with the following features:
 * - Reader-writer locks for concurrent access
 * - Cache-optimized memory layout and allocation
 * - XXHash32 for fast hashing
 * - Hybrid pool/direct allocation for variable-sized entries
 * - O(1) clear operations using version counters
 * - Prefetching and branch prediction optimizations
 *
 * @author Your Name
 * @version 2.0
 * @date 2025
 */

#ifndef HASHMAP_H
#define HASHMAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Opaque hashmap structure
 *
 * The internal implementation is hidden to allow for future optimizations
 * without breaking the API.
 */
typedef struct hashmap hashmap_t;

/**
 * @brief Opaque hashmap entry structure
 *
 * Used internally for chaining and storage. Not directly accessible by users.
 */
typedef struct hashmap_entry hashmap_entry_t;

/**
 * @brief Error codes returned by hashmap operations
 */
typedef enum {
    HASHMAP_OK = 0,                    /**< Operation completed successfully */
    HASHMAP_ERROR_NULL_POINTER,        /**< Null pointer passed to function */
    HASHMAP_ERROR_INVALID_CAPACITY,    /**< Invalid capacity specified */
    HASHMAP_ERROR_INVALID_LOAD_FACTOR, /**< Invalid load factor specified */
    HASHMAP_ERROR_OUT_OF_MEMORY,       /**< Memory allocation failed */
    HASHMAP_ERROR_KEY_NOT_FOUND,       /**< Key not found in hashmap */
    HASHMAP_ERROR_CAPACITY_EXCEEDED,   /**< Maximum capacity exceeded */
    HASHMAP_ERROR_INVALID_ITERATOR     /**< Invalid iterator state */
} hashmap_error_t;

/**
 * @brief Create a new hashmap with default settings
 *
 * Creates a hashmap with:
 * - Initial capacity: 16 buckets
 * - Load factor: 0.75
 * - No maximum capacity limit
 * - Thread-safety enabled
 *
 * @return Pointer to new hashmap, or NULL on failure
 *
 * @note The returned hashmap must be freed with hashmap_destroy()
 *
 * @example
 * ```c
 * hashmap_t* map = hashmap_create();
 * if (!map) {
 *     fprintf(stderr, "Failed to create hashmap\n");
 *     return -1;
 * }
 * // Use map...
 * hashmap_destroy(map);
 * ```
 */
hashmap_t* hashmap_create(void);

/**
 * @brief Create a new hashmap with custom settings
 *
 * @param initial_capacity Initial number of buckets (will be rounded up to power of 2)
 * @param max_capacity Maximum allowed capacity (0 = unlimited)
 * @param load_factor Target load factor (0.1 to 0.95, recommended: 0.75)
 *
 * @return Pointer to new hashmap, or NULL on failure
 *
 * @note The returned hashmap must be freed with hashmap_destroy()
 *
 * @example
 * ```c
 * hashmap_t* map = hashmap_create_ex(1024, 0.8f);
 * if (!map) {
 *     fprintf(stderr, "Failed to create hashmap\n");
 *     return -1;
 * }
 * ```
 */
hashmap_t* hashmap_create_ex(size_t initial_capacity, float load_factor);

/**
 * @brief Destroy a hashmap and free all associated memory
 *
 * This function is thread-safe and will block until all ongoing operations
 * complete. After calling this function, the hashmap pointer becomes invalid.
 *
 * @param map Hashmap to destroy (can be NULL)
 *
 * @note This function is safe to call with NULL pointer
 * @note All stored keys are freed, but user-provided values are not freed
 *
 * @example
 * ```c
 * hashmap_t* map = hashmap_create();
 * // ... use map ...
 * hashmap_destroy(map);
 * map = NULL; // Good practice
 * ```
 */
void hashmap_destroy(hashmap_t* map);

/**
 * @brief Remove all entries from the hashmap (fast O(1) operation)
 *
 * This is an extremely fast clear operation that uses version counters
 * instead of walking all entries. Memory is kept allocated for reuse.
 *
 * @param map Hashmap to clear
 *
 * @note This function is thread-safe
 * @note Memory pools are reset but not freed for better performance
 * @note This is the preferred clear method for frequently cleared maps
 *
 * @example
 * ```c
 * hashmap_clear(map);
 * assert(hashmap_size(map) == 0);
 * ```
 */
void hashmap_clear(hashmap_t* map);

/**
 * @brief Remove all entries and trim excess memory
 *
 * Like hashmap_clear(), but also frees unused memory pools.
 * Use this when you won't be adding many entries again soon.
 *
 * @param map Hashmap to clear and trim
 *
 * @note This function is thread-safe
 * @note Slower than hashmap_clear() but frees more memory
 *
 * @example
 * ```c
 * // Clear and prepare for long idle period
 * hashmap_clear_and_trim(map);
 * ```
 */
void hashmap_clear_and_trim(hashmap_t* map);

/**
 * @brief Insert or update a key-value pair
 *
 * If the key already exists, its value is updated. Otherwise, a new
 * entry is created. The key is copied internally, but the value is
 * stored as-is (shallow copy).
 *
 * @param map Target hashmap
 * @param key Null-terminated string key (must not be NULL)
 * @param value Value to associate with key (can be NULL)
 *
 * @return HASHMAP_OK on success, error code on failure
 *
 * @note This function is thread-safe (uses write lock)
 * @note The key string is copied, so the original can be freed
 * @note Values are not copied - ensure they remain valid
 * @note May trigger automatic resizing if load factor is exceeded
 *
 * @example
 * ```c
 * struct user* user = create_user("Alice", 25);
 * hashmap_error_t err = hashmap_put(map, "user:123", user);
 * if (err != HASHMAP_OK) {
 *     fprintf(stderr, "Put failed: %s\n", hashmap_error_string(err));
 * }
 * ```
 */
hashmap_error_t hashmap_put(hashmap_t* map, const char* key, void* value);

/**
 * @brief Retrieve a value by key
 *
 * This operation uses a read lock, allowing multiple concurrent lookups.
 *
 * @param map Source hashmap
 * @param key Null-terminated string key to search for
 * @param value Pointer to store the retrieved value (output parameter)
 *
 * @return HASHMAP_OK if found, HASHMAP_ERROR_KEY_NOT_FOUND if not found
 *
 * @note This function is thread-safe (uses read lock)
 * @note Multiple threads can perform get() operations concurrently
 * @note *value is set to NULL if key is not found
 *
 * @example
 * ```c
 * void* user_ptr;
 * hashmap_error_t err = hashmap_get(map, "user:123", &user_ptr);
 * if (err == HASHMAP_OK) {
 *     struct user* user = (struct user*)user_ptr;
 *     printf("Found user: %s\n", user->name);
 * } else if (err == HASHMAP_ERROR_KEY_NOT_FOUND) {
 *     printf("User not found\n");
 * }
 * ```
 */
hashmap_error_t hashmap_get(hashmap_t* map, const char* key, void** value);

/**
 * @brief Remove a key-value pair from the hashmap
 *
 * The key and its associated value are removed from the hashmap.
 * The value is not freed - that's the caller's responsibility.
 *
 * @param map Target hashmap
 * @param key Null-terminated string key to remove
 *
 * @return HASHMAP_OK if removed, HASHMAP_ERROR_KEY_NOT_FOUND if not found
 *
 * @note This function is thread-safe (uses write lock)
 * @note The value is not freed automatically
 * @note Memory for the entry is returned to the pool for reuse
 *
 * @example
 * ```c
 * void* user_ptr;
 * if (hashmap_get(map, "user:123", &user_ptr) == HASHMAP_OK) {
 *     hashmap_remove(map, "user:123");
 *     free_user((struct user*)user_ptr); // Clean up the value
 * }
 * ```
 */
hashmap_error_t hashmap_remove(hashmap_t* map, const char* key);

/**
 * @brief Check if a key exists in the hashmap
 *
 * This is a convenience function equivalent to hashmap_get() but
 * without retrieving the value.
 *
 * @param map Source hashmap
 * @param key Null-terminated string key to check
 *
 * @return true if key exists, false otherwise
 *
 * @note This function is thread-safe (uses read lock)
 * @note Returns false if map or key is NULL
 *
 * @example
 * ```c
 * if (hashmap_contains(map, "user:123")) {
 *     printf("User exists\n");
 * }
 * ```
 */
bool hashmap_contains(hashmap_t* map, const char* key);

/**
 * @brief Get the number of key-value pairs in the hashmap
 *
 * @param map Source hashmap
 * @return Number of entries, or 0 if map is NULL
 *
 * @note This function is thread-safe
 * @note This is an O(1) operation
 *
 * @example
 * ```c
 * printf("Hashmap contains %zu entries\n", hashmap_size(map));
 * ```
 */
size_t hashmap_size(hashmap_t* map);

/**
 * @brief Check if the hashmap is empty
 *
 * @param map Source hashmap
 * @return true if empty or NULL, false if contains entries
 *
 * @note This function is thread-safe
 * @note Returns true if map is NULL
 *
 * @example
 * ```c
 * if (hashmap_is_empty(map)) {
 *     printf("No entries to process\n");
 * }
 * ```
 */
bool hashmap_is_empty(hashmap_t* map);

/**
 * @brief Get the current capacity (number of buckets)
 *
 * @param map Source hashmap
 * @return Current capacity, or 0 if map is NULL
 *
 * @note This function is thread-safe
 * @note Capacity is always a power of 2
 *
 * @example
 * ```c
 * printf("Hashmap capacity: %zu buckets\n", hashmap_capacity(map));
 * ```
 */
size_t hashmap_capacity(hashmap_t* map);

/**
 * @brief Get the current load factor
 *
 * The load factor is the ratio of entries to buckets (size/capacity).
 * When this exceeds the target load factor, the hashmap will resize.
 *
 * @param map Source hashmap
 * @return Current load factor (0.0 to 1.0), or 0.0 if map is NULL
 *
 * @note This function is thread-safe
 * @note Values close to 1.0 indicate the hashmap may resize soon
 *
 * @example
 * ```c
 * float load = hashmap_load_factor_current(map);
 * if (load > 0.8f) {
 *     printf("Hashmap is getting full (%.2f)\n", load);
 * }
 * ```
 */
float hashmap_load_factor_current(const hashmap_t* map);

/**
 * @brief Convert error code to human-readable string
 *
 * @param error Error code to convert
 * @return Static string describing the error
 *
 * @note The returned string is static and should not be freed
 * @note Returns "Unknown error" for invalid error codes
 *
 * @example
 * ```c
 * hashmap_error_t err = hashmap_put(map, key, value);
 * if (err != HASHMAP_OK) {
 *     fprintf(stderr, "Error: %s\n", hashmap_error_string(err));
 * }
 * ```
 */
const char* hashmap_error_string(hashmap_error_t error);

/**
 * @brief Get performance statistics (debug/optimization use)
 *
 * Retrieves internal statistics useful for performance tuning
 * and debugging.
 *
 * @param map Source hashmap
 * @param chain_count Output: number of chained entries
 * @param max_chain_len Output: length of longest chain
 * @param memory_used Output: approximate memory usage in bytes
 *
 * @note This function is thread-safe
 * @note All output parameters can be NULL if not needed
 * @note Memory usage is approximate and may not include all overhead
 *
 * @example
 * ```c
 * size_t chains, max_len, memory;
 * hashmap_get_stats(map, &chains, &max_len, &memory);
 * printf("Chains: %zu, Max length: %zu, Memory: %zu KB\n",
 *        chains, max_len, memory / 1024);
 * ```
 */
void hashmap_get_stats(hashmap_t* map, size_t* chain_count, size_t* max_chain_len,
                       size_t* memory_used);

/**
 * @brief Reserve capacity to avoid resizing
 *
 * Pre-allocates space for at least the specified number of entries
 * to avoid multiple resize operations during bulk insertion.
 *
 * @param map Target hashmap
 * @param min_entries Minimum number of entries to accommodate
 *
 * @return HASHMAP_OK on success, error code on failure
 *
 * @note This function is thread-safe (uses write lock)
 * @note Actual capacity may be larger due to power-of-2 rounding
 * @note This is an optimization - the hashmap will still work without it
 *
 * @example
 * ```c
 * // About to insert 1000 entries
 * hashmap_reserve(map, 1000);
 * for (int i = 0; i < 1000; i++) {
 *     hashmap_put(map, keys[i], values[i]);
 * }
 * ```
 */
hashmap_error_t hashmap_reserve(hashmap_t* map, size_t min_entries);

/* Iterator support for walking all entries */

/**
 * @brief Opaque iterator structure
 */
typedef struct hashmap_iterator hashmap_iterator_t;

/**
 * @brief Create an iterator to walk all entries
 *
 * The iterator provides a way to visit all key-value pairs in the hashmap.
 * Order is not guaranteed and may change between iterations.
 *
 * @param map Source hashmap
 * @return New iterator, or NULL on failure
 *
 * @note The iterator must be freed with hashmap_iterator_destroy()
 * @note The iterator holds a read lock while active
 * @note Do not modify the hashmap while iterating
 *
 * @example
 * ```c
 * hashmap_iterator_t* iter = hashmap_iterator_create(map);
 * const char* key;
 * void* value;
 * while (hashmap_iterator_next(iter, &key, &value)) {
 *     printf("Key: %s\n", key);
 * }
 * hashmap_iterator_destroy(iter);
 * ```
 */
hashmap_iterator_t* hashmap_iterator_create(hashmap_t* map);

/**
 * @brief Get the next key-value pair from iterator
 *
 * @param iter Iterator to advance
 * @param key Output: pointer to key string (valid until next iteration)
 * @param value Output: pointer to associated value
 *
 * @return true if entry retrieved, false if no more entries
 *
 * @note The key pointer is valid until the next call to this function
 * @note Returns false when all entries have been visited
 *
 * @example
 * ```c
 * hashmap_iterator_t* iter = hashmap_iterator_create(map);
 * const char* key;
 * void* value;
 * while (hashmap_iterator_next(iter, &key, &value)) {
 *     struct user* user = (struct user*)value;
 *     printf("User %s: age %d\n", key, user->age);
 * }
 * hashmap_iterator_destroy(iter);
 * ```
 */
bool hashmap_iterator_next(hashmap_iterator_t* iter, const char** key, void** value);

/**
 * @brief Destroy an iterator and release its resources
 *
 * @param iter Iterator to destroy (can be NULL)
 *
 * @note This function releases the read lock held by the iterator
 * @note Safe to call with NULL pointer
 *
 * @example
 * ```c
 * hashmap_iterator_t* iter = hashmap_iterator_create(map);
 * // ... use iterator ...
 * hashmap_iterator_destroy(iter);
 * iter = NULL; // Good practice
 * ```
 */
void hashmap_iterator_destroy(hashmap_iterator_t* iter);

#ifdef __cplusplus
}
#endif

#endif /* HASHMAP_H */
