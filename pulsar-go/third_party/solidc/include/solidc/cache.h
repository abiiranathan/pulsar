/**
 * @file cache.h
 * @brief High-performance sharded open-addressing hash cache with 16-bit tags,
 *        256-byte cache-line aligned storage, lock-free per-slot seqlock concurrency,
 *        and an ABA-safe slab allocator.
 */

#ifndef CACHE_H
#define CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>  // for bool, true, false
#include <stddef.h>   // for size_t
#include <stdint.h>   // for uint16_t, uint32_t, uint64_t, uint8_t

/** Number of shards used to partition the key space. Must be a power of 2. */
#define CACHE_SHARD_COUNT 256

/** Default entry time-to-live in seconds if no TTL override is provided. */
#define CACHE_DEFAULT_TTL 300

/** Maximum key length supported by inline slot storage (in bytes). */
#define CACHE_MAX_KEY_LEN 64

/** Maximum inline payload length before spilling to the slab allocator (in bytes). */
#define CACHE_INLINE_VAL_LEN 160

/** Maximum total payload capacity (in bytes) supported per cache entry. */
#define CACHE_MAX_VALUE_LEN 2048

/**
 * Opaque handle to the cache instance.
 * All internal fields are hidden to preserve ABI compatibility.
 */
typedef struct cache_s cache_t;

/** Configuration parameters for cache instantiation. */
typedef struct {
    size_t capacity_per_shard;    /** Requested open-addressing slot capacity per shard. */
    size_t slab_blocks_per_shard; /** Number of dynamic payload blocks in slab pool per shard. */
    uint32_t default_ttl_sec;     /** Default expiration timeout in seconds. */
} cache_config_t;

/**
 * Creates and initializes a new sharded cache instance.
 *
 * @param config Pointer to the cache configuration structure.
 * @return Pointer to initialized cache_t handle on success, NULL on memory allocation failure.
 * @note Thread-safe initialization. Must be destroyed with cache_destroy().
 */
cache_t* cache_create(const cache_config_t* config);

/**
 * Destroys a cache instance and frees all allocated memory and resources.
 *
 * @param cache Pointer to the cache instance.
 * @note Not thread-safe with concurrent operations on the same handle.
 */
void cache_destroy(cache_t* cache);

/**
 * Stores or updates a key-value pair in the cache using seqlock write semantics.
 *
 * @param cache Pointer to the cache instance.
 * @param key Pointer to key buffer.
 * @param key_len Length of key in bytes (must be <= CACHE_MAX_KEY_LEN).
 * @param value Pointer to value buffer.
 * @param val_len Length of value in bytes (must be <= CACHE_MAX_VALUE_LEN).
 * @param ttl_sec TTL for this entry in seconds (0 defaults to config.default_ttl_sec).
 * @return true on success, false if key/value size limits exceeded or shard capacity exhausted.
 * @note Lock-free per-slot write operation. Safe for concurrent multi-threaded writes.
 */
bool cache_put(cache_t* cache, const void* key, size_t key_len, const void* value, size_t val_len, uint32_t ttl_sec);

/**
 * Retrieves a value from the cache for a given key via optimistic seqlock reading.
 *
 * @param cache Pointer to the cache instance.
 * @param key Pointer to key buffer.
 * @param key_len Length of key in bytes.
 * @param val_out Output buffer where retrieved value will be copied.
 * @param val_cap Capacity of val_out buffer in bytes.
 * @param val_len Output pointer to receive actual payload length (can be NULL).
 * @return true if key was found and valid (not expired), false on miss or expiration.
 * @note Lock-free optimistic read loop. Safe for concurrent use across multiple threads.
 */
bool cache_get(cache_t* cache, const void* key, size_t key_len, void* val_out, size_t val_cap, size_t* val_len);

/**
 * Evicts an entry from the cache by key.
 *
 * @param cache Pointer to the cache instance.
 * @param key Pointer to key buffer.
 * @param key_len Length of key in bytes.
 * @return true if key was found and deleted, false if key was not present.
 * @note Thread-safe operation. Reclaims associated slab blocks.
 */
bool cache_delete(cache_t* cache, const void* key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* CACHE_H */
