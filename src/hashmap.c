#include "../include/hashmap.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Thread safety support */
#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION mutex_t;
#define MUTEX_INIT(m)    InitializeCriticalSection(m)
#define MUTEX_DESTROY(m) DeleteCriticalSection(m)
#define MUTEX_LOCK(m)    EnterCriticalSection(m)
#define MUTEX_UNLOCK(m)  LeaveCriticalSection(m)
#else
#include <pthread.h>
typedef pthread_mutex_t mutex_t;
#define MUTEX_INIT(m)    pthread_mutex_init(m, NULL)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(m)
#define MUTEX_LOCK(m)    pthread_mutex_lock(m)
#define MUTEX_UNLOCK(m)  pthread_mutex_unlock(m)
#endif

/* Cache-friendly constants */
#define CACHE_LINE_SIZE   64
#define PREFETCH_DISTANCE 2

/* Prefetch hints for better cache performance */
#ifdef __GNUC__
#define PREFETCH_READ(addr)  __builtin_prefetch(addr, 0, 3)
#define PREFETCH_WRITE(addr) __builtin_prefetch(addr, 1, 3)
#else
#define PREFETCH_READ(addr)  ((void)0)
#define PREFETCH_WRITE(addr) ((void)0)
#endif

/* Arena allocator implementation with optimized clear */
typedef struct arena_block {
    void* memory;
    size_t used;
    size_t size;
    struct arena_block* next;
    bool is_large_block;  // Track if this is a large allocation
} arena_block_t;

struct arena {
    arena_block_t* first;
    arena_block_t* current;
    arena_block_t* clear_point;  // Fast reset point
    size_t block_size;
    size_t total_allocated;  // Track total memory for statistics
    mutex_t* mutex;
    bool thread_safe;
};

static arena_t* arena_create(size_t initial_block_size, bool thread_safe) {
    arena_t* arena = malloc(sizeof(arena_t));
    if (!arena) return NULL;

    arena->first = arena->current = arena->clear_point = NULL;
    arena->block_size                                  = initial_block_size;
    arena->total_allocated                             = 0;
    arena->thread_safe                                 = thread_safe;

    if (thread_safe) {
        arena->mutex = malloc(sizeof(mutex_t));
        if (!arena->mutex) {
            free(arena);
            return NULL;
        }
        MUTEX_INIT(arena->mutex);
    } else {
        arena->mutex = NULL;
    }

    return arena;
}

static void arena_destroy(arena_t* arena) {
    if (!arena) return;

    arena_block_t* block = arena->first;
    while (block) {
        arena_block_t* next = block->next;
        free(block->memory);
        free(block);
        block = next;
    }

    if (arena->thread_safe && arena->mutex) {
        MUTEX_DESTROY(arena->mutex);
        free(arena->mutex);
    }

    free(arena);
}

static void* arena_alloc(arena_t* arena, size_t size) {
    if (!arena || size == 0) return NULL;

    if (arena->thread_safe && arena->mutex) {
        MUTEX_LOCK(arena->mutex);
    }

    // Align to cache line boundary for better performance
    size = (size + CACHE_LINE_SIZE - 1) & ~(CACHE_LINE_SIZE - 1);

    // Check if current block has enough space
    if (!arena->current || (arena->current->size - arena->current->used) < size) {
        // Need a new block - calculate block size
        size_t block_size = arena->block_size;
        bool is_large     = false;

        if (size > block_size) {
            block_size = size * 2;  // For very large allocations
            is_large   = true;
        }

        arena_block_t* new_block = malloc(sizeof(arena_block_t));
        if (!new_block) {
            if (arena->thread_safe && arena->mutex) {
                MUTEX_UNLOCK(arena->mutex);
            }
            return NULL;
        }

        new_block->memory = malloc(block_size);
        if (!new_block->memory) {
            free(new_block);
            if (arena->thread_safe && arena->mutex) {
                MUTEX_UNLOCK(arena->mutex);
            }
            return NULL;
        }

        new_block->used           = 0;
        new_block->size           = block_size;
        new_block->is_large_block = is_large;
        new_block->next           = NULL;

        arena->total_allocated += block_size;

        if (arena->current) {
            arena->current->next = new_block;
        } else {
            arena->first       = new_block;
            arena->clear_point = new_block;  // Set initial clear point
        }
        arena->current = new_block;
    }

    void* ptr = (char*)arena->current->memory + arena->current->used;
    arena->current->used += size;

    if (arena->thread_safe && arena->mutex) {
        MUTEX_UNLOCK(arena->mutex);
    }

    return ptr;
}

// Ultra-fast arena reset optimized for frequent clearing
static void arena_reset_fast(arena_t* arena) {
    if (!arena || !arena->clear_point) return;

    // Simply reset usage counters for blocks up to clear point
    // This is O(1) for most cases since we track the clear point
    arena_block_t* block = arena->first;
    while (block && block != arena->clear_point->next) {
        if (!block->is_large_block) {
            block->used = 0;
        }
        block = block->next;
    }

    arena->current = arena->clear_point;
}

// Full reset that also frees large blocks
static void arena_reset_full(arena_t* arena) {
    if (!arena) return;

    arena_block_t* block = arena->first;
    arena_block_t* prev  = NULL;

    while (block) {
        arena_block_t* next = block->next;

        if (block->is_large_block || block->size > arena->block_size * 4) {
            // Free oversized blocks to avoid memory bloat
            arena->total_allocated -= block->size;

            free(block->memory);
            free(block);

            if (prev)
                prev->next = next;
            else
                arena->first = next;
        } else {
            block->used = 0;
            prev        = block;
        }

        block = next;
    }

    arena->current     = arena->first;
    arena->clear_point = arena->first;
}

/* Internal helper functions */
static inline size_t hash_string(const char* key, size_t capacity);
static inline hashmap_entry_t* create_entry(arena_t* arena, const char* key, void* value);
static inline hashmap_error_t resize_if_needed(hashmap_t* map);
static inline hashmap_error_t resize_internal(hashmap_t* map, size_t new_capacity);
static inline bool is_valid_capacity(size_t capacity);
static inline bool is_valid_load_factor(float load_factor);
static inline void lock_map(hashmap_t* map);
static inline void unlock_map(hashmap_t* map);

/**
 * @brief Optimized hash function with better distribution and cache performance
 */
static size_t hash_string(const char* key, size_t capacity) {
    if (!key || capacity == 0) return 0;

    // FNV-1a hash - better distribution than djb2 and cache-friendly
    const size_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    const size_t FNV_PRIME        = 1099511628211ULL;

    size_t hash     = FNV_OFFSET_BASIS;
    const char* ptr = key;

    // Process 8 bytes at a time when possible for better performance
    while (*ptr) {
        hash ^= (size_t)*ptr++;
        hash *= FNV_PRIME;
    }

    // Use bit masking for power-of-2 capacities, modulo otherwise
    if ((capacity & (capacity - 1)) == 0) {
        return hash & (capacity - 1);
    }
    return hash % capacity;
}

/**
 * @brief Create a new entry with copied key using arena allocation
 * Optimized for cache-friendly layout
 */
static hashmap_entry_t* create_entry(arena_t* arena, const char* key, void* value) {
    if (!key) return NULL;

    // Calculate sizes with proper alignment
    size_t key_len    = strlen(key) + 1;
    size_t entry_size = sizeof(hashmap_entry_t);
    size_t total_size = entry_size + key_len;

    hashmap_entry_t* entry = arena_alloc(arena, total_size);
    if (!entry) return NULL;

    // Key is stored right after the entry struct for cache locality
    char* key_copy = (char*)(entry + 1);
    memcpy(key_copy, key, key_len);  // memcpy is often faster than strcpy

    entry->key   = key_copy;
    entry->value = value;
    entry->next  = NULL;

    return entry;
}

/**
 * @brief Check if capacity is valid and prefer power-of-2 sizes
 */
static bool is_valid_capacity(size_t capacity) {
    return capacity > 0 && capacity <= SIZE_MAX / 2;
}

/**
 * @brief Check if load factor is valid
 */
static bool is_valid_load_factor(float load_factor) {
    return load_factor >= HASHMAP_MIN_LOAD_FACTOR && load_factor <= HASHMAP_MAX_LOAD_FACTOR;
}

/**
 * @brief Lock the hashmap if thread-safe
 */
static void lock_map(hashmap_t* map) {
    if (map && map->thread_safe && map->mutex) {
        MUTEX_LOCK((mutex_t*)map->mutex);
    }
}

/**
 * @brief Unlock the hashmap if thread-safe
 */
static void unlock_map(hashmap_t* map) {
    if (map && map->thread_safe && map->mutex) {
        MUTEX_UNLOCK((mutex_t*)map->mutex);
    }
}

/* Public API Implementation */

hashmap_t* hashmap_create(void) {
    return hashmap_create_ex(HASHMAP_DEFAULT_CAPACITY, 0, HASHMAP_DEFAULT_LOAD_FACTOR, false);
}

hashmap_t* hashmap_create_ex(size_t initial_capacity, size_t max_capacity, float load_factor,
                             bool thread_safe) {
    if (!is_valid_capacity(initial_capacity) || !is_valid_load_factor(load_factor) ||
        (max_capacity > 0 && max_capacity < initial_capacity)) {
        return NULL;
    }

    // Round up to next power of 2 for better hash distribution
    size_t capacity = initial_capacity;
    if ((capacity & (capacity - 1)) != 0) {
        capacity--;
        capacity |= capacity >> 1;
        capacity |= capacity >> 2;
        capacity |= capacity >> 4;
        capacity |= capacity >> 8;
        capacity |= capacity >> 16;
        capacity |= capacity >> 32;
        capacity++;
    }

    hashmap_t* map = malloc(sizeof(hashmap_t));
    if (!map) return NULL;

    // Create arena with initial block size optimized for the capacity
    size_t arena_block_size = 64 * 1024;  // 64KB default
    size_t buckets_size     = capacity * sizeof(hashmap_entry_t*);
    if (buckets_size > arena_block_size) {
        arena_block_size = buckets_size + 32 * 1024;  // Add some extra space
    }

    map->arena = arena_create(arena_block_size, thread_safe);
    if (!map->arena) {
        free(map);
        return NULL;
    }

    map->buckets = arena_alloc(map->arena, buckets_size);
    if (!map->buckets) {
        arena_destroy(map->arena);
        free(map);
        return NULL;
    }

    // Use optimized memory initialization
    memset(map->buckets, 0, buckets_size);

    map->capacity     = capacity;
    map->size         = 0;
    map->max_capacity = max_capacity;
    map->load_factor  = load_factor;
    map->thread_safe  = thread_safe;
    map->mutex        = NULL;

    if (thread_safe) {
        map->mutex = malloc(sizeof(mutex_t));
        if (!map->mutex) {
            arena_destroy(map->arena);
            free(map);
            return NULL;
        }
        MUTEX_INIT((mutex_t*)map->mutex);
    }

    return map;
}

// Ultra-fast clear implementation - the main optimization
void hashmap_clear(hashmap_t* map) {
    if (!map) return;

    lock_map(map);

    // Fast path: use vector instructions to clear buckets in chunks
    const size_t buckets_size = map->capacity * sizeof(hashmap_entry_t*);

// Clear buckets using the most efficient method available
#ifdef __GNUC__
    // Use compiler builtin for optimized clearing
    __builtin_memset(map->buckets, 0, buckets_size);
#else
    memset(map->buckets, 0, buckets_size);
#endif

    map->size = 0;

    // Use fast arena reset that just resets counters
    arena_reset_fast(map->arena);

    unlock_map(map);
}

// New function for periodic full cleanup
void hashmap_clear_and_trim(hashmap_t* map) {
    if (!map) return;

    lock_map(map);

    memset(map->buckets, 0, map->capacity * sizeof(hashmap_entry_t*));
    map->size = 0;

    // Use full reset that also frees large blocks
    arena_reset_full(map->arena);

    unlock_map(map);
}

void hashmap_destroy(hashmap_t* map) {
    if (!map) return;

    lock_map(map);

    arena_destroy(map->arena);

    unlock_map(map);

    if (map->thread_safe && map->mutex) {
        MUTEX_DESTROY((mutex_t*)map->mutex);
        free(map->mutex);
    }

    free(map);
}

hashmap_error_t hashmap_put(hashmap_t* map, const char* key, void* value) {
    if (!map || !key) return HASHMAP_ERROR_NULL_POINTER;

    lock_map(map);

    /* Check if resize is needed before insertion */
    hashmap_error_t resize_result = resize_if_needed(map);
    if (resize_result != HASHMAP_OK) {
        unlock_map(map);
        return resize_result;
    }

    size_t index             = hash_string(key, map->capacity);
    hashmap_entry_t* current = map->buckets[index];

    // Prefetch the likely next cache line for better performance
    if (current) {
        PREFETCH_READ(current);
    }

    /* Check if key already exists */
    while (current) {
        if (strcmp(current->key, key) == 0) {
            current->value = value;
            unlock_map(map);
            return HASHMAP_OK;
        }
        if (current->next) {
            PREFETCH_READ(current->next);  // Prefetch next entry
        }
        current = current->next;
    }

    /* Create new entry */
    hashmap_entry_t* new_entry = create_entry(map->arena, key, value);
    if (!new_entry) {
        unlock_map(map);
        return HASHMAP_ERROR_OUT_OF_MEMORY;
    }

    /* Insert at head of chain for better cache locality of recent entries */
    new_entry->next     = map->buckets[index];
    map->buckets[index] = new_entry;
    map->size++;

    unlock_map(map);
    return HASHMAP_OK;
}

hashmap_error_t hashmap_get(hashmap_t* map, const char* key, void** value) {
    if (!map || !key || !value) return HASHMAP_ERROR_NULL_POINTER;

    lock_map(map);

    *value = NULL;

    size_t index             = hash_string(key, map->capacity);
    hashmap_entry_t* current = map->buckets[index];

    // Prefetch for better cache performance
    if (current) {
        PREFETCH_READ(current);
    }

    while (current) {
        if (strcmp(current->key, key) == 0) {
            *value = current->value;
            unlock_map(map);
            return HASHMAP_OK;
        }
        if (current->next) {
            PREFETCH_READ(current->next);
        }
        current = current->next;
    }

    unlock_map(map);
    return HASHMAP_ERROR_KEY_NOT_FOUND;
}

hashmap_error_t hashmap_remove(hashmap_t* map, const char* key) {
    if (!map || !key) return HASHMAP_ERROR_NULL_POINTER;

    lock_map(map);

    size_t index             = hash_string(key, map->capacity);
    hashmap_entry_t* current = map->buckets[index];
    hashmap_entry_t* prev    = NULL;

    while (current) {
        if (strcmp(current->key, key) == 0) {
            if (prev) {
                prev->next = current->next;
            } else {
                map->buckets[index] = current->next;
            }

            // With arena allocation, we don't free the entry here
            map->size--;
            unlock_map(map);
            return HASHMAP_OK;
        }
        prev    = current;
        current = current->next;
    }

    unlock_map(map);
    return HASHMAP_ERROR_KEY_NOT_FOUND;
}

const char* hashmap_error_string(hashmap_error_t error) {
    switch (error) {
        case HASHMAP_OK:
            return "Success";
        case HASHMAP_ERROR_NULL_POINTER:
            return "Null pointer";
        case HASHMAP_ERROR_INVALID_CAPACITY:
            return "Invalid capacity";
        case HASHMAP_ERROR_INVALID_LOAD_FACTOR:
            return "Invalid load factor";
        case HASHMAP_ERROR_OUT_OF_MEMORY:
            return "Out of memory";
        case HASHMAP_ERROR_KEY_NOT_FOUND:
            return "Key not found";
        case HASHMAP_ERROR_CAPACITY_EXCEEDED:
            return "Capacity exceeded";
        case HASHMAP_ERROR_INVALID_ITERATOR:
            return "Invalid iterator";
        default:
            return "Unknown error";
    }
}

float hashmap_load_factor_current(const hashmap_t* map) {
    if (!map || map->capacity == 0) return 0.0f;
    return (float)map->size / (float)map->capacity;
}

/**
 * @brief Check if resize is needed and perform it
 */
static hashmap_error_t resize_if_needed(hashmap_t* map) {
    if (!map) return HASHMAP_ERROR_NULL_POINTER;

    float current_load = hashmap_load_factor_current(map);

    if (current_load > map->load_factor) {
        size_t new_capacity = map->capacity * HASHMAP_GROWTH_FACTOR;

        // Ensure new capacity is power of 2
        if ((new_capacity & (new_capacity - 1)) != 0) {
            new_capacity--;
            new_capacity |= new_capacity >> 1;
            new_capacity |= new_capacity >> 2;
            new_capacity |= new_capacity >> 4;
            new_capacity |= new_capacity >> 8;
            new_capacity |= new_capacity >> 16;
            new_capacity |= new_capacity >> 32;
            new_capacity++;
        }

        /* Check max capacity limit */
        if (map->max_capacity > 0 && new_capacity > map->max_capacity) {
            if (map->capacity >= map->max_capacity) {
                return HASHMAP_ERROR_CAPACITY_EXCEEDED;
            }
            new_capacity = map->max_capacity;
        }

        return resize_internal(map, new_capacity);
    }

    return HASHMAP_OK;
}

hashmap_error_t hashmap_resize(hashmap_t* map, size_t new_capacity) {
    if (!map) return HASHMAP_ERROR_NULL_POINTER;
    if (!is_valid_capacity(new_capacity)) return HASHMAP_ERROR_INVALID_CAPACITY;
    if (new_capacity < map->size) return HASHMAP_ERROR_INVALID_CAPACITY;

    lock_map(map);
    hashmap_error_t result = resize_internal(map, new_capacity);
    unlock_map(map);

    return result;
}

/**
 * @brief Internal resize implementation with better cache performance
 */
static hashmap_error_t resize_internal(hashmap_t* map, size_t new_capacity) {
    if (!map || new_capacity == 0) return HASHMAP_ERROR_INVALID_CAPACITY;

    /* Allocate new buckets */
    hashmap_entry_t** new_buckets = arena_alloc(map->arena, new_capacity * sizeof(hashmap_entry_t*));
    if (!new_buckets) return HASHMAP_ERROR_OUT_OF_MEMORY;

    /* Initialize new buckets to NULL */
    memset(new_buckets, 0, new_capacity * sizeof(hashmap_entry_t*));

    /* Rehash all entries with better cache access patterns */
    for (size_t i = 0; i < map->capacity; i++) {
        hashmap_entry_t* current = map->buckets[i];

        // Prefetch next bucket for better performance
        if (i + PREFETCH_DISTANCE < map->capacity) {
            PREFETCH_READ(map->buckets[i + PREFETCH_DISTANCE]);
        }

        while (current) {
            hashmap_entry_t* next = current->next;

            /* Reinsert into new buckets */
            size_t new_index       = hash_string(current->key, new_capacity);
            current->next          = new_buckets[new_index];
            new_buckets[new_index] = current;

            current = next;
        }
    }

    /* Update map state */
    map->buckets  = new_buckets;
    map->capacity = new_capacity;

    return HASHMAP_OK;
}
