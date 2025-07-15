#include "../include/hashmap.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Thread safety support */
#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION mutex_t;
#define MUTEX_INIT(m) InitializeCriticalSection(m)
#define MUTEX_DESTROY(m) DeleteCriticalSection(m)
#define MUTEX_LOCK(m) EnterCriticalSection(m)
#define MUTEX_UNLOCK(m) LeaveCriticalSection(m)
#else
#include <pthread.h>
typedef pthread_mutex_t mutex_t;
#define MUTEX_INIT(m) pthread_mutex_init(m, NULL)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(m)
#define MUTEX_LOCK(m) pthread_mutex_lock(m)
#define MUTEX_UNLOCK(m) pthread_mutex_unlock(m)
#endif

/* Arena allocator implementation */
typedef struct arena_block {
    void* memory;
    size_t used;
    size_t size;
    struct arena_block* next;
} arena_block_t;

struct arena {
    arena_block_t* first;
    arena_block_t* current;
    size_t block_size;
    mutex_t* mutex;
    bool thread_safe;
};

static arena_t* arena_create(size_t initial_block_size, bool thread_safe) {
    arena_t* arena = malloc(sizeof(arena_t));
    if (!arena)
        return NULL;

    arena->first = arena->current = NULL;
    arena->block_size             = initial_block_size;
    arena->thread_safe            = thread_safe;

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
    if (!arena)
        return;

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
    if (!arena || size == 0)
        return NULL;

    if (arena->thread_safe && arena->mutex) {
        MUTEX_LOCK(arena->mutex);
    }

    // Align to 8-byte boundary
    size = (size + 7) & ~7;

    // Check if current block has enough space
    if (!arena->current || (arena->current->size - arena->current->used) < size) {
        // Need a new block - calculate block size
        size_t block_size = arena->block_size;
        if (size > block_size) {
            block_size = size * 2;  // For very large allocations
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

        new_block->used = 0;
        new_block->size = block_size;
        new_block->next = NULL;

        if (arena->current) {
            arena->current->next = new_block;
        } else {
            arena->first = new_block;
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

/* Internal helper functions */
static size_t hash_string(const char* key, size_t capacity);
static hashmap_entry_t* create_entry(arena_t* arena, const char* key, void* value);
static hashmap_error_t resize_if_needed(hashmap_t* map);
static hashmap_error_t resize_internal(hashmap_t* map, size_t new_capacity);
static bool is_valid_capacity(size_t capacity);
static bool is_valid_load_factor(float load_factor);
static void lock_map(hashmap_t* map);
static void unlock_map(hashmap_t* map);

/**
 * @brief Hash function for strings (djb2 algorithm)
 */
static size_t hash_string(const char* key, size_t capacity) {
    if (!key || capacity == 0)
        return 0;

    size_t hash = 5381;
    int c;

    while ((c = *key++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash % capacity;
}

/**
 * @brief Create a new entry with copied key using arena allocation
 */
static hashmap_entry_t* create_entry(arena_t* arena, const char* key, void* value) {
    if (!key)
        return NULL;

    // Allocate entry and key in one allocation
    size_t key_len    = strlen(key) + 1;
    size_t total_size = sizeof(hashmap_entry_t) + key_len;

    hashmap_entry_t* entry = arena_alloc(arena, total_size);
    if (!entry)
        return NULL;

    // Key is stored right after the entry struct
    char* key_copy = (char*)(entry + 1);
    strcpy(key_copy, key);

    entry->key   = key_copy;
    entry->value = value;
    entry->next  = NULL;

    return entry;
}

/**
 * @brief Check if capacity is valid
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

    hashmap_t* map = malloc(sizeof(hashmap_t));
    if (!map)
        return NULL;

    // Create arena with initial block size of 64KB or enough for initial buckets
    size_t arena_block_size = 64 * 1024;
    if (initial_capacity * sizeof(hashmap_entry_t*) > arena_block_size) {
        arena_block_size = initial_capacity * sizeof(hashmap_entry_t*);
    }

    map->arena = arena_create(arena_block_size, thread_safe);
    if (!map->arena) {
        free(map);
        return NULL;
    }

    map->buckets = arena_alloc(map->arena, initial_capacity * sizeof(hashmap_entry_t*));
    if (!map->buckets) {
        arena_destroy(map->arena);
        free(map);
        return NULL;
    }

    // Initialize buckets to NULL
    memset(map->buckets, 0, initial_capacity * sizeof(hashmap_entry_t*));

    map->capacity     = initial_capacity;
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

void hashmap_clear(hashmap_t* map) {
    if (!map)
        return;

    lock_map(map);

    // Reset all buckets to NULL
    memset(map->buckets, 0, map->capacity * sizeof(hashmap_entry_t*));
    map->size = 0;

    // Reset the arena by moving all blocks back to initial state
    arena_block_t* block = map->arena->first;
    while (block) {
        block->used = 0;
        block       = block->next;
    }

    // Reset arena's current pointer to first block
    map->arena->current = map->arena->first;

    unlock_map(map);
}

void hashmap_destroy(hashmap_t* map) {
    if (!map)
        return;

    lock_map(map);

    // With arena allocation, we don't need to free individual entries
    // Just destroy the arena which will free all memory at once
    arena_destroy(map->arena);

    unlock_map(map);

    if (map->thread_safe && map->mutex) {
        MUTEX_DESTROY((mutex_t*)map->mutex);
        free(map->mutex);
    }

    free(map);
}

hashmap_error_t hashmap_put(hashmap_t* map, const char* key, void* value) {
    if (!map || !key)
        return HASHMAP_ERROR_NULL_POINTER;

    lock_map(map);

    /* Check if resize is needed before insertion */
    hashmap_error_t resize_result = resize_if_needed(map);
    if (resize_result != HASHMAP_OK) {
        unlock_map(map);
        return resize_result;
    }

    size_t index             = hash_string(key, map->capacity);
    hashmap_entry_t* current = map->buckets[index];

    /* Check if key already exists */
    while (current) {
        if (strcmp(current->key, key) == 0) {
            current->value = value;
            unlock_map(map);
            return HASHMAP_OK;
        }
        current = current->next;
    }

    /* Create new entry */
    hashmap_entry_t* new_entry = create_entry(map->arena, key, value);
    if (!new_entry) {
        unlock_map(map);
        return HASHMAP_ERROR_OUT_OF_MEMORY;
    }

    /* Insert at head of chain */
    new_entry->next     = map->buckets[index];
    map->buckets[index] = new_entry;
    map->size++;

    unlock_map(map);
    return HASHMAP_OK;
}

/* Rest of the implementation remains the same as before,
   except for removing destroy_entry since we're using arena allocation */

hashmap_error_t hashmap_get(hashmap_t* map, const char* key, void** value) {
    if (!map || !key || !value)
        return HASHMAP_ERROR_NULL_POINTER;

    lock_map(map);

    // Initialize with NULL.
    *value = NULL;

    size_t index             = hash_string(key, map->capacity);
    hashmap_entry_t* current = map->buckets[index];

    while (current) {
        if (strcmp(current->key, key) == 0) {
            *value = current->value;
            unlock_map(map);
            return HASHMAP_OK;
        }
        current = current->next;
    }

    unlock_map(map);
    return HASHMAP_ERROR_KEY_NOT_FOUND;
}

hashmap_error_t hashmap_remove(hashmap_t* map, const char* key) {
    if (!map || !key)
        return HASHMAP_ERROR_NULL_POINTER;

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
    if (!map || map->capacity == 0)
        return 0.0f;
    return (float)map->size / (float)map->capacity;
}

/**
 * @brief Check if resize is needed and perform it
 */
static hashmap_error_t resize_if_needed(hashmap_t* map) {
    if (!map)
        return HASHMAP_ERROR_NULL_POINTER;

    float current_load = hashmap_load_factor_current(map);

    if (current_load > map->load_factor) {
        size_t new_capacity = map->capacity * HASHMAP_GROWTH_FACTOR;

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
    if (!map)
        return HASHMAP_ERROR_NULL_POINTER;
    if (!is_valid_capacity(new_capacity))
        return HASHMAP_ERROR_INVALID_CAPACITY;
    if (new_capacity < map->size)
        return HASHMAP_ERROR_INVALID_CAPACITY;

    lock_map(map);
    hashmap_error_t result = resize_internal(map, new_capacity);
    unlock_map(map);

    return result;
}

/**
 * @brief Internal resize implementation
 */
static hashmap_error_t resize_internal(hashmap_t* map, size_t new_capacity) {
    if (!map || new_capacity == 0)
        return HASHMAP_ERROR_INVALID_CAPACITY;

    /* Allocate new buckets */
    hashmap_entry_t** new_buckets = arena_alloc(map->arena, new_capacity * sizeof(hashmap_entry_t*));
    if (!new_buckets)
        return HASHMAP_ERROR_OUT_OF_MEMORY;

    /* Initialize new buckets to NULL */
    memset(new_buckets, 0, new_capacity * sizeof(hashmap_entry_t*));

    /* Rehash all entries */
    for (size_t i = 0; i < map->capacity; i++) {
        hashmap_entry_t* current = map->buckets[i];
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
