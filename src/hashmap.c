#include "../include/hashmap.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>  // For aligned_alloc, free
#include <string.h>
#include "../include/macros.h"

/* Thread safety support */
#ifdef _WIN32
#include <malloc.h>  // For _aligned_malloc, _aligned_free
#include <windows.h>
typedef CRITICAL_SECTION mutex_t;
// Wrap Windows API to match pthread's return value convention (0 for success)
#define MUTEX_INIT(m)    (InitializeCriticalSection(m), 0)
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
#define CACHE_LINE_SIZE 64

/* Prefetch hints for better cache performance */
#ifdef __GNUC__
#define PREFETCH_READ(addr)  __builtin_prefetch(addr, 0, 3)
#define PREFETCH_WRITE(addr) __builtin_prefetch(addr, 1, 3)
#else
#define PREFETCH_READ(addr)  ((void)0)
#define PREFETCH_WRITE(addr) ((void)0)
#endif

/* Default configuration constants */
#define HASHMAP_DEFAULT_CAPACITY    16
#define HASHMAP_DEFAULT_LOAD_FACTOR 0.75f
#define HASHMAP_MAX_LOAD_FACTOR     0.9f
#define HASHMAP_MIN_LOAD_FACTOR     0.1f
#define HASHMAP_GROWTH_FACTOR       2

/* Arena allocator implementation - simplified to not have its own lock */
typedef struct arena_block {
    void* memory;
    size_t used;
    size_t size;
    struct arena_block* next;
    bool is_large_block;
} arena_block_t;

typedef struct arena {
    arena_block_t* first;
    arena_block_t* current;
    arena_block_t* clear_point;
    size_t block_size;
    size_t total_allocated;
} arena_t;

/**
 * @brief Hash map entry structure
 */
struct hashmap_entry {
    char* key;                  /* Owned copy of the key string */
    void* value;                /* User-provided value pointer */
    struct hashmap_entry* next; /* Next entry in chain */
};

/**
 * @brief Hash map structure
 */
struct hashmap {
    bool thread_safe; /* Thread safety flag */
    mutex_t mutex;
    hashmap_entry_t** buckets; /* Array of bucket heads */
    size_t capacity;           /* Current bucket array size */
    size_t size;               /* Number of key-value pairs */
    size_t max_capacity;       /* Maximum allowed capacity (0 = unlimited) */
    float load_factor;         /* Target load factor */
    arena_t* arena;            /* Hashmap arena*/
};

// Portable aligned allocation/deallocation
static void* platform_aligned_alloc(size_t size, size_t alignment) {
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#else
    // aligned_alloc requires size to be a multiple of alignment
    return aligned_alloc(alignment, ALIGN_UP(size, alignment));
#endif
}

static void platform_aligned_free(void* ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

static arena_t* arena_create(size_t initial_block_size) {
    arena_t* arena = malloc(sizeof(arena_t));
    if (!arena) return NULL;

    arena->first = arena->current = arena->clear_point = NULL;
    arena->block_size                                  = initial_block_size;
    arena->total_allocated                             = 0;
    return arena;
}

static void arena_destroy(arena_t* arena) {
    if (!arena) return;

    arena_block_t* block = arena->first;
    while (block) {
        arena_block_t* next = block->next;
        platform_aligned_free(block->memory);
        free(block);
        block = next;
    }
    free(arena);
}

static void* arena_alloc(arena_t* arena, size_t size) {
    if (size == 0) return NULL;

    // Align allocation size to a cache line boundary
    size = ALIGN_UP(size, CACHE_LINE_SIZE);

    if (!arena->current || (arena->current->size - arena->current->used) < size) {
        size_t block_size = arena->block_size;
        bool is_large     = false;

        if (size > block_size) {
            block_size = size * 2;  // Allocate more for large, one-off items
            is_large   = true;
        }

        arena_block_t* new_block = malloc(sizeof(arena_block_t));
        if (!new_block) return NULL;

        // Allocate the actual memory block with cache-line alignment
        new_block->memory = platform_aligned_alloc(block_size, CACHE_LINE_SIZE);
        if (!new_block->memory) {
            free(new_block);
            return NULL;
        }

        new_block->used           = 0;
        new_block->size           = ALIGN_UP(block_size, CACHE_LINE_SIZE);
        new_block->is_large_block = is_large;
        new_block->next           = NULL;
        arena->total_allocated += new_block->size;

        if (arena->current) {
            arena->current->next = new_block;
        } else {
            arena->first       = new_block;
            arena->clear_point = new_block;
        }
        arena->current = new_block;
    }

    void* ptr = (char*)arena->current->memory + arena->current->used;
    arena->current->used += size;
    return ptr;
}

static void arena_reset_fast(arena_t* arena) {
    if (!arena->clear_point) return;

    arena_block_t* block = arena->first;
    while (block && block != arena->clear_point->next) {
        if (!block->is_large_block) {
            block->used = 0;
        }
        block = block->next;
    }
    arena->current = arena->clear_point;
}

static void arena_reset_full(arena_t* arena) {
    if (!arena) return;

    arena_block_t *block = arena->first, *prev = NULL;
    while (block) {
        arena_block_t* next = block->next;
        if (block->is_large_block || block->size > arena->block_size * 4) {
            arena->total_allocated -= block->size;
            platform_aligned_free(block->memory);
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
static inline hashmap_error_t resize_internal(hashmap_t* map, size_t new_capacity);
static inline bool is_valid_capacity(size_t capacity);
static inline bool is_valid_load_factor(float load_factor);
static inline hashmap_error_t resize_if_needed(hashmap_t* map);

static inline void lock_map(hashmap_t* map) {
    MUTEX_LOCK(&map->mutex);
}
static inline void unlock_map(hashmap_t* map) {
    MUTEX_UNLOCK(&map->mutex);
}

static size_t hash_string(const char* key, size_t capacity) {
    if (!key || capacity == 0) return 0;
    const size_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    const size_t FNV_PRIME        = 1099511628211ULL;
    size_t hash                   = FNV_OFFSET_BASIS;
    for (const char* p = key; *p; p++) {
        hash ^= (size_t)*p;
        hash *= FNV_PRIME;
    }
    return hash & (capacity - 1);  // Assumes capacity is a power of 2
}

static hashmap_entry_t* create_entry(arena_t* arena, const char* key, void* value) {
    if (!key) return NULL;
    size_t key_len         = strlen(key) + 1;
    size_t total_size      = sizeof(hashmap_entry_t) + key_len;
    hashmap_entry_t* entry = arena_alloc(arena, total_size);
    if (!entry) return NULL;
    char* key_copy = (char*)(entry + 1);
    memcpy(key_copy, key, key_len);
    entry->key   = key_copy;
    entry->value = value;
    entry->next  = NULL;
    return entry;
}

static bool is_valid_capacity(size_t capacity) {
    return capacity > 0 && capacity <= SIZE_MAX / 2;
}
static bool is_valid_load_factor(float lf) {
    return lf >= 0.1f && lf <= 0.95f;
}

hashmap_t* hashmap_create(void) {
    return hashmap_create_ex(HASHMAP_DEFAULT_CAPACITY, 0, HASHMAP_DEFAULT_LOAD_FACTOR);
}

hashmap_t* hashmap_create_ex(size_t initial_capacity, size_t max_capacity, float load_factor) {
    if (!is_valid_capacity(initial_capacity) || !is_valid_load_factor(load_factor) ||
        (max_capacity > 0 && max_capacity < initial_capacity)) {
        return NULL;
    }

    size_t capacity = NEXT_POWER_OF_TWO(initial_capacity);
    hashmap_t* map  = platform_aligned_alloc(sizeof(hashmap_t), CACHE_LINE_SIZE);
    if (!map) return NULL;

    size_t arena_block_size = 64 * 1024;
    size_t buckets_size     = capacity * sizeof(hashmap_entry_t*);
    if (buckets_size > arena_block_size) arena_block_size = buckets_size + 32 * 1024;

    map->arena = arena_create(arena_block_size);
    if (!map->arena) {
        platform_aligned_free(map);
        return NULL;
    }

    map->buckets = arena_alloc(map->arena, buckets_size);
    if (!map->buckets) {
        arena_destroy(map->arena);
        platform_aligned_free(map);
        return NULL;
    }
    memset(map->buckets, 0, buckets_size);

    map->capacity     = capacity;
    map->size         = 0;
    map->max_capacity = max_capacity;
    map->load_factor  = load_factor;

    if (MUTEX_INIT(&map->mutex) != 0) {
        arena_destroy(map->arena);
        platform_aligned_free(map);
        return NULL;
    }
    return map;
}

void hashmap_destroy(hashmap_t* map) {
    if (!map) return;
    lock_map(map);
    arena_destroy(map->arena);
    unlock_map(map);

    MUTEX_DESTROY(&map->mutex);
    platform_aligned_free(map);
}

void hashmap_clear(hashmap_t* map) {
    lock_map(map);
    memset(map->buckets, 0, map->capacity * sizeof(hashmap_entry_t*));
    map->size = 0;
    arena_reset_fast(map->arena);
    unlock_map(map);
}

void hashmap_clear_and_trim(hashmap_t* map) {
    lock_map(map);
    memset(map->buckets, 0, map->capacity * sizeof(hashmap_entry_t*));
    map->size = 0;
    arena_reset_full(map->arena);
    unlock_map(map);
}

hashmap_error_t hashmap_put(hashmap_t* map, const char* key, void* value) {
    if (!map || !key) return HASHMAP_ERROR_NULL_POINTER;
    lock_map(map);

    hashmap_error_t resize_err = resize_if_needed(map);
    if (resize_err != HASHMAP_OK) {
        unlock_map(map);
        return resize_err;
    }

    size_t index             = hash_string(key, map->capacity);
    hashmap_entry_t* current = map->buckets[index];
    if (current) PREFETCH_READ(current);

    while (current) {
        if (strcmp(current->key, key) == 0) {
            current->value = value;
            unlock_map(map);
            return HASHMAP_OK;
        }
        if (current->next) PREFETCH_READ(current->next);
        current = current->next;
    }

    hashmap_entry_t* new_entry = create_entry(map->arena, key, value);
    if (!new_entry) {
        unlock_map(map);
        return HASHMAP_ERROR_OUT_OF_MEMORY;
    }

    new_entry->next     = map->buckets[index];
    map->buckets[index] = new_entry;
    map->size++;

    unlock_map(map);
    return HASHMAP_OK;
}

hashmap_error_t hashmap_get(hashmap_t* map, const char* key, void** value) {
    if (!map || !key || !value) return HASHMAP_ERROR_NULL_POINTER;
    lock_map(map);

    *value                   = NULL;
    size_t index             = hash_string(key, map->capacity);
    hashmap_entry_t* current = map->buckets[index];
    if (current) PREFETCH_READ(current);

    while (current) {
        if (strcmp(current->key, key) == 0) {
            *value = current->value;
            unlock_map(map);
            return HASHMAP_OK;
        }
        if (current->next) PREFETCH_READ(current->next);
        current = current->next;
    }

    unlock_map(map);
    return HASHMAP_ERROR_KEY_NOT_FOUND;
}

hashmap_error_t hashmap_remove(hashmap_t* map, const char* key) {
    if (!map || !key) return HASHMAP_ERROR_NULL_POINTER;
    lock_map(map);

    size_t index             = hash_string(key, map->capacity);
    hashmap_entry_t *current = map->buckets[index], *prev = NULL;

    while (current) {
        if (strcmp(current->key, key) == 0) {
            if (prev)
                prev->next = current->next;
            else
                map->buckets[index] = current->next;
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

static hashmap_error_t resize_if_needed(hashmap_t* map) {
    if ((float)map->size / (float)map->capacity > map->load_factor) {
        size_t new_capacity = map->capacity * HASHMAP_GROWTH_FACTOR;
        if (map->max_capacity > 0 && new_capacity > map->max_capacity) {
            if (map->capacity >= map->max_capacity) return HASHMAP_ERROR_CAPACITY_EXCEEDED;
            new_capacity = map->max_capacity;
        }

        // Round up to the next power of 2 for optimal index calculation
        if ((new_capacity & (new_capacity - 1)) != 0) {
            new_capacity--;
            for (size_t i = 1; i < sizeof(size_t) * 8; i <<= 1)
                new_capacity |= new_capacity >> i;
            new_capacity++;
        }
        return resize_internal(map, new_capacity);
    }
    return HASHMAP_OK;
}

static hashmap_error_t resize_internal(hashmap_t* map, size_t new_capacity) {
    hashmap_entry_t** new_buckets = arena_alloc(map->arena, new_capacity * sizeof(hashmap_entry_t*));
    if (!new_buckets) return HASHMAP_ERROR_OUT_OF_MEMORY;
    memset(new_buckets, 0, new_capacity * sizeof(hashmap_entry_t*));

    for (size_t i = 0; i < map->capacity; i++) {
        hashmap_entry_t* current = map->buckets[i];
        while (current) {
            hashmap_entry_t* next  = current->next;
            size_t new_index       = hash_string(current->key, new_capacity);
            current->next          = new_buckets[new_index];
            new_buckets[new_index] = current;
            current                = next;
        }
    }
    map->buckets  = new_buckets;
    map->capacity = new_capacity;
    return HASHMAP_OK;
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
