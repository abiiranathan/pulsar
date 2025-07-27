#include "../include/hashmap.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../include/macros.h"

/* Thread safety with reader-writer locks */
#ifdef _WIN32
#include <windows.h>
typedef SRWLOCK rwlock_t;
#define RWLOCK_INIT(rw)     InitializeSRWLock(rw)
#define RWLOCK_DESTROY(rw)  ((void)0)
#define RWLOCK_RDLOCK(rw)   AcquireSRWLockShared(rw)
#define RWLOCK_WRLOCK(rw)   AcquireSRWLockExclusive(rw)
#define RWLOCK_RDUNLOCK(rw) ReleaseSRWLockShared(rw)
#define RWLOCK_WRUNLOCK(rw) ReleaseSRWLockExclusive(rw)
#else
#include <pthread.h>
typedef pthread_rwlock_t rwlock_t;
#define RWLOCK_INIT(rw)     pthread_rwlock_init(rw, NULL)
#define RWLOCK_DESTROY(rw)  pthread_rwlock_destroy(rw)
#define RWLOCK_RDLOCK(rw)   pthread_rwlock_rdlock(rw)
#define RWLOCK_WRLOCK(rw)   pthread_rwlock_wrlock(rw)
#define RWLOCK_RDUNLOCK(rw) pthread_rwlock_unlock(rw)
#define RWLOCK_WRUNLOCK(rw) pthread_rwlock_unlock(rw)
#endif

/* Configuration constants */
#define HASHMAP_DEFAULT_CAPACITY    16
#define HASHMAP_DEFAULT_LOAD_FACTOR 0.75f
#define CACHE_LINE_SIZE             64

/**
 * @brief Optimized hash map entry with better cache locality
 */
struct hashmap_entry {
    uint32_t key_hash;          /* Cached hash for faster comparisons */
    void* value;                /* User-provided value pointer */
    struct hashmap_entry* next; /* Next entry in chain */
    char key[];                 /* Flexible array member for key */
};

/* Hashmap structure */
struct hashmap {
    rwlock_t rwlock;
    hashmap_entry_t** buckets;
    size_t capacity;
    size_t size;
    uint32_t seed;
};

/* Fast hash function */
static inline uint32_t hash_xxhash32(const char* key, size_t len, uint32_t seed) {
    const uint32_t PRIME32_1 = 0x9E3779B1U;
    const uint32_t PRIME32_2 = 0x85EBCA77U;
    const uint32_t PRIME32_3 = 0xC2B2AE3DU;
    const uint32_t PRIME32_4 = 0x27D4EB2FU;
    const uint32_t PRIME32_5 = 0x165667B1U;

    uint32_t h32;
    const uint8_t* p          = (const uint8_t*)key;
    const uint8_t* const bEnd = p + len;

    if (len >= 16) {
        const uint8_t* const limit = bEnd - 16;
        uint32_t v1                = seed + PRIME32_1 + PRIME32_2;
        uint32_t v2                = seed + PRIME32_2;
        uint32_t v3                = seed + 0;
        uint32_t v4                = seed - PRIME32_1;

        do {
            v1 = ((v1 + (*(uint32_t*)p * PRIME32_2)) << 13) | ((v1 + (*(uint32_t*)p * PRIME32_2)) >> 19);
            v1 *= PRIME32_1;
            p += 4;
            v2 = ((v2 + (*(uint32_t*)p * PRIME32_2)) << 13) | ((v2 + (*(uint32_t*)p * PRIME32_2)) >> 19);
            v2 *= PRIME32_1;
            p += 4;
            v3 = ((v3 + (*(uint32_t*)p * PRIME32_2)) << 13) | ((v3 + (*(uint32_t*)p * PRIME32_2)) >> 19);
            v3 *= PRIME32_1;
            p += 4;
            v4 = ((v4 + (*(uint32_t*)p * PRIME32_2)) << 13) | ((v4 + (*(uint32_t*)p * PRIME32_2)) >> 19);
            v4 *= PRIME32_1;
            p += 4;
        } while (p <= limit);

        h32 = ((v1 << 1) | (v1 >> 31)) + ((v2 << 7) | (v2 >> 25)) + ((v3 << 12) | (v3 >> 20)) +
              ((v4 << 18) | (v4 >> 14));
    } else {
        h32 = seed + PRIME32_5;
    }

    h32 += (uint32_t)len;

    while (p + 4 <= bEnd) {
        h32 += *(uint32_t*)p * PRIME32_3;
        h32 = ((h32 << 17) | (h32 >> 15)) * PRIME32_4;
        p += 4;
    }

    while (p < bEnd) {
        h32 += (*p++) * PRIME32_5;
        h32 = ((h32 << 11) | (h32 >> 21)) * PRIME32_1;
    }

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}

/* Helper functions */
static inline void read_lock(hashmap_t* map) {
    RWLOCK_RDLOCK(&map->rwlock);
}
static inline void read_unlock(hashmap_t* map) {
    RWLOCK_RDUNLOCK(&map->rwlock);
}
static inline void write_lock(hashmap_t* map) {
    RWLOCK_WRLOCK(&map->rwlock);
}
static inline void write_unlock(hashmap_t* map) {
    RWLOCK_WRUNLOCK(&map->rwlock);
}

/* Create a new hashmap */
hashmap_t* hashmap_create(void) {
    return hashmap_create_ex(HASHMAP_DEFAULT_CAPACITY, HASHMAP_DEFAULT_LOAD_FACTOR);
}

hashmap_t* hashmap_create_ex(size_t initial_capacity, float load_factor) {
    if (initial_capacity == 0 || load_factor <= 0.0f || load_factor >= 1.0f) {
        return NULL;
    }

    /* Round up to next power of two */
    size_t capacity = 1;
    while (capacity < initial_capacity)
        capacity <<= 1;

    hashmap_t* map = aligned_alloc(CACHE_LINE_SIZE, sizeof(hashmap_t));
    if (!map) return NULL;

    map->buckets = aligned_alloc(CACHE_LINE_SIZE, capacity * sizeof(hashmap_entry_t*));
    if (!map->buckets) {
        free(map);
        return NULL;
    }
    memset(map->buckets, 0, capacity * sizeof(hashmap_entry_t*));

    map->capacity = capacity;
    map->size     = 0;
    map->seed     = (uint32_t)((uintptr_t)map >> 4); /* Simple seed */

    RWLOCK_INIT(&map->rwlock);
    return map;
}

/* Destroy hashmap */
void hashmap_destroy(hashmap_t* map) {
    if (!map) return;

    hashmap_clear(map);
    RWLOCK_DESTROY(&map->rwlock);
    free(map->buckets);
    free(map);
}

/* Clear all entries */
void hashmap_clear(hashmap_t* map) {
    if (!map) return;

    write_lock(map);

    for (size_t i = 0; i < map->capacity; i++) {
        hashmap_entry_t* entry = map->buckets[i];
        while (entry) {
            hashmap_entry_t* next = entry->next;
            free(entry);
            entry = next;
        }
        map->buckets[i] = NULL;
    }

    map->size = 0;
    write_unlock(map);
}

/* Internal resize function */
static hashmap_error_t resize_internal(hashmap_t* map, size_t new_capacity) {
    hashmap_entry_t** new_buckets = aligned_alloc(CACHE_LINE_SIZE, new_capacity * sizeof(hashmap_entry_t*));
    if (!new_buckets) return HASHMAP_ERROR_OUT_OF_MEMORY;
    memset(new_buckets, 0, new_capacity * sizeof(hashmap_entry_t*));

    for (size_t i = 0; i < map->capacity; i++) {
        hashmap_entry_t* entry = map->buckets[i];
        while (entry) {
            hashmap_entry_t* next  = entry->next;
            size_t new_index       = entry->key_hash & (new_capacity - 1);
            entry->next            = new_buckets[new_index];
            new_buckets[new_index] = entry;
            entry                  = next;
        }
    }

    free(map->buckets);
    map->buckets  = new_buckets;
    map->capacity = new_capacity;
    return HASHMAP_OK;
}

/* Put key-value pair */
hashmap_error_t hashmap_put(hashmap_t* map, const char* key, void* value) {
    if (!map || !key) return HASHMAP_ERROR_NULL_POINTER;

    size_t key_len = strlen(key);
    uint32_t hash  = hash_xxhash32(key, key_len, map->seed);
    size_t index   = hash & (map->capacity - 1);

    write_lock(map);

    /* Check for existing key */
    hashmap_entry_t* entry = map->buckets[index];
    while (entry) {
        if (entry->key_hash == hash && strcmp(entry->key, key) == 0) {
            entry->value = value;
            write_unlock(map);
            return HASHMAP_OK;
        }
        entry = entry->next;
    }

    /* Create new entry */
    hashmap_entry_t* new_entry = malloc(sizeof(hashmap_entry_t) + key_len + 1);
    if (!new_entry) {
        write_unlock(map);
        return HASHMAP_ERROR_OUT_OF_MEMORY;
    }

    new_entry->key_hash = hash;
    new_entry->value    = value;
    new_entry->next     = map->buckets[index];
    strcpy(new_entry->key, key);

    map->buckets[index] = new_entry;
    map->size++;

    /* Resize if needed */
    if (map->size > map->capacity * HASHMAP_DEFAULT_LOAD_FACTOR) {
        resize_internal(map, map->capacity * 2);
    }

    write_unlock(map);
    return HASHMAP_OK;
}

/* Get value by key */
hashmap_error_t hashmap_get(hashmap_t* map, const char* key, void** value) {
    if (!map || !key || !value) return HASHMAP_ERROR_NULL_POINTER;

    size_t key_len = strlen(key);
    uint32_t hash  = hash_xxhash32(key, key_len, map->seed);
    size_t index   = hash & (map->capacity - 1);

    read_lock(map);

    hashmap_entry_t* entry = map->buckets[index];
    while (entry) {
        if (entry->key_hash == hash && strcmp(entry->key, key) == 0) {
            *value = entry->value;
            read_unlock(map);
            return HASHMAP_OK;
        }
        entry = entry->next;
    }

    read_unlock(map);
    *value = NULL;
    return HASHMAP_ERROR_KEY_NOT_FOUND;
}

/* Remove key-value pair */
hashmap_error_t hashmap_remove(hashmap_t* map, const char* key) {
    if (!map || !key) return HASHMAP_ERROR_NULL_POINTER;

    size_t key_len = strlen(key);
    uint32_t hash  = hash_xxhash32(key, key_len, map->seed);
    size_t index   = hash & (map->capacity - 1);

    write_lock(map);

    hashmap_entry_t *entry = map->buckets[index], *prev = NULL;
    while (entry) {
        if (entry->key_hash == hash && strcmp(entry->key, key) == 0) {
            if (prev) {
                prev->next = entry->next;
            } else {
                map->buckets[index] = entry->next;
            }

            free(entry);
            map->size--;
            write_unlock(map);
            return HASHMAP_OK;
        }
        prev  = entry;
        entry = entry->next;
    }

    write_unlock(map);
    return HASHMAP_ERROR_KEY_NOT_FOUND;
}

/* Error string */
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
