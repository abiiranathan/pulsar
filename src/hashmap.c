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

/* Internal helper functions */
static size_t hash_string(const char* key, size_t capacity);
static hashmap_entry_t* create_entry(const char* key, void* value);
static void destroy_entry(hashmap_entry_t* entry);
static void destroy_chain(hashmap_entry_t* head);
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
 * @brief Create a new entry with copied key
 */
static hashmap_entry_t* create_entry(const char* key, void* value) {
    if (!key)
        return NULL;

    hashmap_entry_t* entry = malloc(sizeof(hashmap_entry_t));
    if (!entry)
        return NULL;

    entry->key = malloc(strlen(key) + 1);
    if (!entry->key) {
        free(entry);
        return NULL;
    }

    strcpy(entry->key, key);
    entry->value = value;
    entry->next = NULL;

    return entry;
}

/**
 * @brief Destroy a single entry
 */
static void destroy_entry(hashmap_entry_t* entry) {
    if (entry) {
        free(entry->key);
        free(entry);
    }
}

/**
 * @brief Destroy an entire chain of entries
 */
static void destroy_chain(hashmap_entry_t* head) {
    while (head) {
        hashmap_entry_t* next = head->next;
        destroy_entry(head);
        head = next;
    }
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

    map->buckets = calloc(initial_capacity, sizeof(hashmap_entry_t*));
    if (!map->buckets) {
        free(map);
        return NULL;
    }

    map->capacity = initial_capacity;
    map->size = 0;
    map->max_capacity = max_capacity;
    map->load_factor = load_factor;
    map->thread_safe = thread_safe;
    map->mutex = NULL;

    if (thread_safe) {
        map->mutex = malloc(sizeof(mutex_t));
        if (!map->mutex) {
            free(map->buckets);
            free(map);
            return NULL;
        }
        MUTEX_INIT((mutex_t*)map->mutex);
    }

    return map;
}

void hashmap_destroy(hashmap_t* map) {
    if (!map)
        return;

    lock_map(map);

    /* Free all entries */
    for (size_t i = 0; i < map->capacity; i++) {
        destroy_chain(map->buckets[i]);
    }

    free(map->buckets);

    if (map->thread_safe && map->mutex) {
        unlock_map(map);
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

    size_t index = hash_string(key, map->capacity);
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
    hashmap_entry_t* new_entry = create_entry(key, value);
    if (!new_entry) {
        unlock_map(map);
        return HASHMAP_ERROR_OUT_OF_MEMORY;
    }

    /* Insert at head of chain */
    new_entry->next = map->buckets[index];
    map->buckets[index] = new_entry;
    map->size++;

    unlock_map(map);
    return HASHMAP_OK;
}

hashmap_error_t hashmap_get(hashmap_t* map, const char* key, void** value) {
    if (!map || !key || !value)
        return HASHMAP_ERROR_NULL_POINTER;

    lock_map(map);

    // Initialize with NULL.
    *value = NULL;

    size_t index = hash_string(key, map->capacity);
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

    size_t index = hash_string(key, map->capacity);
    hashmap_entry_t* current = map->buckets[index];
    hashmap_entry_t* prev = NULL;

    while (current) {
        if (strcmp(current->key, key) == 0) {
            if (prev) {
                prev->next = current->next;
            } else {
                map->buckets[index] = current->next;
            }

            destroy_entry(current);
            map->size--;
            unlock_map(map);
            return HASHMAP_OK;
        }
        prev = current;
        current = current->next;
    }

    unlock_map(map);
    return HASHMAP_ERROR_KEY_NOT_FOUND;
}

bool hashmap_contains(hashmap_t* map, const char* key) {
    void* value;
    return hashmap_get(map, key, &value) == HASHMAP_OK;
}

void hashmap_clear(hashmap_t* map) {
    if (!map)
        return;

    lock_map(map);

    for (size_t i = 0; i < map->capacity; i++) {
        destroy_chain(map->buckets[i]);
        map->buckets[i] = NULL;
    }

    map->size = 0;
    unlock_map(map);
}

size_t hashmap_size(const hashmap_t* map) {
    return map ? map->size : 0;
}

size_t hashmap_capacity(const hashmap_t* map) {
    return map ? map->capacity : 0;
}

float hashmap_load_factor_current(const hashmap_t* map) {
    if (!map || map->capacity == 0)
        return 0.0f;
    return (float)map->size / (float)map->capacity;
}

bool hashmap_is_empty(const hashmap_t* map) {
    return map ? map->size == 0 : true;
}

/* Iterator implementation */

hashmap_iterator_t hashmap_iterator_create(hashmap_t* map) {
    hashmap_iterator_t it = {0};

    if (!map) {
        it.valid = false;
        return it;
    }

    it.map = map;
    it.bucket_index = 0;
    it.current = NULL;
    it.valid = true;

    /* Find first non-empty bucket */
    for (size_t i = 0; i < map->capacity; i++) {
        if (map->buckets[i]) {
            it.bucket_index = i;
            it.current = map->buckets[i];
            break;
        }
    }

    if (!it.current) {
        it.valid = false;
    }

    return it;
}

bool hashmap_iterator_next(hashmap_iterator_t* it) {
    if (!it || !it->valid || !it->map)
        return false;

    /* Move to next entry in current chain */
    if (it->current && it->current->next) {
        it->current = it->current->next;
        return true;
    }

    /* Find next non-empty bucket */
    for (size_t i = it->bucket_index + 1; i < it->map->capacity; i++) {
        if (it->map->buckets[i]) {
            it->bucket_index = i;
            it->current = it->map->buckets[i];
            return true;
        }
    }

    /* No more entries */
    it->valid = false;
    it->current = NULL;
    return false;
}

const char* hashmap_iterator_key(const hashmap_iterator_t* it) {
    if (!it || !it->valid || !it->current)
        return NULL;
    return it->current->key;
}

void* hashmap_iterator_value(const hashmap_iterator_t* it) {
    if (!it || !it->valid || !it->current)
        return NULL;
    return it->current->value;
}

bool hashmap_iterator_valid(const hashmap_iterator_t* it) {
    return it && it->valid && it->current;
}

/* Utility functions */

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

    /* Save old state */
    hashmap_entry_t** old_buckets = map->buckets;
    size_t old_capacity = map->capacity;

    /* Allocate new buckets */
    hashmap_entry_t** new_buckets = calloc(new_capacity, sizeof(hashmap_entry_t*));
    if (!new_buckets)
        return HASHMAP_ERROR_OUT_OF_MEMORY;

    /* Update map state */
    map->buckets = new_buckets;
    map->capacity = new_capacity;
    map->size = 0;

    /* Rehash all entries */
    for (size_t i = 0; i < old_capacity; i++) {
        hashmap_entry_t* current = old_buckets[i];
        while (current) {
            hashmap_entry_t* next = current->next;

            /* Reinsert into new buckets */
            size_t new_index = hash_string(current->key, new_capacity);
            current->next = new_buckets[new_index];
            new_buckets[new_index] = current;
            map->size++;

            current = next;
        }
    }

    /* Free old buckets array */
    free(old_buckets);

    return HASHMAP_OK;
}
