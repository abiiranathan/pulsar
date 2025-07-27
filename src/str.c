#include "../include/str.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/* ======================================================================== */

/**
 * @brief Virtual function table for allocator operations
 */
typedef struct allocator_vtable_t {
    /**
     * @brief Allocate memory block
     * @param allocator The allocator instance
     * @param size Size of memory to allocate
     * @return Pointer to allocated memory or NULL on failure
     */
    void* (*alloc)(allocator_t* allocator, size_t size);

    /**
     * @brief Reallocate memory block
     * @param allocator The allocator instance
     * @param ptr Pointer to existing memory block (may be NULL)
     * @param old_size Current size of memory block
     * @param new_size New size to allocate
     * @return Pointer to reallocated memory or NULL on failure
     */
    void* (*realloc)(allocator_t* allocator, void* ptr, size_t old_size, size_t new_size);

    /**
     * @brief Free memory block
     * @param allocator The allocator instance
     * @param ptr Pointer to memory to free (may be NULL)
     * @param size Size of memory block being freed
     */
    void (*free)(allocator_t* allocator, void* ptr, size_t size);

    /**
     * @brief Destroy allocator instance
     * @param allocator The allocator instance to destroy
     */
    void (*destroy)(allocator_t* allocator);
} allocator_vtable_t;

/**
 * @brief Memory allocator interface
 */
struct allocator_t {
    const allocator_vtable_t* vtable;  ///< Virtual function table
    void* user_data;                   ///< Allocator-specific data
    const char* name;                  ///< Allocator name for debugging
};

/**
 * @brief Allocate memory using an allocator
 * @param alloc_ Allocator instance
 * @param size_ Size to allocate
 * @return Pointer to allocated memory or NULL
 */
#define allocator_alloc(alloc_, size_)                                                             \
    ((alloc_) && (alloc_)->vtable && (alloc_)->vtable->alloc                                       \
         ? (alloc_)->vtable->alloc((alloc_), (size_))                                              \
         : NULL)

/**
 * @brief Reallocate memory using an allocator
 * @param alloc Allocator instance
 * @param ptr Pointer to existing memory
 * @param old_size Current size of memory block
 * @param new_size New size to allocate
 * @return Pointer to reallocated memory or NULL
 */
#define allocator_realloc(alloc, ptr, old_size, new_size)                                          \
    ((alloc) && (alloc)->vtable && (alloc)->vtable->realloc                                        \
         ? (alloc)->vtable->realloc((alloc), (ptr), (old_size), (new_size))                        \
         : NULL)

/**
 * @brief Free memory using an allocator
 * @param alloc Allocator instance
 * @param ptr Pointer to memory to free
 * @param size Size of memory block
 */
#define allocator_free(alloc, ptr, size)                                                           \
    do {                                                                                           \
        if ((alloc) && (alloc)->vtable && (alloc)->vtable->free)                                   \
            (alloc)->vtable->free((alloc), (ptr), (size));                                         \
    } while (0)

/**
 * @brief Destroy an allocator instance
 * @param alloc Allocator instance to destroy
 */
#define allocator_destroy(alloc)                                                                   \
    do {                                                                                           \
        if ((alloc) && (alloc)->vtable && (alloc)->vtable->destroy)                                \
            (alloc)->vtable->destroy(alloc);                                                       \
    } while (0)

/* =========================================================================*/

/* ===========================================================================
 * DEFAULT ALLOCATOR IMPLEMENTATION
 * =========================================================================*/

static void* default_alloc(allocator_t* allocator, size_t size) {
    (void)allocator;
    return malloc(size);
}

static void* default_realloc(allocator_t* allocator, void* ptr, size_t old_size, size_t new_size) {
    (void)allocator;
    (void)old_size;
    return realloc(ptr, new_size);
}

static void default_free(allocator_t* allocator, void* ptr, size_t size) {
    (void)allocator;
    (void)size;
    free(ptr);
}

static const allocator_vtable_t default_vtable = {.alloc   = default_alloc,
                                                  .realloc = default_realloc,
                                                  .free    = default_free,
                                                  .destroy = NULL};

static allocator_t default_allocator_instance = {.vtable    = &default_vtable,
                                                 .user_data = NULL,
                                                 .name      = "default"};

allocator_t* str_default_allocator(void) {
    return &default_allocator_instance;
}

/**
 * @brief Free object allocated with allocator.
 * @return Pointer to default allocator (never NULL)
 */
void str_allocator_free(allocator_t* allocator, void* ptr, size_t size) {
    allocator_free(allocator, ptr, size);
}

/* ===========================================================================
 * TRACKING ALLOCATOR IMPLEMENTATION
 * =========================================================================*/

typedef struct tracking_data_t {
    allocator_t* base_allocator;
    size_t total_allocated;
    size_t current_allocated;
    size_t allocation_count;
} tracking_data_t;

static void* tracking_alloc(allocator_t* allocator, size_t size) {
    tracking_data_t* data = (tracking_data_t*)allocator->user_data;
    void* ptr             = allocator_alloc(data->base_allocator, size);
    if (ptr) {
        data->total_allocated += size;
        data->current_allocated += size;
        data->allocation_count++;
    }
    return ptr;
}

static void* tracking_realloc(allocator_t* allocator, void* ptr, size_t old_size, size_t new_size) {
    tracking_data_t* data = (tracking_data_t*)allocator->user_data;
    void* new_ptr         = allocator_realloc(data->base_allocator, ptr, old_size, new_size);

    if (new_ptr || new_size == 0) {
        data->current_allocated -= old_size;
        if (new_size > 0) {
            data->total_allocated += new_size;
            data->current_allocated += new_size;
        }
    }
    return new_ptr;
}

static void tracking_free(allocator_t* allocator, void* ptr, size_t size) {
    tracking_data_t* data = (tracking_data_t*)allocator->user_data;
    allocator_free(data->base_allocator, ptr, size);
    data->current_allocated -= size;
}

static void tracking_destroy(allocator_t* allocator) {
    tracking_data_t* data = (tracking_data_t*)allocator->user_data;
    free(data);
    free(allocator);
}

static const allocator_vtable_t tracking_vtable = {.alloc   = tracking_alloc,
                                                   .realloc = tracking_realloc,
                                                   .free    = tracking_free,
                                                   .destroy = tracking_destroy};

allocator_t* str_create_tracking_allocator(allocator_t* base_allocator) {
    if (!base_allocator) {
        base_allocator = str_default_allocator();
    }

    allocator_t* allocator = malloc(sizeof(allocator_t));
    if (!allocator) return NULL;

    tracking_data_t* data = malloc(sizeof(tracking_data_t));
    if (!data) {
        free(allocator);
        return NULL;
    }

    *data = (tracking_data_t){.base_allocator    = base_allocator,
                              .total_allocated   = 0,
                              .current_allocated = 0,
                              .allocation_count  = 0};

    *allocator = (allocator_t){.vtable = &tracking_vtable, .user_data = data, .name = "tracking"};

    return allocator;
}

bool str_get_allocation_stats(allocator_t* allocator, size_t* total_allocated,
                              size_t* current_allocated, size_t* allocation_count) {
    if (!allocator || allocator->vtable != &tracking_vtable) {
        return false;
    }

    tracking_data_t* data = (tracking_data_t*)allocator->user_data;
    if (total_allocated) *total_allocated = data->total_allocated;
    if (current_allocated) *current_allocated = data->current_allocated;
    if (allocation_count) *allocation_count = data->allocation_count;
    return true;
}

/* ===========================================================================
 * ARENA ALLOCATOR IMPLEMENTATION
 * =========================================================================*/

typedef struct arena_block {
    struct arena_block* next;
    size_t capacity;
    size_t used;
} arena_block;

typedef struct {
    arena_block* first_block;
    arena_block* current_block;
    size_t default_block_size;
} arena_state;

#define ARENA_DEFAULT_BLOCK_SIZE (64 * 1024)

static void* arena_alloc(allocator_t* allocator, size_t size) {
    arena_state* state = (arena_state*)allocator->user_data;
    if (size == 0) return NULL;

    size = (size + 7) & ~7;

    if (!state->current_block ||
        (state->current_block->used + size > state->current_block->capacity)) {
        size_t block_size = state->default_block_size;
        if (size > block_size) {
            block_size = size + sizeof(arena_block);
        }

        arena_block* new_block = (arena_block*)malloc(sizeof(arena_block) + block_size);
        if (!new_block) return NULL;

        new_block->next     = NULL;
        new_block->capacity = block_size;
        new_block->used     = 0;

        if (state->current_block) {
            state->current_block->next = new_block;
        } else {
            state->first_block = new_block;
        }
        state->current_block = new_block;
    }

    void* ptr = (char*)(state->current_block + 1) + state->current_block->used;
    state->current_block->used += size;
    return ptr;
}

static void* arena_realloc(allocator_t* allocator, void* ptr, size_t old_size, size_t new_size) {
    arena_state* state = (arena_state*)allocator->user_data;
    if (!ptr) return arena_alloc(allocator, new_size);
    if (new_size == 0) return NULL;

    if (state->current_block && ptr >= (void*)(state->current_block + 1) &&
        ptr <= (void*)((char*)(state->current_block + 1) + state->current_block->used)) {

        size_t offset = (char*)ptr - (char*)(state->current_block + 1);
        if (offset + old_size == state->current_block->used) {
            size_t available = state->current_block->capacity - state->current_block->used;
            if (old_size + available >= new_size) {
                state->current_block->used += (new_size - old_size);
                return ptr;
            }
        }
    }

    void* new_ptr = arena_alloc(allocator, new_size);
    if (new_ptr && old_size > 0) {
        memcpy(new_ptr, ptr, old_size < new_size ? old_size : new_size);
    }
    return new_ptr;
}

static void arena_free(allocator_t* allocator, void* ptr, size_t size) {
    (void)allocator;
    (void)ptr;
    (void)size;
}

static void arena_destroy(allocator_t* allocator) {
    arena_allocator_destroy(allocator);
}

static const allocator_vtable_t arena_vtable = {.alloc   = arena_alloc,
                                                .realloc = arena_realloc,
                                                .free    = arena_free,
                                                .destroy = arena_destroy};

allocator_t* arena_allocator_create(size_t initial_size) {
    allocator_t* allocator = (allocator_t*)malloc(sizeof(allocator_t));
    if (!allocator) return NULL;

    arena_state* state = (arena_state*)malloc(sizeof(arena_state));
    if (!state) {
        free(allocator);
        return NULL;
    }

    *state =
        (arena_state){.first_block        = NULL,
                      .current_block      = NULL,
                      .default_block_size = initial_size ? initial_size : ARENA_DEFAULT_BLOCK_SIZE};

    *allocator = (allocator_t){.vtable = &arena_vtable, .user_data = state, .name = "arena"};

    return allocator;
}

void arena_allocator_destroy(allocator_t* allocator) {
    if (!allocator || allocator->vtable != &arena_vtable) return;

    arena_state* state = (arena_state*)allocator->user_data;
    arena_block* block = state->first_block;
    while (block) {
        arena_block* next = block->next;
        free(block);
        block = next;
    }

    free(state);
    free(allocator);
}

void arena_allocator_reset(allocator_t* allocator) {
    if (!allocator || allocator->vtable != &arena_vtable) return;

    arena_state* state = (arena_state*)allocator->user_data;
    arena_block* block = state->first_block;
    while (block) {
        block->used = 0;
        block       = block->next;
    }
    state->current_block = state->first_block;
}

/* ===========================================================================
 * STRING VIEW IMPLEMENTATION
 * =========================================================================*/

int str_cmp(str a, str b) {
    if (a.data == NULL || b.data == NULL) {
        if (a.data == NULL && b.data == NULL) return 0;
        return a.data == NULL ? -1 : 1;
    }

    size_t min_len = a.size < b.size ? a.size : b.size;
    int result     = memcmp(a.data, b.data, min_len);

    if (result == 0) {
        if (a.size < b.size) return -1;
        if (a.size > b.size) return 1;
    }
    return result;
}

int str_icmp(str a, str b) {
    if (a.data == NULL || b.data == NULL) {
        if (a.data == NULL && b.data == NULL) return 0;
        return a.data == NULL ? -1 : 1;
    }

    size_t min_len = a.size < b.size ? a.size : b.size;
    for (size_t i = 0; i < min_len; i++) {
        int ca = tolower((unsigned char)a.data[i]);
        int cb = tolower((unsigned char)b.data[i]);
        if (ca != cb) return ca - cb;
    }

    if (a.size < b.size) return -1;
    if (a.size > b.size) return 1;
    return 0;
}

bool str_starts_with(str s, str prefix) {
    if (prefix.size == 0) return true;
    if (s.data == NULL || prefix.data == NULL) return false;
    if (prefix.size > s.size) return false;
    return memcmp(s.data, prefix.data, prefix.size) == 0;
}

bool str_ends_with(str s, str suffix) {
    if (suffix.size == 0) return true;
    if (s.data == NULL || suffix.data == NULL) return false;
    if (suffix.size > s.size) return false;
    return memcmp(s.data + s.size - suffix.size, suffix.data, suffix.size) == 0;
}

size_t str_find(str haystack, str needle) {
    if (needle.size == 0) return 0;
    if (haystack.data == NULL || needle.data == NULL) return SIZE_MAX;
    if (needle.size > haystack.size) return SIZE_MAX;

    for (size_t i = 0; i <= haystack.size - needle.size; i++) {
        if (memcmp(haystack.data + i, needle.data, needle.size) == 0) {
            return i;
        }
    }
    return SIZE_MAX;
}

str str_substr(str s, size_t start, size_t len) {
    if (s.data == NULL || start >= s.size) return str_empty();
    size_t actual_len = len;
    if (start + len > s.size) {
        actual_len = s.size - start;
    }
    return (str){.data = s.data + start, .size = actual_len};
}

str str_trim(str s) {
    if (s.size == 0 || s.data == NULL) return s;

    size_t start = 0;
    while (start < s.size && isspace((unsigned char)s.data[start])) {
        start++;
    }

    size_t end = s.size;
    while (end > start && isspace((unsigned char)s.data[end - 1])) {
        end--;
    }

    return (str){.data = s.data + start, .size = end - start};
}

/* ===========================================================================
 * STRING BUFFER IMPLEMENTATION
 * =========================================================================*/

#define STR_BUF_MIN_CAPACITY 16

static str_result_t str_buf_grow(str_buf* buf, size_t required_capacity) {
    if (!buf || !buf->allocator) return STR_ERR_NULL_PTR;
    if (required_capacity + 1 <= buf->capacity) return STR_OK;

    size_t new_capacity = buf->capacity == 0 ? STR_BUF_MIN_CAPACITY : buf->capacity;
    while (new_capacity < required_capacity + 1) {
        if (new_capacity > SIZE_MAX / 2) {
            new_capacity = required_capacity + 1;
            break;
        }
        new_capacity *= 2;
    }

    char* new_data = allocator_realloc(buf->allocator, buf->data, buf->capacity, new_capacity);
    if (!new_data) return STR_ERR_OUT_OF_MEMORY;

    buf->data     = new_data;
    buf->capacity = new_capacity;
    if (buf->size == 0) {
        buf->data[0] = '\0';
    }
    return STR_OK;
}

str_result_t str_buf_init(str_buf* buf, allocator_t* allocator) {
    if (!buf) return STR_ERR_NULL_PTR;
    *buf = (str_buf){.data      = NULL,
                     .size      = 0,
                     .capacity  = 0,
                     .allocator = allocator ? allocator : str_default_allocator()};
    return str_buf_grow(buf, 0);
}

str_result_t str_buf_init_cap(str_buf* buf, size_t initial_capacity, allocator_t* allocator) {
    str_result_t result = str_buf_init(buf, allocator);
    if (result != STR_OK) return result;
    if (initial_capacity > 0) {
        return str_buf_grow(buf, initial_capacity);
    }
    return STR_OK;
}

void str_buf_free(str_buf* buf) {
    if (buf && buf->allocator && buf->data) {
        allocator_free(buf->allocator, buf->data, buf->capacity);
        *buf = (str_buf){0};
    }
}

str_result_t str_buf_reserve(str_buf* buf, size_t capacity) {
    if (!buf) return STR_ERR_NULL_PTR;
    return str_buf_grow(buf, capacity);
}

str_result_t str_buf_append(str_buf* buf, str s) {
    if (!buf) return STR_ERR_NULL_PTR;
    if (s.size == 0 || s.data == NULL) return STR_OK;

    str_result_t result = str_buf_grow(buf, buf->size + s.size);
    if (result != STR_OK) return result;

    memcpy(buf->data + buf->size, s.data, s.size);
    buf->size += s.size;
    buf->data[buf->size] = '\0';
    return STR_OK;
}

str_result_t str_buf_append_cstr(str_buf* buf, const char* cstr) {
    if (!cstr) return STR_OK;
    return str_buf_append(buf, str_from_cstr(cstr));
}

str_result_t str_buf_append_char(str_buf* buf, char c) {
    if (!buf) return STR_ERR_NULL_PTR;
    str_result_t result = str_buf_grow(buf, buf->size + 1);
    if (result != STR_OK) return result;
    buf->data[buf->size++] = c;
    buf->data[buf->size]   = '\0';
    return STR_OK;
}

str_result_t str_buf_appendf(str_buf* buf, const char* fmt, ...) {
    if (!buf || !fmt) return STR_ERR_NULL_PTR;

    va_list args1, args2;
    va_start(args1, fmt);
    va_copy(args2, args1);

    int needed = vsnprintf(NULL, 0, fmt, args1);
    va_end(args1);

    if (needed < 0) {
        va_end(args2);
        return STR_ERR_INVALID_ARG;
    }

    str_result_t result = str_buf_grow(buf, buf->size + needed);
    if (result != STR_OK) {
        va_end(args2);
        return result;
    }

    vsnprintf(buf->data + buf->size, needed + 1, fmt, args2);
    va_end(args2);
    buf->size += needed;
    return STR_OK;
}

str_result_t str_buf_insert(str_buf* buf, size_t pos, str s) {
    if (!buf) return STR_ERR_NULL_PTR;
    if (pos > buf->size) return STR_ERR_INVALID_ARG;
    if (s.size == 0 || s.data == NULL) return STR_OK;

    str_result_t result = str_buf_grow(buf, buf->size + s.size);
    if (result != STR_OK) return result;

    if (pos < buf->size) {
        memmove(buf->data + pos + s.size, buf->data + pos, buf->size - pos);
    }

    memcpy(buf->data + pos, s.data, s.size);
    buf->size += s.size;
    buf->data[buf->size] = '\0';
    return STR_OK;
}

str_result_t str_buf_remove(str_buf* buf, size_t start, size_t len) {
    if (!buf) return STR_ERR_NULL_PTR;
    if (start > buf->size) return STR_ERR_INVALID_ARG;

    if (start + len > buf->size) {
        len = buf->size - start;
    }

    if (len == 0) return STR_OK;

    if (start + len < buf->size) {
        memmove(buf->data + start, buf->data + start + len, buf->size - start - len);
    }

    buf->size -= len;
    buf->data[buf->size] = '\0';
    return STR_OK;
}

str_result_t str_buf_replace_all(str_buf* buf, str find, str replace) {
    if (!buf) return STR_ERR_NULL_PTR;
    if (find.size == 0 || find.data == NULL) return STR_ERR_INVALID_ARG;

    size_t search_pos = 0;
    while (search_pos < buf->size) {
        str remaining       = str_from_buf(buf->data + search_pos, buf->size - search_pos);
        size_t relative_pos = str_find(remaining, find);

        if (relative_pos == SIZE_MAX) break;

        size_t absolute_pos = search_pos + relative_pos;
        str_result_t result = str_buf_remove(buf, absolute_pos, find.size);
        if (result != STR_OK) return result;

        result = str_buf_insert(buf, absolute_pos, replace);
        if (result != STR_OK) return result;

        search_pos = absolute_pos + replace.size;
    }
    return STR_OK;
}
