#ifndef STR_H
#define STR_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file str.h
 * @brief String handling library with views, buffers, and custom allocators
 */

/* ===========================================================================
 * ALLOCATOR INTERFACE
 * =========================================================================*/

/**
 * @brief Forward declaration of allocator type
 */
typedef struct allocator_t allocator_t;

/* ===========================================================================
 * STRING TYPES
 * =========================================================================*/

/**
 * @brief Immutable string view (non-owning)
 */
typedef struct str {
    const char* data;  ///< String data (may not be null-terminated)
    size_t size;       ///< Length of string (excluding null terminator)
} str;

/**
 * @brief Growable string buffer (owning)
 */
typedef struct str_buf {
    char* data;              ///< String data (always null-terminated)
    size_t size;             ///< Length of string (excluding null terminator)
    size_t capacity;         ///< Total allocated capacity
    allocator_t* allocator;  ///< Memory allocator
} str_buf;

/**
 * @brief Operation result codes
 */
typedef enum {
    STR_OK = 0,             ///< Operation succeeded
    STR_ERR_NULL_PTR,       ///< Null pointer encountered
    STR_ERR_OUT_OF_MEMORY,  ///< Memory allocation failed
    STR_ERR_INVALID_ARG,    ///< Invalid argument provided
    STR_ERR_NOT_FOUND       ///< Requested item not found
} str_result_t;

/* ===========================================================================
 * ALLOCATOR MANAGEMENT
 * =========================================================================*/

/**
 * @brief Get the default allocator (uses malloc/realloc/free)
 * You must call str_allocator_free or free() to realease memory allocated with it.
 * @return Pointer to default allocator (never NULL)
 */
allocator_t* str_default_allocator(void);

/**
 * @brief Free object allocated with allocator.
 * @param allocator The allocator pointer.
 * @param ptr The pointer to free.
 * @param size Size of the allocation. May be 0 if using default allocator.
 * @return Pointer to default allocator (never NULL)
 */
void str_allocator_free(allocator_t* allocator, void* ptr, size_t size);

/**
 * @brief Create a tracking allocator that wraps another allocator
 * @param base_allocator The allocator to wrap (NULL for default)
 * @return New tracking allocator or NULL on failure
 * @note The returned allocator must be freed with allocator_destroy()
 */
allocator_t* str_create_tracking_allocator(allocator_t* base_allocator);

/**
 * @brief Get allocation statistics from a tracking allocator
 * @param allocator The tracking allocator
 * @param[out] total_allocated Total bytes allocated
 * @param[out] current_allocated Currently allocated bytes
 * @param[out] allocation_count Number of allocations
 * @return true if statistics were retrieved, false if invalid allocator
 */
bool str_get_allocation_stats(allocator_t* allocator, size_t* total_allocated,
                              size_t* current_allocated, size_t* allocation_count);

/**
 * @brief Create a new arena allocator
 * @param initial_size Initial size of the arena (0 for default)
 * @return New arena allocator or NULL on failure
 */
allocator_t* arena_allocator_create(size_t initial_size);

/**
 * @brief Destroy an arena allocator and free all its memory
 * @param allocator Arena allocator to destroy
 */
void arena_allocator_destroy(allocator_t* allocator);

/**
 * @brief Reset an arena allocator (free all allocations but retain memory)
 * @param allocator Arena allocator to reset
 */
void arena_allocator_reset(allocator_t* allocator);

/* ===========================================================================
 * STRING VIEW OPERATIONS
 * =========================================================================*/

/**
 * @brief Create string view from null-terminated C string
 * @param cstr Null-terminated C string (may be NULL)
 * @return str view (empty if cstr is NULL)
 */
static inline str str_from_cstr(const char* cstr) {
    return cstr ? (str){.data = cstr, .size = strlen(cstr)} : (str){0};
}

/**
 * @brief Create string view from buffer with known length
 * @param data Buffer containing string data (may be NULL)
 * @param size Length of data (ignored if data is NULL)
 * @return str view (empty if data is NULL)
 */
static inline str str_from_buf(const char* data, size_t size) {
    return data ? (str){.data = data, .size = size} : (str){0};
}

/**
 * @brief Create empty string view
 * @return Empty str view
 */
static inline str str_empty(void) {
    return (str){.data = "", .size = 0};
}

/**
 * @brief Check if string view is empty
 * @param s String to check
 * @return true if empty, false otherwise
 */
static inline bool str_is_empty(str s) {
    return s.size == 0 || s.data == NULL;
}

/**
 * @brief Compare two string views lexicographically
 * @param a First string
 * @param b Second string
 * @return <0 if a < b, 0 if a == b, >0 if a > b
 */
int str_cmp(str a, str b);

/**
 * @brief Case-insensitive string comparison
 * @param a First string
 * @param b Second string
 * @return <0 if a < b, 0 if a == b, >0 if a > b (case-insensitive)
 */
int str_icmp(str a, str b);

/**
 * @brief Check if string starts with prefix
 * @param s String to check
 * @param prefix Prefix to look for
 * @return true if string starts with prefix, false otherwise
 */
bool str_starts_with(str s, str prefix);

/**
 * @brief Check if string ends with suffix
 * @param s String to check
 * @param suffix Suffix to look for
 * @return true if string ends with suffix, false otherwise
 */
bool str_ends_with(str s, str suffix);

/**
 * @brief Find first occurrence of substring
 * @param haystack String to search in
 * @param needle Substring to find
 * @return Position of first occurrence or SIZE_MAX if not found
 */
size_t str_find(str haystack, str needle);

/**
 * @brief Create substring view
 * @param s Original string
 * @param start Starting position (0-based)
 * @param len Length of substring
 * @return Substring view (empty if start is out of bounds)
 */
str str_substr(str s, size_t start, size_t len);

/**
 * @brief Trim whitespace from both ends of string
 * @param s String to trim
 * @return Trimmed string view
 */
str str_trim(str s);

/* ===========================================================================
 * STRING BUFFER OPERATIONS
 * =========================================================================*/

/**
 * @brief Initialize string buffer with default capacity
 * @param buf Buffer to initialize
 * @param allocator Allocator to use (NULL for default)
 * @return STR_OK on success, error code otherwise
 */
str_result_t str_buf_init(str_buf* buf, allocator_t* allocator);

/**
 * @brief Initialize string buffer with specific capacity
 * @param buf Buffer to initialize
 * @param initial_capacity Initial capacity (excluding null terminator)
 * @param allocator Allocator to use (NULL for default)
 * @return STR_OK on success, error code otherwise
 */
str_result_t str_buf_init_cap(str_buf* buf, size_t initial_capacity, allocator_t* allocator);

/**
 * @brief Free string buffer resources
 * @param buf Buffer to free
 */
void str_buf_free(str_buf* buf);

/**
 * @brief Get string view of buffer contents
 * @param buf Buffer to view
 * @return str view of buffer contents
 */
static inline str str_buf_view(const str_buf* buf) {
    return buf && buf->data ? (str){.data = buf->data, .size = buf->size} : str_empty();
}

/**
 * @brief Clear buffer contents (retains capacity)
 * @param buf Buffer to clear
 */
static inline void str_buf_clear(str_buf* buf) {
    if (buf && buf->data && buf->capacity > 0) {
        buf->size    = 0;
        buf->data[0] = '\0';
    }
}

/**
 * @brief Reserve capacity in buffer
 * @param buf Buffer to modify
 * @param capacity Minimum capacity to reserve (excluding null terminator)
 * @return STR_OK on success, error code otherwise
 */
str_result_t str_buf_reserve(str_buf* buf, size_t capacity);

/**
 * @brief Append string to buffer
 * @param buf Buffer to modify
 * @param s String to append
 * @return STR_OK on success, error code otherwise
 */
str_result_t str_buf_append(str_buf* buf, str s);

/**
 * @brief Append C string to buffer
 * @param buf Buffer to modify
 * @param cstr Null-terminated string to append
 * @return STR_OK on success, error code otherwise
 */
str_result_t str_buf_append_cstr(str_buf* buf, const char* cstr);

/**
 * @brief Append single character to buffer
 * @param buf Buffer to modify
 * @param c Character to append
 * @return STR_OK on success, error code otherwise
 */
str_result_t str_buf_append_char(str_buf* buf, char c);

/**
 * @brief Append formatted string (printf-style) to buffer
 * @param buf Buffer to modify
 * @param fmt Format string
 * @param ... Format arguments
 * @return STR_OK on success, error code otherwise
 */
str_result_t str_buf_appendf(str_buf* buf, const char* fmt, ...);

/**
 * @brief Insert string into buffer at specified position
 * @param buf Buffer to modify
 * @param pos Position to insert at (0-based)
 * @param s String to insert
 * @return STR_OK on success, error code otherwise
 */
str_result_t str_buf_insert(str_buf* buf, size_t pos, str s);

/**
 * @brief Remove characters from buffer
 * @param buf Buffer to modify
 * @param start Starting position (0-based)
 * @param len Number of characters to remove
 * @return STR_OK on success, error code otherwise
 */
str_result_t str_buf_remove(str_buf* buf, size_t start, size_t len);

/**
 * @brief Replace all occurrences of a substring
 * @param buf Buffer to modify
 * @param find Substring to find
 * @param replace Replacement string
 * @return STR_OK on success, error code otherwise
 */
str_result_t str_buf_replace_all(str_buf* buf, str find, str replace);

#ifdef __cplusplus
}
#endif

#endif  // STR_H
