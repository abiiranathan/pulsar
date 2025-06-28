#include "../include/cstr.h"
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define IS_POWER_OF_TWO(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

// Small String Optimization (SSO) constants
#define SSO_MAX_SIZE (sizeof(size_t) + sizeof(size_t) + sizeof(char*) - 1)
#define SSO_HEAP_FLAG 0x80
#define SSO_LENGTH_MASK 0x7F
#define HEAP_FLAG_BIT (1ULL << 63)

// Security and performance constants
#define CSTR_GROWTH_FACTOR 2
#define CSTR_MIN_HEAP_CAPACITY 16
#define CSTR_MAX_REASONABLE_SIZE (SIZE_MAX / 4)  // Prevent overflow attacks
static_assert(IS_POWER_OF_TWO(CSTR_MIN_HEAP_CAPACITY), "STR_MIN_CAPACITY must be a power of two");

// Macros for capacity manipulation
#define CSTR_SET_HEAP_CAPACITY(cap) ((cap) | HEAP_FLAG_BIT)
#define CSTR_GET_HEAP_CAPACITY(cap) ((cap) & ~HEAP_FLAG_BIT)

#define CSTR_IS_HEAP(s) ((s->heap.capacity & HEAP_FLAG_BIT) != 0)

#define WOULD_OVERFLOW_ADD(a, b) (a > SIZE_MAX - b)
#define would_overflow_mul(a, b) (b != 0 && a > SIZE_MAX / b)

/**
 * @brief A dynamically resizable C-string with Small String Optimization (SSO).
 *
 * This structure implements an efficient string type that stores small strings
 * (up to SSO_MAX_SIZE bytes) directly in the structure to avoid heap allocation,
 * and larger strings on the heap. This provides optimal performance for both
 * small and large strings while maintaining a consistent API.
 *
 * The structure uses a union to overlay stack and heap storage modes:
 * - Stack mode: For strings up to SSO_MAX_SIZE-1 characters
 * - Heap mode: For larger strings, indicated by the MSB of capacity field
 *
 * @note All strings are null-terminated regardless of storage mode.
 * @note The structure size is optimized to fit common cache line sizes.
 */
typedef struct cstr {
    union {
        struct {
            /// @brief Length of the string (excluding null terminator)
            size_t length;

            /// @brief Capacity with heap flag in MSB. Use CSTR_GET_HEAP_CAPACITY() to extract actual
            /// capacity.
            size_t capacity;

            /// @brief Pointer to heap-allocated string data
            char* data;
        } heap;

        struct {
            /// @brief Inline buffer for small strings
            char data[SSO_MAX_SIZE];

            /// @brief Length of stack string (with potential flags in upper bits)
            unsigned char len;
        } stack;
    };
} cstr;

// --- Internal Helper Functions ---

/**
 * @brief Retrieves the length of the string.
 * @param s Pointer to the cstr (must not be NULL)
 * @return Length of the string excluding null terminator
 * @pre s != NULL
 */
static inline size_t cstr_get_length(const cstr* s) {
    if (CSTR_IS_HEAP(s)) {
        return s->heap.length;
    } else {
        return s->stack.len & SSO_LENGTH_MASK;
    }
}

/**
 * @brief Retrieves a mutable pointer to the string data.
 * @param s Pointer to the cstr (must not be NULL)
 * @return Pointer to null-terminated string data
 * @pre s != NULL
 */
static inline char* cstr_get_data(cstr* s) {
    return CSTR_IS_HEAP(s) ? s->heap.data : s->stack.data;
}

/**
 * @brief Retrieves a const pointer to the string data.
 * @param s Pointer to the cstr (must not be NULL)
 * @return Const pointer to null-terminated string data
 * @pre s != NULL
 */
static inline const char* cstr_get_data_const(const cstr* s) {
    return CSTR_IS_HEAP(s) ? s->heap.data : s->stack.data;
}

/**
 * @brief Retrieves the current capacity of the string.
 * @param s Pointer to the cstr (must not be NULL)
 * @return Capacity including space for null terminator
 * @pre s != NULL
 */
static inline size_t cstr_get_capacity(const cstr* s) {
    return CSTR_IS_HEAP(s) ? CSTR_GET_HEAP_CAPACITY(s->heap.capacity) : SSO_MAX_SIZE;
}

/**
 * @brief Sets the length of the string.
 *
 * This function updates the length field without modifying the actual string data.
 * The caller is responsible for ensuring the string data is properly null-terminated
 * and that the length is accurate.
 *
 * @param s Pointer to the cstr (must not be NULL)
 * @param len New length (must be less than current capacity)
 * @pre s != NULL
 * @pre len < cstr_get_capacity(s)
 */
static inline void cstr_set_length(cstr* s, size_t len) {
    assert(len < cstr_get_capacity(s));

    if (CSTR_IS_HEAP(s)) {
        s->heap.length = len;
    } else {
        s->stack.len = (unsigned char)len;
    }
}

/**
 * @brief Calculates optimal capacity for growth.
 *
 * Uses a growth factor to minimize reallocations while preventing excessive
 * memory usage. Includes overflow protection.
 *
 * @param current_cap Current capacity
 * @param min_needed Minimum capacity needed
 * @return Optimal new capacity, or 0 if overflow would occur
 */
static size_t calculate_growth_capacity(size_t current_cap, size_t min_needed) {
    if (min_needed > CSTR_MAX_REASONABLE_SIZE) {
        return 0;  // Prevent unreasonable allocations
    }

    // Ensure minimum heap capacity
    if (min_needed < CSTR_MIN_HEAP_CAPACITY) {
        min_needed = CSTR_MIN_HEAP_CAPACITY;
    }

    // Try growth factor approach
    if (!would_overflow_mul(current_cap, CSTR_GROWTH_FACTOR)) {
        size_t grown = current_cap * CSTR_GROWTH_FACTOR;
        if (grown >= min_needed && grown <= CSTR_MAX_REASONABLE_SIZE) {
            return grown;
        }
    }

    // Fallback to minimum needed
    return min_needed;
}

/**
 * @brief Promotes a stack-allocated string to heap storage.
 *
 * This function transitions a string from stack storage to heap storage when
 * the required capacity exceeds the SSO threshold. It preserves all existing
 * string data during the transition.
 *
 * @param s Pointer to the cstr (must be stack-allocated)
 * @param capacity_needed Minimum capacity required including null terminator
 * @return true on success, false on allocation failure
 * @pre s != NULL && !CSTR_IS_HEAP(s)
 * @pre capacity_needed > SSO_MAX_SIZE
 */
static bool cstr_promote_to_heap(cstr* s, size_t capacity_needed) {
    assert(!CSTR_IS_HEAP(s));
    assert(capacity_needed > SSO_MAX_SIZE);

    // Prevent overflow attacks
    if (capacity_needed > CSTR_MAX_REASONABLE_SIZE) {
        return false;
    }

    // Extract stack data before modifying the struct
    size_t current_len = s->stack.len & SSO_LENGTH_MASK;
    char stack_data[SSO_MAX_SIZE];
    memcpy(stack_data, s->stack.data, current_len + 1);

    // Calculate optimal capacity
    size_t optimal_capacity = calculate_growth_capacity(SSO_MAX_SIZE, capacity_needed);
    if (optimal_capacity == 0) {
        return false;
    }

    char* new_data = malloc(optimal_capacity);
    if (!new_data) {
        return false;
    }

    // Copy data and transition to heap mode
    memcpy(new_data, stack_data, current_len + 1);

    s->heap.data     = new_data;
    s->heap.length   = current_len;
    s->heap.capacity = CSTR_SET_HEAP_CAPACITY(optimal_capacity);

    return true;
}

/**
 * @brief Ensures the string has at least the specified capacity.
 *
 * This function handles both stack-to-heap promotion and heap reallocation
 * as needed. It uses intelligent growth strategies to minimize future
 * reallocations while preventing excessive memory usage.
 *
 * @param s Pointer to the cstr (must not be NULL)
 * @param new_capacity Minimum capacity required including null terminator
 * @return true on success, false on allocation failure or overflow
 * @pre s != NULL
 */
static bool cstr_ensure_capacity(cstr* s, size_t new_capacity) {
    if (new_capacity <= cstr_get_capacity(s)) {
        return true;
    }

    // Prevent overflow attacks
    if (new_capacity > CSTR_MAX_REASONABLE_SIZE) {
        return false;
    }

    if (CSTR_IS_HEAP(s)) {
        size_t optimal_capacity = calculate_growth_capacity(cstr_get_capacity(s), new_capacity);
        if (optimal_capacity == 0) {
            return false;
        }

        char* new_data = realloc(s->heap.data, optimal_capacity);
        if (!new_data) {
            return false;
        }

        s->heap.data     = new_data;
        s->heap.capacity = CSTR_SET_HEAP_CAPACITY(optimal_capacity);
    } else {
        return cstr_promote_to_heap(s, new_capacity);
    }

    return true;
}

// --- Public API Functions ---

/**
 * @brief Creates a new empty cstr with specified initial capacity.
 *
 * Creates a new dynamically allocated cstr with at least the requested capacity.
 * The string is initialized to empty but can grow up to the specified capacity
 * without reallocation.
 *
 * @param initial_capacity Requested initial capacity including null terminator
 * @return Pointer to new cstr on success, NULL on allocation failure
 * @note Caller must call str_free() to release memory
 * @note Actual capacity may be larger than requested for optimization
 */
cstr* cstr_init(size_t initial_capacity) {
    // Prevent overflow attacks
    if (initial_capacity > CSTR_MAX_REASONABLE_SIZE) {
        return NULL;
    }

    cstr* s = malloc(sizeof(cstr));
    if (!s) {
        return NULL;
    }

    initial_capacity = MAX(initial_capacity, CSTR_MIN_HEAP_CAPACITY);

    if (initial_capacity <= SSO_MAX_SIZE) {
        // Initialize as stack-allocated string
        s->stack.len     = 0;
        s->stack.data[0] = '\0';
        // Clear remaining bytes for security
        memset(s->stack.data + 1, 0, SSO_MAX_SIZE - 1);
    } else {
        size_t optimal_capacity = calculate_growth_capacity(0, initial_capacity);
        if (optimal_capacity == 0) {
            free(s);
            return NULL;
        }

        char* data = malloc(optimal_capacity);
        if (!data) {
            free(s);
            return NULL;
        }

        data[0]          = '\0';
        s->heap.data     = data;
        s->heap.length   = 0;
        s->heap.capacity = CSTR_SET_HEAP_CAPACITY(optimal_capacity);
    }

    return s;
}

/**
 * @brief Creates a new cstr from a C string.
 *
 * Creates a new cstr containing a copy of the input C string. The new string
 * will have exactly the capacity needed to store the input plus room for growth.
 *
 * @param input C string to copy (must be null-terminated, can be NULL)
 * @return Pointer to new cstr on success, NULL on allocation failure or if input is NULL
 * @note Caller must call str_free() to release memory
 */
cstr* cstr_new(const char* input) {
    if (!input) {
        return NULL;
    }

    size_t len = strlen(input);
    cstr* str  = cstr_init(len + 1);
    if (!str) {
        return NULL;
    }

    if (len > 0) {
        char* dest = cstr_get_data(str);
        memcpy(dest, input, len);
        dest[len] = '\0';
        cstr_set_length(str, len);
    }

    return str;
}

/**
 * @brief Debug function to print comprehensive string information.
 *
 * Outputs detailed information about the string's internal state, including
 * storage mode, capacity, length, and raw data representation. Useful for
 * debugging and understanding the SSO behavior.
 *
 * @param s Pointer to the cstr (can be NULL)
 */
void cstr_debug(const cstr* s) {
    if (!s) {
        printf("String: NULL\n");
        return;
    }

    printf("=== String Debug Info ===\n");
    printf("Storage type: %s\n", CSTR_IS_HEAP(s) ? "heap" : "stack");
    printf("Length: %zu\n", cstr_get_length(s));
    printf("Capacity: %zu\n", cstr_get_capacity(s));
    printf("Content: \"%s\"\n", cstr_get_data_const((cstr*)s));
    printf("Union size: %zu bytes\n", sizeof(cstr));

    if (CSTR_IS_HEAP(s)) {
        printf("--- Heap Details ---\n");
        printf("Raw capacity field: 0x%016lx\n", s->heap.capacity);
        printf("Actual capacity: %zu\n", cstr_get_capacity(s));
        printf("Data pointer: %p\n", (void*)s->heap.data);
        printf("Heap flag bit set: %s\n", (s->heap.capacity & HEAP_FLAG_BIT) != 0 ? "yes" : "no");
    } else {
        printf("--- Stack Details ---\n");
        printf("Available space: %zu bytes\n", SSO_MAX_SIZE);
        printf("Used space: %zu bytes\n", cstr_get_length(s));
        printf("Free space: %zu bytes\n", SSO_MAX_SIZE - cstr_get_length(s));
        printf("len_and_flag value: %u\n", s->stack.len);

        printf("Stack data (hex): ");
        for (size_t i = 0; i < SSO_MAX_SIZE; i++) {
            printf("%02x ", (unsigned char)s->stack.data[i]);
        }
        printf("\n");
    }
    printf("========================\n\n");
}

/**
 * @brief Checks if the string uses heap storage.
 *
 * @param s Pointer to the cstr (can be NULL)
 * @return true if heap-allocated, false if stack-allocated or NULL
 */
bool cstr_allocated(const cstr* s) {
    return s && CSTR_IS_HEAP(s);
}

/**
 * @brief Frees a cstr and all associated memory.
 *
 * Releases all memory associated with the cstr, including heap-allocated
 * string data if applicable. After calling this function, the pointer
 * becomes invalid and must not be used.
 *
 * @param s Pointer to the cstr to free (can be NULL)
 * @note Safe to call with NULL pointer
 */
void cstr_free(cstr* s) {
    if (!s) {
        return;
    }

    if (CSTR_IS_HEAP(s)) {
        free(s->heap.data);
    }

    // Clear memory for security
    memset(s, 0, sizeof(cstr));
    free(s);
}

/**
 * @brief Returns the length of the string.
 *
 * @param s Pointer to the cstr (can be NULL)
 * @return Length excluding null terminator, or 0 if s is NULL
 */
size_t cstr_len(const cstr* s) {
    return s ? cstr_get_length(s) : 0;
}

/**
 * @brief Returns the current capacity of the string.
 *
 * @param s Pointer to the cstr (can be NULL)
 * @return Current capacity including null terminator, or 0 if s is NULL
 */
size_t cstr_capacity(const cstr* s) {
    return s ? cstr_get_capacity(s) : 0;
}

/**
 * @brief Checks if the string is empty.
 *
 * @param s Pointer to the cstr (can be NULL)
 * @return true if NULL or empty, false otherwise
 */
bool cstr_empty(const cstr* s) {
    return !s || cstr_get_length(s) == 0;
}

/**
 * @brief Resizes the string's capacity.
 *
 * Ensures the string has at least the specified capacity. If the current
 * capacity is already sufficient, no operation is performed.
 *
 * @param s Pointer to the cstr (must not be NULL)
 * @param new_capacity Minimum required capacity including null terminator
 * @return true on success, false on allocation failure or if s is NULL
 */
bool cstr_resize(cstr* s, size_t new_capacity) {
    if (!s) {
        return false;
    }
    return cstr_ensure_capacity(s, new_capacity);
}

/**
 * @brief Appends a C string to the cstr.
 *
 * Appends the entire source string to the end of the destination string,
 * automatically reallocating if necessary.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param append_str C string to append (must not be NULL)
 * @return true on success, false on allocation failure or invalid input
 */
bool cstr_append(cstr* s, const char* append_str) {
    if (!s || !append_str) {
        return false;
    }

    size_t append_len = strlen(append_str);
    if (append_len == 0) {
        return true;
    }

    size_t current_len = cstr_get_length(s);

    // Check for overflow
    if (WOULD_OVERFLOW_ADD(current_len, append_len) || WOULD_OVERFLOW_ADD(current_len + append_len, 1)) {
        return false;
    }

    size_t new_len = current_len + append_len;
    if (!cstr_ensure_capacity(s, new_len + 1)) {
        return false;
    }

    char* dest = cstr_get_data(s);
    memcpy(dest + current_len, append_str, append_len);
    dest[new_len] = '\0';
    cstr_set_length(s, new_len);

    return true;
}

/**
 * @brief Fast append assuming sufficient capacity.
 *
 * Appends a C string without checking or expanding capacity. The caller
 * must ensure sufficient capacity exists.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param append_str C string to append (must not be NULL)
 * @return true on success, false on invalid input
 * @pre Sufficient capacity must exist for the append operation
 */
bool cstr_append_fast(cstr* s, const char* append_str) {
    if (!s || !append_str) {
        return false;
    }

    size_t append_len = strlen(append_str);
    if (append_len == 0) {
        return true;
    }

    size_t current_len = cstr_get_length(s);

    // Verify capacity assumption
    assert(current_len + append_len + 1 <= cstr_get_capacity(s));

    char* dest = cstr_get_data(s);
    memcpy(dest + current_len, append_str, append_len);
    dest[current_len + append_len] = '\0';
    cstr_set_length(s, current_len + append_len);

    return true;
}

/**
 * @brief Creates a new cstr from a formatted string (printf-style).
 *
 * Creates a new cstr by formatting the input according to the format string,
 * similar to sprintf but with automatic memory management.
 *
 * @param format Printf-style format string (must not be NULL)
 * @param ... Arguments for the format string
 * @return Pointer to new formatted cstr on success, NULL on failure
 * @note Caller must call str_free() to release memory
 */
cstr* cstr_format(const char* format, ...) {
    if (!format) {
        return NULL;
    }

    va_list args;
    va_start(args, format);

    // Get required length
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, format, args_copy);
    va_end(args_copy);

    if (len < 0) {
        va_end(args);
        return NULL;
    }

    // Prevent unreasonably large format results
    if ((size_t)len >= CSTR_MAX_REASONABLE_SIZE) {
        va_end(args);
        return NULL;
    }

    size_t capacity = (size_t)len + 1;
    cstr* s         = cstr_init(capacity);
    if (!s) {
        va_end(args);
        return NULL;
    }

    char* data  = cstr_get_data(s);
    int written = vsnprintf(data, capacity, format, args);
    va_end(args);

    if (written < 0 || (size_t)written >= capacity) {
        cstr_free(s);
        return NULL;
    }

    cstr_set_length(s, (size_t)written);
    return s;
}

/**
 * @brief Appends a formatted string to the cstr.
 *
 * Appends text formatted according to printf-style format string and arguments
 * to the end of the existing string content.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param format Printf-style format string (must not be NULL)
 * @param ... Arguments for the format string
 * @return true on success, false on allocation failure or formatting error
 */
bool cstr_append_fmt(cstr* s, const char* format, ...) {
    if (!s || !format) {
        return false;
    }

    va_list args;
    va_start(args, format);

    // Get required length
    va_list args_copy;
    va_copy(args_copy, args);
    int append_len = vsnprintf(NULL, 0, format, args_copy);
    va_end(args_copy);

    if (append_len < 0) {
        va_end(args);
        return false;
    }

    if (append_len == 0) {
        va_end(args);
        return true;
    }

    size_t current_len = cstr_get_length(s);

    // Check for overflow
    if (WOULD_OVERFLOW_ADD(current_len, (size_t)append_len) ||
        WOULD_OVERFLOW_ADD(current_len + (size_t)append_len, 1)) {
        va_end(args);
        return false;
    }

    size_t new_len = current_len + (size_t)append_len;
    if (!cstr_ensure_capacity(s, new_len + 1)) {
        va_end(args);
        return false;
    }

    char* dest  = cstr_get_data(s);
    int written = vsnprintf(dest + current_len, (size_t)append_len + 1, format, args);
    va_end(args);

    if (written < 0 || written != append_len) {
        return false;
    }

    cstr_set_length(s, new_len);
    return true;
}

/**
 * @brief Appends a single character to the cstr.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param c Character to append
 * @return true on success, false on allocation failure or invalid input
 */
bool cstr_append_char(cstr* s, char c) {
    if (!s) {
        return false;
    }

    size_t current_len = cstr_get_length(s);

    // Check for overflow
    if (WOULD_OVERFLOW_ADD(current_len, 2)) {
        return false;
    }

    if (!cstr_ensure_capacity(s, current_len + 2)) {
        return false;
    }

    char* dest            = cstr_get_data(s);
    dest[current_len]     = c;
    dest[current_len + 1] = '\0';
    cstr_set_length(s, current_len + 1);

    return true;
}

/**
 * @brief Prepends a C string to the beginning of the cstr.
 *
 * Inserts the source string at the beginning of the destination string,
 * shifting existing content to the right.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param prepend_str C string to prepend (must not be NULL)
 * @return true on success, false on allocation failure or invalid input
 */
bool cstr_prepend(cstr* s, const char* prepend_str) {
    if (!s || !prepend_str) {
        return false;
    }

    size_t prepend_len = strlen(prepend_str);
    if (prepend_len == 0) {
        return true;
    }

    size_t current_len = cstr_get_length(s);

    // Check for overflow
    if (WOULD_OVERFLOW_ADD(current_len, prepend_len) || WOULD_OVERFLOW_ADD(current_len + prepend_len, 1)) {
        return false;
    }

    size_t new_len = current_len + prepend_len;
    if (!cstr_ensure_capacity(s, new_len + 1)) {
        return false;
    }

    char* dest = cstr_get_data(s);
    memmove(dest + prepend_len, dest, current_len + 1);
    memcpy(dest, prepend_str, prepend_len);
    cstr_set_length(s, new_len);

    return true;
}

/**
 * @brief Fast prepend assuming sufficient capacity.
 *
 * Prepends a C string without checking or expanding capacity. The caller
 * must ensure sufficient capacity exists.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param prepend_str C string to prepend (must not be NULL)
 * @return true on success, false on invalid input
 * @pre Sufficient capacity must exist for the prepend operation
 */
bool cstr_prepend_fast(cstr* s, const char* prepend_str) {
    if (!s || !prepend_str) {
        return false;
    }

    size_t prepend_len = strlen(prepend_str);
    if (prepend_len == 0) {
        return true;
    }

    size_t current_len = cstr_get_length(s);

    // Verify capacity assumption
    assert(current_len + prepend_len + 1 <= cstr_get_capacity(s));

    char* dest = cstr_get_data(s);
    memmove(dest + prepend_len, dest, current_len + 1);
    memcpy(dest, prepend_str, prepend_len);
    cstr_set_length(s, current_len + prepend_len);

    return true;
}

/**
 * @brief Inserts a C string at the specified position.
 *
 * Inserts the source string at the given index, shifting existing content
 * to make room. Index must be within the current string length.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param index Position to insert at (0-based, must be <= current length)
 * @param insert_str C string to insert (must not be NULL)
 * @return true on success, false on allocation failure or invalid input/index
 */
bool cstr_insert(cstr* s, size_t index, const char* insert_str) {
    size_t current_length = cstr_get_length(s);

    if (!s || !insert_str || index > current_length) {
        return false;
    }

    size_t insert_len = strlen(insert_str);
    if (insert_len == 0) {
        return true;
    }

    // Check for overflow
    if (WOULD_OVERFLOW_ADD(current_length, insert_len) ||
        WOULD_OVERFLOW_ADD(current_length + insert_len, 1)) {
        return false;
    }

    size_t new_length = current_length + insert_len;
    if (!cstr_ensure_capacity(s, new_length + 1)) {
        return false;
    }

    char* data = cstr_get_data(s);
    memmove(data + index + insert_len, data + index, current_length - index + 1);
    memcpy(data + index, insert_str, insert_len);
    cstr_set_length(s, new_length);
    return true;
}

/**
 * @brief Removes a range of characters from the cstr.
 *
 * Removes 'count' characters starting from 'index'. If 'index' + 'count'
 * extends beyond the string's length, characters are removed until the end.
 *
 * @param s Pointer to the cstr (must not be NULL)
 * @param index Starting index of the range to remove.
 * @param count Number of characters to remove.
 * @return True on success, false on invalid input or index.
 */
bool cstr_remove(cstr* s, size_t index, size_t count) {
    if (!s) {
        return false;
    }
    size_t current_length = cstr_get_length(s);

    if (index > current_length) {
        // Invalid index, unless count is 0 and index is exactly the length
        return index == current_length && count == 0;
    }

    // Adjust count if it exceeds the remaining length
    count = MIN(count, current_length - index);

    if (count == 0) {
        return true;  // No characters to remove
    }

    char* data = cstr_get_data(s);
    // Shift the remaining part of the string
    memmove(data + index, data + index + count,
            current_length - index - count + 1);  // +1 for the null terminator
    cstr_set_length(s, current_length - count);
    return true;
}

/**
 * @brief Clears the cstr, setting its length to 0.
 *
 * Sets the string's length to zero and null-terminates the first character.
 * The capacity remains unchanged.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_clear(cstr* s) {
    if (s) {
        cstr_set_length(s, 0);
        cstr_get_data(s)[0] = '\0';
    }
}

/**
 * @brief Removes all occurrences of a substring from the cstr.
 *
 * Removes all instances of the specified substring from the string.
 *
 * @param s Pointer to the cstr (must not be NULL).
 * @param substr Substring to remove (must not be NULL and not empty).
 * @return Number of occurrences removed. Returns 0 on invalid input or if substring is not found.
 */
size_t cstr_remove_all(cstr* s, const char* substr) {
    if (!s || !substr || !*substr) {
        return 0;
    }

    size_t substr_len = strlen(substr);
    if (substr_len == 0) {
        return 0;  // Cannot remove an empty substring
    }

    char* data      = cstr_get_data(s);
    char* write_ptr = data;
    char* read_ptr  = data;
    size_t count    = 0;
    const char* end = data + cstr_get_length(s);

    while (read_ptr < end) {
        // Check if the substring exists starting from read_ptr
        if ((size_t)(end - read_ptr) >= substr_len && strncmp(read_ptr, substr, substr_len) == 0) {
            read_ptr += substr_len;  // Skip the substring
            count++;
        } else {
            *write_ptr++ = *read_ptr++;  // Copy the character
        }
    }
    *write_ptr = '\0';  // Null-terminate the resulting string
    cstr_set_length(s, (size_t)(write_ptr - data));
    return count;
}

/**
 * @brief Returns the character at the specified index.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param index Index of the character (0-based).
 * @return The character at the index, or '\0' if s is NULL or index is out of bounds.
 */
char cstr_at(const cstr* s, size_t index) {
    if (!s || index >= cstr_get_length(s)) {
        return '\0';
    }
    return cstr_get_data_const(s)[index];
}

/**
 * @brief Returns a mutable pointer to the cstr's data.
 *
 * Provides direct access to the underlying character buffer. Use with caution,
 * as modifying the buffer without updating the string's length can lead to
 * inconsistencies.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @return Pointer to the null-terminated string, or NULL if s is NULL.
 */
char* cstr_data(cstr* s) {
    return s ? cstr_get_data(s) : NULL;
}

/**
 * @brief Returns a const pointer to the cstr's data.
 *
 * Provides read-only access to the underlying character buffer.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @return Const pointer to the null-terminated string, or NULL if s is NULL.
 */
const char* cstr_data_const(const cstr* s) {
    return s ? cstr_get_data_const(s) : NULL;
}

/**
 * @brief Converts the cstr to a string view.
 *
 * Creates a read-only view of the cstr's data and length.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @return A str_view representing the cstr's data and length. If s is NULL,
 * an empty str_view is returned.
 */
str_view cstr_as_view(const cstr* s) {
    str_view view = {NULL, 0};
    if (s) {
        view.data   = cstr_get_data_const(s);
        view.length = cstr_get_length(s);
    }
    return view;
}

/**
 * @brief Compares two cstrs lexicographically.
 *
 * Compares the strings based on their character sequences.
 *
 * @param s1 First cstr (can be NULL).
 * @param s2 Second cstr (can be NULL).
 * @return Negative if s1 < s2, zero if s1 == s2, positive if s1 > s2.
 *         NULL strings are considered less than non-NULL strings. Two NULL
 *         strings are considered equal.
 */
int cstr_compare(const cstr* s1, const cstr* s2) {
    if (!s1 && !s2) {
        return 0;
    }
    if (!s1) {
        return -1;
    }
    if (!s2) {
        return 1;
    }
    return strcmp(cstr_get_data_const(s1), cstr_get_data_const(s2));
}

/**
 * @brief Checks if two cstrs are equal.
 *
 * Checks if the strings have the same length and the same character sequences.
 *
 * @param s1 First cstr (can be NULL).
 * @param s2 Second cstr (can be NULL).
 * @return True if the cstrs are equal, false otherwise. Two NULL strings are
 *         considered equal.
 */
bool cstr_equals(const cstr* s1, const cstr* s2) {
    if (s1 == s2) {
        return true;  // Same pointer or both NULL
    }
    if (!s1 || !s2) {
        return false;  // One is NULL, other isn't
    }
    size_t len1 = cstr_get_length(s1);
    size_t len2 = cstr_get_length(s2);
    if (len1 != len2) {
        return false;  // Different lengths
    }
    return memcmp(cstr_get_data_const(s1), cstr_get_data_const(s2), len1) == 0;
}

/**
 * @brief Checks if the cstr starts with the given prefix.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param prefix Prefix to check (can be NULL).
 * @return True if the cstr starts with the prefix, false otherwise.
 *         Returns false if s is NULL or prefix is NULL. An empty prefix
 *         is considered a prefix of any string.
 */
bool cstr_starts_with(const cstr* s, const char* prefix) {
    if (!s || !prefix) {
        return false;
    }
    size_t prefix_len = strlen(prefix);
    size_t s_len      = cstr_get_length(s);
    return prefix_len == 0 ||
           (prefix_len <= s_len && memcmp(cstr_get_data_const(s), prefix, prefix_len) == 0);
}

/**
 * @brief Checks if the cstr ends with the given suffix.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param suffix Suffix to check (can be NULL).
 * @return True if the cstr ends with the suffix, false otherwise.
 *         Returns false if s is NULL or suffix is NULL. An empty suffix
 *         is considered a suffix of any string.
 */
bool cstr_ends_with(const cstr* s, const char* suffix) {
    if (!s || !suffix) {
        return false;
    }
    size_t suffix_len = strlen(suffix);
    size_t s_len      = cstr_get_length(s);
    return suffix_len == 0 || (suffix_len <= s_len &&
                               memcmp(cstr_get_data_const(s) + s_len - suffix_len, suffix, suffix_len) == 0);
}

/**
 * @brief Finds the first occurrence of a substring in the cstr.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param substr Substring to find (can be NULL).
 * @return Index of the first occurrence (0-based), or STR_NPOS (-1) if not found or invalid input.
 */
int cstr_find(const cstr* s, const char* substr) {
    if (!s || !substr) {
        return STR_NPOS;
    }
    const char* found = strstr(cstr_get_data_const(s), substr);
    return found ? (int)(found - cstr_get_data_const(s)) : STR_NPOS;
}

/**
 * @brief Finds the last occurrence of a substring in the cstr.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param substr Substring to find (can be NULL).
 * @return Index of the last occurrence (0-based), or STR_NPOS (-1) if not found or invalid input.
 */
int cstr_rfind(const cstr* s, const char* substr) {
    if (!s || !substr || !*substr) {
        return STR_NPOS;
    }

    size_t substr_len = strlen(substr);
    size_t s_len      = cstr_get_length(s);

    if (substr_len > s_len) {
        return STR_NPOS;
    }
    if (substr_len == 0) {
        // An empty substring is found at the end
        return (int)s_len;
    }

    const char* s_data = cstr_get_data_const(s);
    const char* found  = NULL;
    const char* p      = s_data;

    while ((p = strstr(p, substr))) {
        found = p;
        p += substr_len;
    }

    return found ? (int)(found - s_data) : STR_NPOS;
}

/**
 * @brief Converts the cstr to lowercase in place.
 *
 * Converts all uppercase characters in the string to their lowercase equivalents.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_lower(cstr* s) {
    if (!s)
        return;

    char* data    = cstr_get_data(s);
    size_t length = cstr_get_length(s);
    for (size_t i = 0; i < length; ++i) {
        data[i] = (char)tolower((unsigned char)data[i]);
    }
}

/**
 * @brief Converts the cstr to uppercase in place.
 *
 * Converts all lowercase characters in the string to their uppercase equivalents.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_upper(cstr* s) {
    if (!s)
        return;
    size_t length = cstr_get_length(s);
    char* data    = cstr_get_data(s);
    for (size_t i = 0; i < length; ++i) {
        data[i] = (char)toupper((unsigned char)data[i]);
    }
}

/**
 * @brief Converts the cstr to snake_case in place.
 *
 * Converts a string like "CamelCaseString" or "PascalCaseString" to
 * "camel_case_string". Inserts underscores before uppercase letters
 * (except the first) and converts all characters to lowercase.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @return true on success, false on allocation failure or invalid input.
 */
bool cstr_snakecase(cstr* s) {
    if (!s)
        return false;

    size_t original_length = cstr_get_length(s);
    if (original_length == 0) {
        return true;  // Empty string is already snake_case
    }

    size_t underscores     = 0;
    const char* data_const = cstr_get_data_const(s);

    // First pass to count needed underscores
    for (size_t i = 0; i < original_length; ++i) {
        if (i > 0 && isupper((unsigned char)data_const[i])) {
            underscores++;
        }
    }

    size_t new_length = original_length + underscores;

    // Check for overflow
    if (WOULD_OVERFLOW_ADD(new_length, 1)) {
        return false;
    }

    if (!cstr_ensure_capacity(s, new_length + 1)) {
        return false;  // Allocation failure
    }

    char* data       = cstr_get_data(s);
    size_t read_idx  = original_length;
    size_t write_idx = new_length;

    // Start from the end to insert underscores without moving data multiple times
    while (read_idx > 0) {
        read_idx--;
        char c = data[read_idx];

        if (read_idx > 0 && isupper((unsigned char)c)) {
            data[--write_idx] = (char)tolower((unsigned char)c);
            data[--write_idx] = '_';
        } else {
            data[--write_idx] = (char)tolower((unsigned char)c);
        }
    }

    data[new_length] = '\0';
    cstr_set_length(s, new_length);

    return true;
}

/**
 * @brief Converts the cstr to camelCase in place.
 *
 * Converts a string like "snake_case_string" or "PascalCaseString" to
 * "camelCaseString". Removes underscores/spaces and capitalizes the following letter.
 * The first character is converted to lowercase.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_camelcase(cstr* s) {
    if (!s) {
        return;
    }

    size_t length = cstr_get_length(s);
    if (length == 0) {
        return;
    }

    size_t read = 0, write = 0;
    bool capitalize_next = false;
    char* data           = cstr_get_data(s);

    // Skip leading underscores/spaces
    while (read < length && (data[read] == '_' || isspace((unsigned char)data[read]))) {
        read++;
    }

    if (read < length) {
        // First character should be lowercase
        data[write++] = (char)tolower((unsigned char)data[read++]);
    }

    while (read < length) {
        char c = data[read++];

        if (c == '_' || isspace((unsigned char)c)) {
            capitalize_next = true;
        } else if (capitalize_next) {
            data[write++]   = (char)toupper((unsigned char)c);
            capitalize_next = false;
        } else {
            data[write++] = (char)tolower((unsigned char)c);
        }
    }

    data[write] = '\0';
    cstr_set_length(s, write);
}

/**
 * @brief Converts the cstr to PascalCase in place.
 *
 * Converts a string like "snake_case_string" or "camelCaseString" to
 * "PascalCaseString". Removes underscores/spaces and capitalizes the following letter.
 * The first character is converted to uppercase.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_pascalcase(cstr* s) {
    if (!s) {
        return;
    }

    size_t length = cstr_get_length(s);
    if (length == 0) {
        return;
    }

    size_t read = 0, write = 0;
    char* data = cstr_get_data(s);

    // Skip leading underscores/spaces
    while (read < length && (data[read] == '_' || isspace((unsigned char)data[read]))) {
        read++;
    }

    // Start with true to capitalize the first letter (if it exists)
    bool new_word = true;

    while (read < length) {
        char c = data[read++];

        if (c == '_' || isspace((unsigned char)c)) {
            new_word = true;
        } else if (new_word) {
            data[write++] = (char)toupper((unsigned char)c);
            new_word      = false;
        } else {
            data[write++] = (char)tolower((unsigned char)c);
        }
    }

    data[write] = '\0';
    cstr_set_length(s, write);
}

/**
 * @brief Converts the cstr to Title Case in place.
 *
 * Capitalizes the first character of each word and converts the rest to lowercase.
 * Words are delimited by spaces.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_titlecase(cstr* s) {
    if (!s) {
        return;
    }
    size_t length = cstr_get_length(s);
    if (length == 0) {
        return;
    }
    char* data = cstr_get_data(s);

    bool capitalize = true;
    for (size_t i = 0; i < length; i++) {
        if (isspace((unsigned char)data[i])) {
            capitalize = true;
        } else if (capitalize) {
            data[i]    = (char)toupper((unsigned char)data[i]);
            capitalize = false;
        } else {
            data[i] = (char)tolower((unsigned char)data[i]);
        }
    }
}

/**
 * @brief Removes leading and trailing whitespace from the cstr in place.
 *
 * Removes whitespace characters (as defined by `isspace()`) from both the
 * beginning and the end of the string.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_trim(cstr* s) {
    if (!s) {
        return;
    }

    size_t length = cstr_get_length(s);
    if (length == 0) {
        return;
    }

    size_t start = 0, end = length - 1;
    char* data = cstr_get_data(s);

    // Find the first non-whitespace character
    while (start < length && isspace((unsigned char)data[start]))
        ++start;

    // Find the last non-whitespace character
    while (end > start && isspace((unsigned char)data[end]))
        --end;

    // Calculate the new length
    size_t new_length = (start > end) ? 0 : (end - start + 1);

    // Move the remaining part to the beginning
    if (new_length > 0 && start > 0) {
        memmove(data, data + start, new_length);
    }

    // Null-terminate the trimmed string
    data[new_length] = '\0';
    cstr_set_length(s, new_length);
}

/**
 * @brief Removes trailing whitespace from the cstr in place.
 *
 * Removes whitespace characters (as defined by `isspace()`) from the end
 * of the string.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_rtrim(cstr* s) {
    if (!s) {
        return;
    }

    size_t length = cstr_get_length(s);
    if (length == 0) {
        return;
    }

    size_t end = length - 1;
    char* data = cstr_get_data(s);

    // Find the last non-whitespace character
    while (end > 0 && isspace((unsigned char)data[end]))
        --end;

    // New length is up to and including the last non-whitespace character
    size_t new_length = isspace((unsigned char)data[end]) ? end : end + 1;

    // Null-terminate the trimmed string
    data[new_length] = '\0';
    cstr_set_length(s, new_length);
}

/**
 * @brief Removes leading whitespace from the cstr in place.
 *
 * Removes whitespace characters (as defined by `isspace()`) from the beginning
 * of the string.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_ltrim(cstr* s) {
    if (!s) {
        return;
    }

    size_t length = cstr_get_length(s);
    if (length == 0) {
        return;
    }

    size_t start = 0;
    char* data   = cstr_get_data(s);

    // Find the first non-whitespace character
    while (start < length && isspace((unsigned char)data[start]))
        ++start;

    // Calculate the new length
    size_t new_length = length - start;

    // Move the remaining part to the beginning
    if (new_length > 0 && start > 0) {
        memmove(data, data + start, new_length);
    }

    // Null-terminate the trimmed string
    data[new_length] = '\0';
    cstr_set_length(s, new_length);
}

/**
 * @brief Removes leading and trailing characters from the cstr in place based on a set of characters.
 *
 * Removes characters specified in the 'chars' string from both the beginning
 * and the end of the string.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param chars C string containing characters to remove (can be NULL or empty).
 */
void cstr_trim_chars(cstr* s, const char* chars) {
    if (!s || !chars) {
        return;
    }

    size_t length = cstr_get_length(s);
    if (length == 0 || *chars == '\0') {
        return;  // Nothing to trim
    }
    char* data = cstr_get_data(s);

    // Remove leading characters
    size_t start = 0;
    while (start < length && strchr(chars, data[start])) {
        start++;
    }

    // If all characters were removed
    if (start == length) {
        cstr_clear(s);
        return;
    }

    // Remove trailing characters
    size_t end = length - 1;
    while (end > start && strchr(chars, data[end])) {
        end--;  // move the pointer to the left
    }

    size_t len = (size_t)(end - start + 1);  // length of the remaining string
    if (start > 0) {
        memmove(data, data + start, len);  // move the remaining string to the beginning
    }
    data[len] = '\0';
    cstr_set_length(s, len);
}

/**
 * @brief Count the number of occurrences of a substring within the string.
 *
 * @param str Pointer to the cstr (can be NULL).
 * @param substr Substring to count (can be NULL).
 * @return Number of occurrences. Returns 0 on invalid input or if substring is not found.
 */
size_t cstr_count_substr(const cstr* str, const char* substr) {
    if (!str || !substr) {
        return 0;
    }
    size_t count   = 0;
    size_t sub_len = strlen(substr);
    if (sub_len == 0) {
        return 0;  // Cannot count empty substring occurrences
    }

    const char* p = cstr_get_data_const(str);
    while ((p = strstr(p, substr))) {
        count++;
        p += sub_len;
    }
    return count;
}

// Remove characters in str from start index, up to start + length.
void cstr_remove_substr(cstr* str, size_t start, size_t substr_length) {
    if (!str)
        return;

    size_t length = cstr_get_length(str);
    if (start >= length)
        return;
    if (substr_length == 0)
        return;  // Nothing to remove

    // Calculate safe removal length
    if (substr_length > length - start) {
        substr_length = length - start;
    }

    char* data           = cstr_get_data(str);
    size_t bytes_to_move = length - start - substr_length;

    // Move remaining characters (including null terminator)
    if (bytes_to_move > 0) {
        memmove(data + start, data + start + substr_length, bytes_to_move + 1);
    } else {
        // Special case when removing at end of string
        data[start] = '\0';
    }

    cstr_set_length(str, length - substr_length);
}

/**
 * @brief Removes all occurrences of a character from the cstr.
 *
 * Removes all instances of the specified character from the string.
 *
 * @param s Pointer to the cstr (must not be NULL).
 * @param c Character to remove.
 */
void cstr_remove_char(cstr* s, char c) {
    if (!s || cstr_get_length(s) == 0) {
        return;
    }

    char* data      = cstr_get_data(s);
    size_t len      = cstr_get_length(s);
    char* write_ptr = data;
    char* read_ptr  = data;

    for (size_t i = 0; i < len; i++, read_ptr++) {
        if (*read_ptr != c) {
            *write_ptr++ = *read_ptr;
        }
    }
    *write_ptr = '\0';  // Null-terminate the resulting string
    cstr_set_length(s, (size_t)(write_ptr - data));
}

/**
 * @brief Extracts a substring from the cstr.
 *
 * Creates a new cstr containing a portion of the original string starting
 * at 'start' index with the specified 'length'. If 'start' is out of bounds
 * or 'start' + 'length' exceeds the original string's length, the substring
 * will be truncated accordingly.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param start Starting index of the substring (0-based).
 * @param length Length of the substring.
 * @return Pointer to the new cstr containing the substring, or NULL on invalid input or allocation failure.
 */
cstr* cstr_substr(const cstr* s, size_t start, size_t length) {
    if (!s || start > cstr_get_length(s)) {
        return NULL;
    }

    size_t s_len = cstr_get_length(s);
    length       = MIN(length, s_len - start);

    if (length == 0) {
        return cstr_new("");  // Return an empty string if the substring length is 0
    }

    cstr* result = cstr_init(length + 1);
    if (!result) {
        return NULL;
    }
    char* data = cstr_get_data(result);
    memcpy(data, cstr_get_data_const(s) + start, length);
    data[length] = '\0';
    cstr_set_length(result, length);
    return result;
}

/**
 * @brief Replaces the first occurrence of a substring with another in the cstr.
 *
 * Creates a new cstr where the first occurrence of 'old_str' is replaced by 'new_str'.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param old_str Substring to replace (can be NULL). Cannot be empty.
 * @param new_str Replacement substring (can be NULL).
 * @return Pointer to the new cstr with the first occurrence replaced, or NULL on invalid input or allocation
 * failure.
 */
cstr* cstr_replace(const cstr* s, const char* old_str, const char* new_str) {
    if (!s || !old_str || !new_str) {
        return NULL;
    }

    size_t old_len     = strlen(old_str);
    const char* s_data = cstr_get_data_const(s);
    size_t s_len       = cstr_get_length(s);

    if (old_len == 0) {
        return cstr_new(s_data);  // Cannot replace empty string, return a copy
    }

    const char* found = strstr(s_data, old_str);
    if (!found) {
        return cstr_new(s_data);  // No occurrence found, return a copy
    }

    size_t new_len       = strlen(new_str);
    size_t pos           = (size_t)(found - s_data);
    size_t remaining_len = s_len - pos - old_len;

    // Calculate required capacity for the new string
    size_t required_capacity;
    if (WOULD_OVERFLOW_ADD(pos, new_len) || WOULD_OVERFLOW_ADD(pos + new_len, remaining_len) ||
        WOULD_OVERFLOW_ADD(pos + new_len + remaining_len, 1)) {
        return NULL;  // Potential overflow
    }
    required_capacity = pos + new_len + remaining_len + 1;

    cstr* result = cstr_init(required_capacity);
    if (!result) {
        return NULL;
    }

    char* dest = cstr_get_data(result);

    // Copy up to the found position
    if (pos > 0) {
        memcpy(dest, s_data, pos);
    }
    // Copy the new string
    memcpy(dest + pos, new_str, new_len);
    // Copy the remaining part of the original string
    if (remaining_len > 0) {
        memcpy(dest + pos + new_len, s_data + pos + old_len, remaining_len);
    }
    dest[required_capacity - 1] = '\0';  // Ensure null termination
    cstr_set_length(result, required_capacity - 1);

    return result;
}

/**
 * @brief Replaces all occurrences of a substring with another.
 *
 * Creates a new cstr where all non-overlapping occurrences of 'old_sub'
 * are replaced by 'new_sub'.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param old_sub Substring to replace (can be NULL). Cannot be empty.
 * @param new_sub Replacement substring (can be NULL).
 * @return Pointer to the new cstr with replacements, or NULL on invalid input or allocation failure.
 */
cstr* cstr_replace_all(const cstr* s, const char* old_sub, const char* new_sub) {
    if (!s || !old_sub || !new_sub) {
        return NULL;
    }

    size_t old_len     = strlen(old_sub);
    const char* s_data = cstr_get_data_const(s);

    if (old_len == 0) {
        return cstr_new(s_data);  // Cannot replace empty string, return a copy
    }

    size_t new_len = strlen(new_sub);
    size_t s_len   = cstr_get_length(s);

    // Count occurrences to estimate new size
    size_t count  = 0;
    const char* p = s_data;
    while ((p = strstr(p, old_sub))) {
        count++;
        p += old_len;
    }

    if (count == 0) {
        return cstr_new(s_data);  // No occurrences found, return a copy
    }

    // Calculate estimated result length
    size_t result_len_estimate;
    if (new_len > old_len) {
        if (would_overflow_mul(count, new_len - old_len) ||
            WOULD_OVERFLOW_ADD(s_len, count * (new_len - old_len))) {
            return NULL;  // Potential overflow
        }
        result_len_estimate = s_len + count * (new_len - old_len);
    } else {
        result_len_estimate = s_len - count * (old_len - new_len);
    }

    cstr* result = cstr_init(result_len_estimate + 1);
    if (!result) {
        return NULL;
    }

    char* dest = cstr_get_data(result);
    p          = s_data;
    size_t pos = 0;

    while (*p) {
        // Check if the current position matches the old substring
        if ((s_len - (p - s_data)) >= old_len && strncmp(p, old_sub, old_len) == 0) {
            // Append the new substring
            if (!cstr_ensure_capacity(result, pos + new_len + (s_len - (p - s_data) - old_len) + 1)) {
                cstr_free(result);
                return NULL;
            }
            dest = cstr_get_data(result);  // Re-get data pointer after potential realloc
            memcpy(dest + pos, new_sub, new_len);
            pos += new_len;
            p += old_len;  // Move past the old substring
        } else {
            // Append the current character
            if (!cstr_ensure_capacity(result, pos + (s_len - (p - s_data)) + 1)) {
                cstr_free(result);
                return NULL;
            }
            dest        = cstr_get_data(result);  // Re-get data pointer after potential realloc
            dest[pos++] = *p++;
        }
    }
    dest[pos] = '\0';
    cstr_set_length(result, pos);
    return result;
}

/**
 * @brief Splits the cstr into substrings based on a delimiter.
 *
 * Divides the string into an array of new cstr objects, using the delimiter
 * as the separator. Consecutive delimiters result in empty strings in the output array.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param delim Delimiter string (can be NULL). If empty, returns an array containing a copy of the original
 * string.
 * @param count_out Pointer to store the number of resulting substrings (must not be NULL).
 * @return Array of cstr pointers, or NULL on invalid input or allocation failure.
 *         The caller is responsible for freeing the array and each cstr within it.
 */
cstr** cstr_split(const cstr* s, const char* delim, size_t* count_out) {
    if (!s || !count_out) {
        if (count_out)
            *count_out = 0;
        return NULL;
    }

    const char* s_data = cstr_get_data_const(s);
    size_t s_len       = cstr_get_length(s);
    *count_out         = 0;

    // Handle empty delimiter case
    if (!delim || !*delim) {
        cstr** result = malloc(sizeof(cstr*));
        if (!result)
            return NULL;
        result[0] = cstr_new(s_data);
        if (!result[0]) {
            free(result);
            return NULL;
        }
        *count_out = 1;
        return result;
    }

    size_t delim_len = strlen(delim);
    if (delim_len == 0) {
        return cstr_split(s, NULL, count_out);
    }

    // Estimate capacity (avoid scanning entire string)
    size_t capacity = (s_len / (delim_len * 2)) + 4;  // Heuristic
    cstr** result   = malloc(capacity * sizeof(cstr*));
    if (!result)
        return NULL;

    const char* start = s_data;
    const char* end   = s_data + s_len;
    size_t count      = 0;

    while (1) {
        const char* found = strstr(start, delim);
        if (!found || found >= end)
            found = end;

        // Grow array if needed (but less frequently)
        if (count >= capacity) {
            capacity *= 2;
            cstr** new_result = realloc(result, capacity * sizeof(cstr*));
            if (!new_result)
                goto error;
            result = new_result;
        }

        size_t token_len = found - start;
        result[count]    = cstr_init(token_len + 1);
        if (!result[count])
            goto error;

        memcpy(cstr_get_data(result[count]), start, token_len);
        cstr_get_data(result[count])[token_len] = '\0';
        cstr_set_length(result[count], token_len);
        count++;

        if (found == end)
            break;
        start = found + delim_len;
    }

    // Trim to exact size if we over-allocated significantly
    if (capacity > count * 2 && count > 8) {
        cstr** trimmed = realloc(result, count * sizeof(cstr*));
        if (trimmed)
            result = trimmed;  // Accept if successful, keep old if not
    }

    *count_out = count;
    return result;

error:
    for (size_t i = 0; i < count; i++) {
        cstr_free(result[i]);
    }
    free(result);
    *count_out = 0;
    return NULL;
}

/**
 * @brief Joins multiple cstrs with a delimiter.
 *
 * Concatenates an array of cstrs into a single new cstr, separated by the
 * specified delimiter.
 *
 * @param strings Array of cstr pointers (can be NULL or empty). Each cstr pointer must not be NULL.
 * @param count Number of cstrs in the array.
 * @param delim Delimiter string (can be NULL for no delimiter).
 * @return Pointer to the new cstr with joined strings, or NULL on invalid input or allocation failure.
 *         Returns a new empty cstr if the input array is empty.
 */
cstr* cstr_join(const cstr** strings, size_t count, const char* delim) {
    if (!strings || count == 0) {
        return cstr_new("");  // Return an empty string for an empty input array
    }

    size_t delim_len = delim ? strlen(delim) : 0;
    size_t total_len = 0;

    // Calculate total length needed
    for (size_t i = 0; i < count; i++) {
        if (!strings[i]) {
            // Invalid input array
            return NULL;
        }
        size_t string_len = cstr_get_length(strings[i]);
        if (WOULD_OVERFLOW_ADD(total_len, string_len)) {
            return NULL;  // Potential overflow
        }
        total_len += string_len;

        if (i < count - 1 && delim_len > 0) {
            if (WOULD_OVERFLOW_ADD(total_len, delim_len)) {
                return NULL;  // Potential overflow
            }
            total_len += delim_len;
        }
    }

    // Check for overflow with null terminator
    if (WOULD_OVERFLOW_ADD(total_len, 1)) {
        return NULL;
    }

    cstr* result = cstr_init(total_len + 1);
    if (!result) {
        return NULL;
    }

    char* dest = cstr_get_data(result);
    size_t pos = 0;

    for (size_t i = 0; i < count; i++) {
        size_t len = cstr_get_length(strings[i]);
        if (len > 0) {
            memcpy(dest + pos, cstr_get_data_const(strings[i]), len);
            pos += len;
        }
        if (delim_len > 0 && i < count - 1) {
            memcpy(dest + pos, delim, delim_len);
            pos += delim_len;
        }
    }
    dest[pos] = '\0';
    cstr_set_length(result, pos);
    return result;
}

/**
 * @brief Creates a new cstr with the contents of the input cstr reversed.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @return Pointer to the new reversed cstr, or NULL on invalid input or allocation failure.
 */
cstr* cstr_reverse(const cstr* s) {
    if (!s) {
        return NULL;
    }
    size_t len = cstr_get_length(s);
    if (len == 0) {
        return cstr_new("");  // Return an empty string for an empty input
    }

    cstr* result = cstr_init(len + 1);
    if (!result) {
        return NULL;
    }

    char* dest      = cstr_get_data(result);
    const char* src = cstr_get_data_const(s);

    for (size_t i = 0; i < len; i++) {
        dest[i] = src[len - 1 - i];
    }

    dest[len] = '\0';
    cstr_set_length(result, len);
    return result;
}

/**
 * @brief Reverses the contents of the cstr in place.
 *
 * Reverses the string data within the existing cstr buffer.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_reverse_inplace(cstr* s) {
    if (!s) {
        return;
    }
    size_t len = cstr_get_length(s);
    if (len < 2) {
        return;  // Nothing to reverse
    }
    char* data = cstr_get_data(s);
    for (size_t i = 0; i < len / 2; i++) {
        char temp         = data[i];
        data[i]           = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}
