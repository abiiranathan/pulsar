/*
 * STB-style type-safe dynamic array implementation
 *
 * This single-header library provides type-safe dynamic arrays using C23 features.
 * Simply include this file and use the macros to create typed dynamic arrays.
 *
 * Usage:
 *   #define DA_IMPLEMENTATION  // Include this in ONE source file
 *   #include "dynarray.h"
 *
 *   // Create array types
 *   DA_DECLARE(int, int_array);
 *   DA_DECLARE(char*, string_array);
 *
 *   // Use the arrays
 *   int_array arr = {0};
 *   da_push(&arr, 42);
 *   da_push(&arr, 24);
 *
 *   for (size_t i = 0; i < da_len(arr); i++) {
 *       printf("%d\n", arr.data[i]);
 *   }
 *
 *   da_free(&arr);
 */

#ifndef DYNARRAY_H
#define DYNARRAY_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef DA_MALLOC
#define DA_MALLOC malloc
#endif

#ifndef DA_REALLOC
#define DA_REALLOC realloc
#endif

#ifndef DA_FREE
#define DA_FREE free
#endif

#ifndef DA_ASSERT
#define DA_ASSERT assert
#endif

// Default growth factor (1.5x growth)
#ifndef DA_GROWTH_FACTOR
#define DA_GROWTH_FACTOR 1.5
#endif

// Minimum initial capacity
#ifndef DA_INITIAL_CAPACITY
#define DA_INITIAL_CAPACITY 8
#endif

/*
 * DA_DECLARE(type, name) - Declares a new dynamic array type
 *
 * Creates a new struct type called 'name' that can hold elements of 'type'.
 * The struct contains:
 *   - data: pointer to the array data
 *   - len: current number of elements
 *   - cap: current capacity
 */
#define DA_DECLARE(type, name)                                                                     \
    typedef struct {                                                                               \
        type* data;                                                                                \
        size_t len;                                                                                \
        size_t cap;                                                                                \
    } name

// Get the length of a dynamic array
#define da_len(arr) ((arr).len)

// Get the capacity of a dynamic array
#define da_cap(arr) ((arr).cap)

// Check if array is empty
#define da_empty(arr) ((arr).len == 0)

// Get pointer to the last element (undefined behavior if empty)
#define da_last(arr) (&(arr).data[(arr).len - 1])

// Access element at index (bounds checking with assert)
#define da_at(arr, idx) (DA_ASSERT((idx) < (arr).len), (arr).data[idx])

// Internal: Calculate new capacity
#define DA_NEW_CAP(old_cap)                                                                        \
    ((old_cap) == 0 ? DA_INITIAL_CAPACITY : (size_t)((old_cap) * DA_GROWTH_FACTOR))

/*
 * da_reserve(arr_ptr, new_cap) - Ensure array has at least new_cap capacity
 *
 * Returns true on success, false on allocation failure.
 */
#define da_reserve(arr_ptr, new_cap)                                                               \
    ((arr_ptr)->cap >= (new_cap) ? true                                                            \
                                 : da_grow_((void**)&(arr_ptr)->data, &(arr_ptr)->cap, (new_cap),  \
                                            sizeof(*(arr_ptr)->data)))

/*
 * da_resize(arr_ptr, new_len) - Resize array to new_len elements
 *
 * If growing, new elements are uninitialized.
 * Returns true on success, false on allocation failure.
 */
#define da_resize(arr_ptr, new_len)                                                                \
    (da_reserve((arr_ptr), (new_len)) ? ((arr_ptr)->len = (new_len), true) : false)

/*
 * da_push(arr_ptr, elem) - Append element to end of array
 *
 * Returns true on success, false on allocation failure.
 */
#define da_push(arr_ptr, elem)                                                                     \
    (da_reserve((arr_ptr), (arr_ptr)->len + 1)                                                     \
         ? ((arr_ptr)->data[(arr_ptr)->len++] = (elem), true)                                      \
         : false)

/*
 * da_pop(arr_ptr) - Remove and return last element
 *
 * Undefined behavior if array is empty.
 */
#define da_pop(arr_ptr) (DA_ASSERT((arr_ptr)->len > 0), (arr_ptr)->data[--(arr_ptr)->len])

/*
 * da_clear(arr_ptr) - Remove all elements (doesn't free memory)
 */
#define da_clear(arr_ptr) ((arr_ptr)->len = 0)

/*
 * da_free(arr_ptr) - Free array memory and reset to empty state
 */
#define da_free(arr_ptr)                                                                           \
    do {                                                                                           \
        if ((arr_ptr)->data) {                                                                     \
            DA_FREE((arr_ptr)->data);                                                              \
            (arr_ptr)->data = NULL;                                                                \
        }                                                                                          \
        (arr_ptr)->len = 0;                                                                        \
        (arr_ptr)->cap = 0;                                                                        \
    } while (0)

/*
 * da_insert(arr_ptr, idx, elem) - Insert element at index
 *
 * All elements at and after idx are shifted right.
 * Returns true on success, false on allocation failure.
 */
#define da_insert(arr_ptr, idx, elem)                                                              \
    (DA_ASSERT((idx) <= (arr_ptr)->len),                                                           \
     da_reserve((arr_ptr), (arr_ptr)->len + 1)                                                     \
         ? (memmove(&(arr_ptr)->data[(idx) + 1], &(arr_ptr)->data[idx],                            \
                    ((arr_ptr)->len - (idx)) * sizeof(*(arr_ptr)->data)),                          \
            (arr_ptr)->data[idx] = (elem), (arr_ptr)->len++, true)                                 \
         : false)

/*
 * da_remove(arr_ptr, idx) - Remove element at index
 *
 * All elements after idx are shifted left.
 * Returns the removed element.
 */
#define da_remove(arr_ptr, idx)                                                                    \
    (DA_ASSERT((idx) < (arr_ptr)->len), (arr_ptr)->len--,                                          \
     memmove(&(arr_ptr)->data[idx], &(arr_ptr)->data[(idx) + 1],                                   \
             ((arr_ptr)->len - (idx)) * sizeof(*(arr_ptr)->data)),                                 \
     (arr_ptr)->data[(arr_ptr)->len])

/*
 * da_shrink_to_fit(arr_ptr) - Reduce capacity to match length
 *
 * Returns true on success, false on allocation failure (array unchanged).
 */
#define da_shrink_to_fit(arr_ptr)                                                                  \
    ((arr_ptr)->len == (arr_ptr)->cap ? true                                                       \
     : (arr_ptr)->len == 0            ? (da_free(arr_ptr), true)                                   \
                           : da_shrink_((void**)&(arr_ptr)->data, &(arr_ptr)->cap, (arr_ptr)->len, \
                                        sizeof(*(arr_ptr)->data)))

// Function declarations
static inline bool da_grow_(void** data, size_t* cap, size_t min_cap, size_t elem_size);
static inline bool da_shrink_(void** data, size_t* cap, size_t new_cap, size_t elem_size);

#ifdef DA_IMPLEMENTATION

#ifdef __cplusplus
extern "C" {
#endif

bool da_grow_(void** data, size_t* cap, size_t min_cap, size_t elem_size) {
    size_t new_cap = *cap;

    while (new_cap < min_cap) {
        new_cap = DA_NEW_CAP(new_cap);
    }

    void* new_data = DA_REALLOC(*data, new_cap * elem_size);
    if (!new_data) {
        return false;
    }

    *data = new_data;
    *cap  = new_cap;
    return true;
}

bool da_shrink_(void** data, size_t* cap, size_t new_cap, size_t elem_size) {
    void* new_data = DA_REALLOC(*data, new_cap * elem_size);
    if (!new_data) {
        return false;
    }

    *data = new_data;
    *cap  = new_cap;
    return true;
}

#ifdef __cplusplus
}
#endif

#endif  // DA_IMPLEMENTATION

#endif  // DYNARRAY_H

#if 0
#include <stdio.h>

DA_DECLARE(int, IntArray);
DA_DECLARE(const char*, StringArray);

int main() {
    // Integer array example
    IntArray numbers = {0};

    da_push(&numbers, 10);
    da_push(&numbers, 20);
    da_push(&numbers, 30);

    printf("Numbers: ");
    for (size_t i = 0; i < da_len(numbers); i++) {
        printf("%d ", numbers.data[i]);
    }
    printf("\n");

    // Insert at beginning
    da_insert(&numbers, 0, 5);
    printf("After inserting 5 at beginning: ");
    for (size_t i = 0; i < da_len(numbers); i++) {
        printf("%d ", numbers.data[i]);
    }
    printf("\n");

    // Remove middle element
    da_remove(&numbers, 2);
    printf("After removing element at index 2: ");
    for (size_t i = 0; i < da_len(numbers); i++) {
        printf("%d ", numbers.data[i]);
    }
    printf("\n");

    da_free(&numbers);

    // String array example
    StringArray strings = {0};

    da_push(&strings, "Hello");
    da_push(&strings, "World");
    da_push(&strings, "!");

    printf("Strings: ");
    for (size_t i = 0; i < da_len(strings); i++) {
        printf("%s ", strings.data[i]);
    }
    printf("\n");

    da_free(&strings);

    return 0;
}

#endif
