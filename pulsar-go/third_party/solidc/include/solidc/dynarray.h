/**
 * @file dynarray.h
 * @brief High-performance dynamic array implementation with automatic resizing.
 */

#ifndef DYNARRAY_H
#define DYNARRAY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>  // for bool
#include <stddef.h>   // for size_t
#include <stdint.h>   // for SIZE_MAX, uint8_t, uint16_t, uint32_t, uint64_t
#include <string.h>   // for memcpy, memmove

/* -------------------------------------------------------------------------- */
/* Compiler Portability & Branch Hints                                       */
/* -------------------------------------------------------------------------- */

#if defined(__GNUC__) || defined(__clang__)
    #define DYNARRAY_LIKELY(x)   __builtin_expect(!!(x), 1)
    #define DYNARRAY_UNLIKELY(x) __builtin_expect(!!(x), 0)
    #define DYNARRAY_INLINE      inline __attribute__((always_inline))
    #define DYNARRAY_COLD        __attribute__((cold, noinline))
    #define DYNARRAY_RESTRICT    __restrict__
#else
    #define DYNARRAY_LIKELY(x)   (x)
    #define DYNARRAY_UNLIKELY(x) (x)
    #define DYNARRAY_INLINE      inline
    #define DYNARRAY_COLD
    #define DYNARRAY_RESTRICT
#endif

/** Initial capacity when array is first created. */
#define DYNARRAY_INITIAL_CAPACITY 8

/** Threshold for shrinking: shrink when size < capacity/4. */
#define DYNARRAY_SHRINK_THRESHOLD 4

/**
 * Dynamic array structure.
 * Grows automatically on push, shrinks on explicit request or when usage drops below threshold.
 * Thread-unsafe: caller must synchronize concurrent access.
 *
 * Lifetime contract:
 *  - dynarray_init() must be called before any other operation (a
 *    zero-initialized struct is safely rejected by every entry point).
 *  - Pointers returned by dynarray_get()/dynarray_get_const() are
 *    invalidated by push/insert/remove/reserve (any reallocation) and by
 *    remove/swap_remove for elements after the removed index.
 *  - Element copies are byte-wise; elements requiring deep cleanup need a
 *    caller-side pass before dynarray_clear()/dynarray_free().
 */
typedef struct {
    /** Pointer to the data buffer. Marked restrict for compiler vectorization. */
    void* DYNARRAY_RESTRICT data;
    /** Number of elements currently in the array. */
    size_t size;
    /** Current capacity (number of elements that can be stored without reallocation). */
    size_t capacity;
    /** Size of each element in bytes. Must be nonzero (enforced by init). */
    size_t element_size;
} dynarray_t;

/* -------------------------------------------------------------------------- */
/* Internal Helper Functions                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Fast-path element copy.
 *
 * Plain memcpy: for constant sizes every mainstream compiler emits a
 * single load/store pair, matching the old hand-rolled switch, while
 * remaining well-defined for MISALIGNED sources (e.g. fields of packed
 * structs), which the switch's direct casts were not.
 */
static DYNARRAY_INLINE void dynarray_fast_copy(void* DYNARRAY_RESTRICT dest, const void* DYNARRAY_RESTRICT src,
                                               size_t size) {
    memcpy(dest, src, size);
}

/** Out-of-line cold reallocation target to keep hot inline paths lightweight. */
DYNARRAY_COLD bool dynarray_grow_slowpath(dynarray_t* arr, size_t min_capacity);

/* -------------------------------------------------------------------------- */
/* Public API                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Initializes a new dynamic array.
 * @param arr Pointer to the array structure to initialize.
 * @param element_size Size of each element in bytes.
 * @param initial_capacity Initial capacity (0 uses default).
 * @return true on success, false on allocation failure.
 */
bool dynarray_init(dynarray_t* arr, size_t element_size, size_t initial_capacity);

/**
 * Frees all resources associated with the dynamic array.
 * @param arr Pointer to the array to free. Safe to pass NULL.
 */
void dynarray_free(dynarray_t* arr);

/**
 * Appends an element to the end of the array.
 * @param arr Pointer to the array.
 * @param element Pointer to the element to append.
 * @return true on success, false on allocation failure.
 */
static DYNARRAY_INLINE bool dynarray_push(dynarray_t* arr, const void* element) {
    if (DYNARRAY_UNLIKELY(arr == NULL || element == NULL)) {
        return false;
    }

    if (DYNARRAY_UNLIKELY(arr->size >= arr->capacity)) {
        // Fast 1.5x capacity growth via bitwise shifts: cap + (cap >> 1)
        size_t new_cap = arr->capacity + (arr->capacity >> 1);
        if (DYNARRAY_UNLIKELY(new_cap <= arr->capacity)) {
            new_cap = arr->capacity + 1;
        }
        if (DYNARRAY_UNLIKELY(!dynarray_grow_slowpath(arr, new_cap))) {
            return false;
        }
    }

    unsigned char* dest = (unsigned char*)arr->data + (arr->size * arr->element_size);
    dynarray_fast_copy(dest, element, arr->element_size);
    arr->size++;

    return true;
}

/**
 * Appends count contiguous elements to the end of the array.
 */
bool dynarray_push_n(dynarray_t* arr, const void* elements, size_t count);

/**
 * Removes and returns the last element from the array.
 */
static DYNARRAY_INLINE bool dynarray_pop(dynarray_t* arr, void* out_element) {
    if (DYNARRAY_UNLIKELY(arr == NULL || arr->size == 0)) {
        return false;
    }

    arr->size--;

    if (out_element != NULL) {
        const unsigned char* src = (const unsigned char*)arr->data + (arr->size * arr->element_size);
        dynarray_fast_copy(out_element, src, arr->element_size);
    }

    // Shrink check on cold path if usage drops below threshold
    if (DYNARRAY_UNLIKELY(arr->capacity > DYNARRAY_INITIAL_CAPACITY &&
                          arr->size < arr->capacity / DYNARRAY_SHRINK_THRESHOLD)) {
        size_t new_capacity = arr->capacity >> 1;  // Faster capacity / 2
        if (new_capacity < DYNARRAY_INITIAL_CAPACITY) {
            new_capacity = DYNARRAY_INITIAL_CAPACITY;
        }
        dynarray_grow_slowpath(arr, new_capacity);
    }

    return true;
}

/**
 * Gets a mutable pointer to the element at the specified index.
 */
static DYNARRAY_INLINE void* dynarray_get(const dynarray_t* arr, size_t index) {
    if (DYNARRAY_UNLIKELY(arr == NULL || index >= arr->size)) {
        return NULL;
    }
    return (unsigned char*)arr->data + (index * arr->element_size);
}

/**
 * Gets a read-only pointer to the element at the specified index.
 */
static DYNARRAY_INLINE const void* dynarray_get_const(const dynarray_t* arr, size_t index) {
    if (DYNARRAY_UNLIKELY(arr == NULL || index >= arr->size)) {
        return NULL;
    }
    return (const unsigned char*)arr->data + (index * arr->element_size);
}

/**
 * Sets the element at the specified index.
 */
static DYNARRAY_INLINE bool dynarray_set(dynarray_t* arr, size_t index, const void* element) {
    if (DYNARRAY_UNLIKELY(arr == NULL || element == NULL || index >= arr->size)) {
        return false;
    }

    unsigned char* dest = (unsigned char*)arr->data + (index * arr->element_size);
    dynarray_fast_copy(dest, element, arr->element_size);

    return true;
}

bool dynarray_reserve(dynarray_t* arr, size_t new_capacity);
bool dynarray_shrink_to_fit(dynarray_t* arr);
void dynarray_clear(dynarray_t* arr);

/**
 * Inserts an element at @p index, shifting elements [index, size) right.
 * @param index Position for the new element; must be <= size (size == append).
 * @return true on success; false on NULL args, index > size, or allocation
 *         failure. On failure the array is unchanged.
 */
static DYNARRAY_INLINE bool dynarray_insert(dynarray_t* arr, size_t index, const void* element) {
    if (DYNARRAY_UNLIKELY(arr == NULL || element == NULL || index > arr->size)) {
        return false;
    }

    if (DYNARRAY_UNLIKELY(arr->size >= arr->capacity)) {
        size_t new_cap = arr->capacity + (arr->capacity >> 1);
        if (DYNARRAY_UNLIKELY(new_cap <= arr->capacity)) {
            new_cap = arr->capacity + 1;
        }
        if (DYNARRAY_UNLIKELY(!dynarray_grow_slowpath(arr, new_cap))) {
            return false;
        }
    }

    unsigned char* base = (unsigned char*)arr->data;
    memmove(base + ((index + 1) * arr->element_size), base + (index * arr->element_size),
            (arr->size - index) * arr->element_size);
    dynarray_fast_copy(base + (index * arr->element_size), element, arr->element_size);
    arr->size++;

    return true;
}

/**
 * Removes the element at @p index, shifting elements after it left.
 * Preserves order at O(n) cost.
 * @return true on success; false on NULL args or index >= size.
 */
static DYNARRAY_INLINE bool dynarray_remove(dynarray_t* arr, size_t index) {
    if (DYNARRAY_UNLIKELY(arr == NULL || index >= arr->size)) {
        return false;
    }

    unsigned char* base = (unsigned char*)arr->data;
    memmove(base + (index * arr->element_size), base + ((index + 1) * arr->element_size),
            (arr->size - index - 1) * arr->element_size);
    arr->size--;

    /* Same shrink policy as pop(): halve when a quarter full. */
    if (DYNARRAY_UNLIKELY(arr->capacity > DYNARRAY_INITIAL_CAPACITY &&
                          arr->size < arr->capacity / DYNARRAY_SHRINK_THRESHOLD)) {
        size_t new_capacity = arr->capacity >> 1;
        if (new_capacity < DYNARRAY_INITIAL_CAPACITY) {
            new_capacity = DYNARRAY_INITIAL_CAPACITY;
        }
        dynarray_grow_slowpath(arr, new_capacity); /* best effort */
    }

    return true;
}

/**
 * Removes the element at @p index by moving the LAST element into its
 * place. O(1) but does NOT preserve order.
 * @param out_element Optional; receives the removed element.
 * @return true on success; false on NULL args or index >= size.
 */
static DYNARRAY_INLINE bool dynarray_swap_remove(dynarray_t* arr, size_t index, void* out_element) {
    if (DYNARRAY_UNLIKELY(arr == NULL || index >= arr->size)) {
        return false;
    }

    unsigned char* base = (unsigned char*)arr->data;
    unsigned char* slot = base + (index * arr->element_size);

    if (out_element != NULL) {
        dynarray_fast_copy(out_element, slot, arr->element_size);
    }

    arr->size--;
    if (index != arr->size) {
        /* Overwrite with the last element (memcpy: regions never overlap,
         * distinct indices in an array). */
        memcpy(slot, base + (arr->size * arr->element_size), arr->element_size);
    }

    return true;
}

/**
 * Returns a mutable pointer to the first element, or NULL if empty/NULL arr.
 * The pointer is invalidated by any resize or reorder operation.
 */
static DYNARRAY_INLINE void* dynarray_first(dynarray_t* arr) { return dynarray_get(arr, 0); }

/**
 * Returns a mutable pointer to the last element, or NULL if empty/NULL arr.
 * The pointer is invalidated by any resize or reorder operation.
 */
static DYNARRAY_INLINE void* dynarray_last(dynarray_t* arr) {
    if (DYNARRAY_UNLIKELY(arr == NULL || arr->size == 0)) {
        return NULL;
    }
    return (unsigned char*)arr->data + ((arr->size - 1) * arr->element_size);
}

/**
 * Detaches the internal buffer, transferring ownership to the caller.
 * The array is reset to the zero-initialized state afterwards.
 * @param out_size Optional; receives the element count.
 * @param out_capacity Optional; receives the capacity (in elements).
 * @return Pointer to a malloc'd contiguous buffer holding exactly
 *         size elements (NOT NUL-terminated), or NULL on NULL arr /
 *         empty array / allocation failure of the exact-size copy.
 * @note The caller owns the returned buffer and must free() it.
 */
void* dynarray_detach(dynarray_t* arr, size_t* out_size, size_t* out_capacity);

static inline size_t dynarray_size(const dynarray_t* arr) { return arr ? arr->size : 0; }

static inline size_t dynarray_capacity(const dynarray_t* arr) { return arr ? arr->capacity : 0; }

static inline bool dynarray_is_empty(const dynarray_t* arr) { return arr == NULL || arr->size == 0; }

/* -------------------------------------------------------------------------- */
/* Zero-Overhead Type-Safe Accessor Macros                                   */
/* -------------------------------------------------------------------------- */

/**
 * Direct typed array index macro. Completely bypasses function call overhead
 * and pointer arithmetic calculations for maximum speed in inner loops.
 * @param type Concrete C type (e.g., int, my_struct_t).
 * @param arr Pointer to the array.
 * @param index Element index.
 */
#define DYNARRAY_GET_AS(type, arr, index) (((type*)(arr)->data)[index])

#ifdef __cplusplus
}
#endif

#endif  // DYNARRAY_H
