#include "dynarray.h"

#include <stdio.h>   // for fprintf, stderr
#include <stdlib.h>  // for malloc, realloc, free

DYNARRAY_COLD bool dynarray_grow_slowpath(dynarray_t* arr, size_t min_capacity) {
    if (arr == NULL) {
        return false;
    }

    /*
     * Guard against zero-initialised structs used without dynarray_init():
     * element_size == 0 would divide by zero below and produce a SIGFPE.
     * A zero-element-size array is meaningless, so refuse to grow.
     */
    if (arr->element_size == 0) {
        return false;
    }

    // Check for overflow before allocating
    if (min_capacity > SIZE_MAX / arr->element_size) {
        return false;
    }

    void* new_data = realloc(arr->data, min_capacity * arr->element_size);
    if (new_data == NULL && min_capacity > 0) {
        return false;
    }

    arr->data = new_data;
    arr->capacity = min_capacity;
    return true;
}

bool dynarray_init(dynarray_t* arr, size_t element_size, size_t initial_capacity) {
    if (arr == NULL || element_size == 0) {
        return false;
    }

    if (initial_capacity == 0) {
        initial_capacity = DYNARRAY_INITIAL_CAPACITY;
    }

    if (initial_capacity > SIZE_MAX / element_size) {
        return false;
    }

    void* data = malloc(element_size * initial_capacity);
    if (data == NULL) {
        return false;
    }

    *arr = (dynarray_t){
        .data = data,
        .size = 0,
        .capacity = initial_capacity,
        .element_size = element_size,
    };

    return true;
}

void dynarray_free(dynarray_t* arr) {
    if (arr == NULL) {
        return;
    }

    free(arr->data);
    *arr = (dynarray_t){0};
}

bool dynarray_push_n(dynarray_t* arr, const void* elements, size_t count) {
    if (DYNARRAY_UNLIKELY(arr == NULL)) {
        return false;
    }
    if (DYNARRAY_UNLIKELY(count == 0)) {
        /* Zero-count append is a no-op success even with NULL elements. */
        return true;
    }
    if (DYNARRAY_UNLIKELY(elements == NULL)) {
        return false;
    }

    if (DYNARRAY_UNLIKELY(count > SIZE_MAX - arr->size)) {
        return false;
    }

    size_t required = arr->size + count;

    if (DYNARRAY_UNLIKELY(required > arr->capacity)) {
        // Compute 1.5x exponential growth analytically without loops
        size_t new_capacity = arr->capacity + (arr->capacity >> 1);
        if (new_capacity < required) {
            new_capacity = required;
        }

        if (!dynarray_grow_slowpath(arr, new_capacity)) {
            return false;
        }
    }

    unsigned char* dest = (unsigned char*)arr->data + (arr->size * arr->element_size);
    memcpy(dest, elements, count * arr->element_size);
    arr->size = required;

    return true;
}

bool dynarray_reserve(dynarray_t* arr, size_t new_capacity) {
    if (arr == NULL || arr->element_size == 0) {
        return false;
    }

    // Do not shrink below current size
    if (new_capacity < arr->size) {
        new_capacity = arr->size;
    }

    // No-op if already at desired capacity
    if (new_capacity == arr->capacity) {
        return true;
    }

    // Check for multiplication overflow
    if (new_capacity > SIZE_MAX / arr->element_size) {
        return false;
    }

    void* new_data = realloc(arr->data, new_capacity * arr->element_size);
    if (new_data == NULL && new_capacity > 0) {
        return false;
    }

    arr->data = new_data;
    arr->capacity = new_capacity;

    return true;
}

bool dynarray_shrink_to_fit(dynarray_t* arr) {
    if (arr == NULL) {
        return false;
    }

    size_t target_capacity = arr->size > DYNARRAY_INITIAL_CAPACITY ? arr->size : DYNARRAY_INITIAL_CAPACITY;
    return dynarray_reserve(arr, target_capacity);
}

void dynarray_clear(dynarray_t* arr) {
    if (arr != NULL) {
        arr->size = 0;
    }
}

void* dynarray_detach(dynarray_t* arr, size_t* out_size, size_t* out_capacity) {
    if (out_size) *out_size = 0;
    if (out_capacity) *out_capacity = 0;
    if (arr == NULL || arr->data == NULL || arr->size == 0) {
        return NULL;
    }

    void* detached = NULL;
    size_t target_bytes = arr->size * arr->element_size;

    if (arr->capacity == arr->size) {
        /* Buffer is already exact-size: hand it over directly. */
        detached = arr->data;
        arr->data = NULL;
    } else {
        /* Shrink to exact size; on realloc failure fall back to a copy so
         * the caller still receives a valid, owned buffer.
         * NOTE: a successful realloc consumes the original block -- only
         * free arr->data when realloc FAILED (the copy branch). */
        void* shrunk = realloc(arr->data, target_bytes);
        if (shrunk != NULL) {
            detached = shrunk;
            arr->data = NULL;
        } else {
            detached = malloc(target_bytes);
            if (detached == NULL) {
                /* Nothing lost: the array keeps its buffer. */
                return NULL;
            }
            memcpy(detached, arr->data, target_bytes);
            free(arr->data);
            arr->data = NULL;
        }
    }

    if (out_size) *out_size = arr->size;
    if (out_capacity) *out_capacity = arr->size;

    /* Reset to the zero-initialized state: detach consumes the array. */
    *arr = (dynarray_t){0};
    return detached;
}
