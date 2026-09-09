/**
 * @file aligned_alloc.h
 * @brief High-performance C11+ cross-platform aligned allocation.
 */

#ifndef ALIGNED_ALLOC_H
#define ALIGNED_ALLOC_H

#include <assert.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#include <malloc.h>
#endif

/**
 * Allocates @p size bytes aligned to @p alignment.
 *
 * Requires:
 * - C11 or above.
 * - @p alignment must be a power of two >= sizeof(void*).
 */
static inline void* aligned_alloc_xp(size_t alignment, size_t size) {
    /* Validated only in debug builds; 0 cost in Release */
    assert((alignment & (alignment - 1)) == 0 && "alignment must be a power of 2");
    assert(alignment >= sizeof(void*) && "alignment must be >= sizeof(void*)");

    /* C11 aligned_alloc requires size to be an exact multiple of alignment.
     * When alignment is constant (e.g. 64), the compiler folds this completely. */
    size = (size + alignment - 1) & ~(alignment - 1);

#if defined(_WIN32) || defined(__CYGWIN__)
    return _aligned_malloc(size, alignment);
#else
    return aligned_alloc(alignment, size);
#endif
}

static inline void aligned_free_xp(void* ptr) {
#if defined(_WIN32) || defined(__CYGWIN__)
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

#define ALIGNED_ALLOC(alignment, size) aligned_alloc_xp(alignment, size)
#define ALIGNED_FREE(ptr)              aligned_free_xp(ptr)

#ifdef __cplusplus
}
#endif

#endif  // ALIGNED_ALLOC_H
