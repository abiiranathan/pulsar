#ifndef ARENA_H
#define ARENA_H

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

// Faster alignment for 64-bit systems
#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

#ifdef __cplusplus
extern "C" {
#endif

// Single threaded Linear (bump) allocator.
typedef struct {
    size_t allocated;  // Allocated memory
    size_t capacity;   // Capacity of the arena
    uint8_t memory[];  // Arena memory as a flexible array member
} Arena;

// Create a new arena with given capacity. Capacity must be > 0.
INLINE Arena* arena_create(size_t capacity) {
    if (capacity == 0) {
        return NULL;
    }

    // Allocate arena structure with enough space for memory.
    Arena* arena = calloc(1, sizeof(Arena) + capacity);
    if (!arena) {
        perror("calloc: arena_create failed");
        return NULL;
    }
    arena->allocated = 0;
    arena->capacity  = capacity;
    return arena;
}

// Destroty arena and free memory.
INLINE void arena_destroy(Arena* arena) {
    if (!arena)
        return;
    free(arena);
}

// Allocate pointer of given size in arena.
// Returns NULL if arena is out of memory.
INLINE void* arena_alloc(Arena* arena, size_t size) {
    size = ALIGN_UP(size, 16);  // Use 16-byte alignment for SSE/AVX

    if (unlikely(arena->allocated + size > arena->capacity)) {
        return NULL;
    }
    void* ptr = &arena->memory[arena->allocated];
    arena->allocated += size;

    // Prefetch next allocation slot
    __builtin_prefetch(&arena->memory[arena->allocated], 1, 3);

    return ptr;
}

// Copy char *str (null-terminated), allocating it in arena.
// Returns NULL if out of memory.
INLINE char* arena_strdup(Arena* arena, const char* str) {
    size_t len = strlen(str);
    size_t cap = len + 1;
    char* dst  = arena_alloc(arena, cap);
    if (dst) {
        memcpy(dst, str, len + 1);  // +1 to include null terminator
    }
    return dst;
}

// Copy char *str that is possibly not null-terminated, allocating it in arena.
// It is assumed that str has a length of len.
// Returns NULL if out of memory.
INLINE char* arena_strdup2(Arena* arena, const char* str, size_t len) {
    size_t cap = len + 1;
    char* dst  = arena_alloc(arena, cap);
    if (dst) {
        memcpy(dst, str, len);
        dst[len] = '\0';  // Ensure null termination
    }
    return dst;
}

// Reset arena memory offset to 0.
INLINE void arena_reset(Arena* arena) {
    arena->allocated = 0;
}

#ifdef __cplusplus
}
#endif

#endif /* ARENA_H */
