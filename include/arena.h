#ifndef ARENA_H
#define ARENA_H

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

// Single threaded Linear (bump) allocator.
typedef struct {
    uint8_t* memory;   // Arena memory
    size_t allocated;  // Allocated memory
    size_t capacity;   // Capacity of the arena
} Arena;

// Create a new arena with given capacity. Capacity must be > 0.
INLINE Arena* arena_create(size_t capacity) {
    assert(capacity > 0);

    Arena* arena = malloc(sizeof(Arena));
    if (!arena) {
        perror("malloc: arena_create failed");
        return NULL;
    }

    arena->memory = calloc(1, capacity);
    if (!arena->memory) {
        perror("calloc: arena_create failed");
        free(arena);
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
    free(arena->memory);
    free(arena);
}

// Allocate pointer of given size in arena.
// Returns NULL if arena is out of memory.
INLINE void* arena_alloc(Arena* arena, size_t size) {
    size = (size + 7) & ~7;
    if (arena->allocated + size > arena->capacity) {
        return NULL;
    }
    void* ptr = &arena->memory[arena->allocated];
    arena->allocated += size;
    return ptr;
}

// Copy char *str, allocating it in arena.
// Returns NULL if out of memory.
INLINE char* arena_strdup(Arena* arena, const char* str) {
    size_t cap = strlen(str) + 1;
    char* dst  = arena_alloc(arena, cap);
    if (!dst) {
        return NULL;
    }

    // copy string including NULL terminator.
    (void)strlcpy(dst, str, cap);
    return dst;
}

// Reset arena memory offset to 0.
INLINE void arena_reset(Arena* arena) {
    arena->allocated = 0;
    // memset(arena->memory, 0, arena->capacity);
}

#ifdef __cplusplus
}
#endif

#endif  // ARENA_H
