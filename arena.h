#ifndef ARENA_H
#define ARENA_H

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t* memory;   // Arena memory
    size_t allocated;  // Allocated memory
    size_t capacity;   // Capacity of the arena
} Arena;

static inline Arena* arena_create(size_t capacity) {
    assert(capacity > 0);
    Arena* arena = malloc(sizeof(Arena));
    if (!arena) {
        return NULL;
    }

    arena->memory = calloc(1, capacity);
    if (!arena->memory) {
        free(arena);
        return NULL;
    }
    arena->allocated = 0;
    arena->capacity  = capacity;
    return arena;
}

static inline void arena_destroy(Arena* arena) {
    if (!arena) return;
    free(arena->memory);
    free(arena);
}

static inline void* arena_alloc(Arena* arena, size_t size) {
    if (arena->allocated + size > arena->capacity) {
        return NULL;
    }

    void* ptr = &arena->memory[arena->allocated];
    arena->allocated += size;
    return ptr;
}

static inline char* arena_strdup(Arena* arena, const char* str) {
    size_t cap = strlen(str) + 1;
    char* dst  = arena_alloc(arena, cap);
    if (!dst) {
        return NULL;
    }

    // copy string including NULL terminator.
    (void)strlcpy(dst, str, cap);
    return dst;
}

static inline void arena_reset(Arena* arena) {
    arena->allocated = 0;
}

#endif /* ARENA_H */
