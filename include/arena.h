#ifndef ARENA_H
#define ARENA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Single threaded Linear (bump) allocator.
typedef struct {
    uint8_t* memory;   // Arena memory
    size_t allocated;  // Allocated memory
    size_t capacity;   // Capacity of the arena
} Arena;

// Create a new arena with given capacity.
// If capacity is 0, 1024 bytes are allocated.
static inline Arena* arena_create(size_t capacity) {
    if (capacity == 0) {
        capacity = 1024;  // Default is 1KB
    }

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
static inline void arena_destroy(Arena* arena) {
    if (!arena)
        return;
    free(arena->memory);
    free(arena);
}

// Allocate pointer of given size in arena.
// Size is aligned to 8 bytes.
// Returns NULL if arena is out of memory.
static inline void* arena_alloc(Arena* arena, size_t size) {
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

// Reset arena memory offset to 0.
// memset is not called to zero the memory.
static inline void arena_reset(Arena* arena) {
    arena->allocated = 0;
    // memset(arena->memory, 0, arena->capacity);
}

#ifdef __cplusplus
}
#endif

#endif  // ARENA_H
