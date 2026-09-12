#ifndef WORKER_POOL_H
#define WORKER_POOL_H

#include "pulsar.h"

typedef struct ALIGN(64) WorkerPool {
    PulsarConn* conns[WORKER_POOL_SIZE];
    Arena* arenas[WORKER_POOL_SIZE];
    size_t top;
} WorkerPool;

static WorkerPool worker_pools[NUM_WORKERS];

static inline void worker_pool_init(int worker_id) {
    WorkerPool* pool = &worker_pools[worker_id];
    pool->top = 0;

    for (size_t i = 0; i < WORKER_POOL_SIZE; i++) {
        PulsarConn* conn = malloc(sizeof(*conn));
        Arena* arena = arena_create(CONNECTION_ARENA_SIZE);
        if (!conn || !arena) {
            free(conn);
            arena_destroy(arena);
            fprintf(stderr, "worker_pool_init failed for worker %d at slot %zu\n", worker_id, i);
            return;
        }

        pool->conns[pool->top] = conn;
        pool->arenas[pool->top] = arena;
        pool->top++;
    }
}

static inline PulsarConn* worker_pool_acquire(int worker_id, Arena** arena) {
    WorkerPool* pool = &worker_pools[worker_id];
    if (pool->top == 0) {
        *arena = arena_create(CONNECTION_ARENA_SIZE);
        return malloc(sizeof(PulsarConn));
    }

    pool->top--;
    *arena = pool->arenas[pool->top];
    return pool->conns[pool->top];
}

static inline void worker_pool_release(int worker_id, PulsarConn* conn, Arena* arena) {
    WorkerPool* pool = &worker_pools[worker_id];

    if (pool->top < WORKER_POOL_SIZE) {
        arena_reset(arena);
        pool->conns[pool->top] = conn;
        pool->arenas[pool->top] = arena;
        pool->top++;
        return;
    }

    arena_destroy(arena);
    free(conn);
}

static inline void worker_pool_cleanup(int worker_id) {
    WorkerPool* pool = &worker_pools[worker_id];
    while (pool->top > 0) {
        pool->top--;
        arena_destroy(pool->arenas[pool->top]);
        free(pool->conns[pool->top]);
    }
}

#endif  // WORKER_POOL_H