#include "arena.h"
#include "aligned_alloc.h"
#include "macros.h"

#include <stdbool.h>
#include <stdlib.h> /* abort    */
#include <string.h> /* memset   */

#if defined(_WIN32)
    #include "../include/platform.h"
#else
    #include <sys/mman.h> /* (reserved for future mmap path) */
    #include <unistd.h>   /* sysconf */
#endif

/* -------------------------------------------------------------------------
 * Thread-local static backing buffer
 *
 * arena_create() uses this buffer as the first block when it is large enough
 * and not already claimed.  One buffer per thread means no contention and no
 * heap allocation on the happy path.
 * ---------------------------------------------------------------------- */

#define STATIC_BUFFER_SIZE (1024 * 1024) /* 1 MB per thread */

/** Per-thread 1 MB backing buffer handed to arenas as their first block while unclaimed. */
static alignas(64) THREAD_LOCAL char static_buffer[STATIC_BUFFER_SIZE];
static THREAD_LOCAL bool static_buffer_in_use = false;

/* -------------------------------------------------------------------------
 * Thread-local overflow-block recycle bin
 *
 * Problem
 * -------
 * Short-lived arenas that outgrow their first block pay a heavy tax on
 * every create/destroy cycle: overflow blocks are multi-page allocations
 * which the system allocator satisfies with mmap() and returns to the OS
 * on free().  The next arena then faults every page back in.  In the
 * bundled benchmark (bench_arena, Large scenario) this made cold arenas
 * ~170x slower than warm ones.
 *
 * Mechanism
 * ---------
 * arena_destroy() hands its overflow blocks to a per-thread LIFO recycle
 * bin instead of free(); _arena_alloc_slow() reuses a cached slab (best
 * fit) before calling aligned_alloc_xp().  Pages therefore stay mapped
 * and resident: no syscall, no page faults.
 *
 * Bounds & hygiene
 * ----------------
 * The bin is capped both in block count and total bytes; excess blocks go
 * straight to free().  The cache is drained by a TLS destructor when a
 * thread exits, so nothing is ever leaked.  Sanitizer builds disable the
 * bin entirely for precise leak attribution.  Define
 * ARENA_BLOCK_CACHE_COUNT=0 to turn recycling off at compile time.
 * ---------------------------------------------------------------------- */

#ifndef ARENA_BLOCK_CACHE_COUNT
    #define ARENA_BLOCK_CACHE_COUNT 8
#endif
#ifndef ARENA_BLOCK_CACHE_BYTES
    #define ARENA_BLOCK_CACHE_BYTES (16u << 20) /* 16 MB per thread */
#endif

#if defined(__SANITIZE_ADDRESS__) || SOLIDC_HAS_FEATURE(address_sanitizer)
    #undef ARENA_BLOCK_CACHE_COUNT
    #define ARENA_BLOCK_CACHE_COUNT 0 /* sanitizers want exact alloc/free pairing */
#endif

#if ARENA_BLOCK_CACHE_COUNT > 0

    #define ARENA_HAVE_BLOCK_CACHE 1

static THREAD_LOCAL ArenaBlock* blk_cache[ARENA_BLOCK_CACHE_COUNT];
static THREAD_LOCAL size_t blk_cache_slab[ARENA_BLOCK_CACHE_COUNT]; /* full slab bytes */
static THREAD_LOCAL size_t blk_cache_count = 0;
static THREAD_LOCAL size_t blk_cache_bytes = 0;

    /* TLS destructor support: drain the bin when the owning thread exits.
     * Note: POSIX only runs key destructors from pthread_exit(); returning
     * from main() bypasses them on glibc, so we also hook atexit() which is
     * guaranteed to run on the main thread during normal shutdown. */
    #if !defined(_WIN32)
        #include <pthread.h>

/** POSIX-only cache teardown path; drains the bin (defined below). */
static void blk_cache_drain(void);
/** pthread key destructor trampoline; drains the bin when the owning thread exits. */
static void blk_cache_tls_dtor(void* unused);
static pthread_key_t blk_cache_key;
static pthread_once_t blk_cache_once = PTHREAD_ONCE_INIT;

/** pthread_once callback: creates @c blk_cache_key with blk_cache_tls_dtor() as its destructor. */
static void blk_cache_key_create(void) { pthread_key_create(&blk_cache_key, blk_cache_tls_dtor); }

/** Registered as the pthread key destructor; runs at thread exit. */
static void blk_cache_tls_dtor(void* unused) {
    (void)unused;
    blk_cache_drain();
}

/** atexit() handler covering main(), whose return bypasses pthread key destructors on glibc. */
static void blk_cache_atexit_hook(void) { blk_cache_drain(); }

/** Arms the TLS destructor for this thread and registers the one-shot atexit fallback; idempotent. */
static void blk_cache_register(void) {
    pthread_once(&blk_cache_once, blk_cache_key_create);
    /* Any non-NULL value arms the key destructor for this thread. */
    pthread_setspecific(blk_cache_key, &(char){0});
    static bool atexit_registered = false;
    if (!atexit_registered) {
        atexit(blk_cache_atexit_hook); /* covers main(), which skips TLS dtors */
        atexit_registered = true;
    }
}

    #else
        #include "../include/platform.h"

static DWORD blk_cache_fls_index = FLS_OUT_OF_INDEXES;
static INIT_ONCE blk_cache_init_once = INIT_ONCE_STATIC_INIT;

/** Windows-only cache teardown path; drains the bin (defined below). */
static void blk_cache_drain(void);

/** FlsAlloc callback; drains the cache when the owning thread exits. */
static VOID CALLBACK blk_cache_fls_cb(PVOID unused) {
    (void)unused;
    blk_cache_drain();
}

/** InitOnce callback allocating the FLS index used to arm the per-thread destructor. */
static BOOL CALLBACK blk_cache_init_cb(PINIT_ONCE once, PVOID param, PVOID* ctx) {
    (void)once;
    (void)param;
    (void)ctx;
    blk_cache_fls_index = FlsAlloc(blk_cache_fls_cb);
    return TRUE;
}

/** Arms the FLS destructor for this thread; idempotent. */
static void blk_cache_register(void) {
    InitOnceExecuteOnce(&blk_cache_init_once, blk_cache_init_cb, NULL, NULL);
    if (blk_cache_fls_index != FLS_OUT_OF_INDEXES) FlsSetValue(blk_cache_fls_index, (PVOID)(uintptr_t)1);
}
    #endif

/** Releases every cached slab (freeing each pointer); called by the platform TLS destructor and safe to call
 * explicitly. */
static void blk_cache_drain(void) {
    for (size_t i = 0; i < blk_cache_count; i++) {
        aligned_free_xp(blk_cache[i]);
    }
    blk_cache_count = 0;
    blk_cache_bytes = 0;
}

/** Best-fit take: removes the smallest cached slab with size >= @p min_slab, writing its full slab size to @p slab_out;
 * returns NULL when nothing fits. */
static char* blk_cache_take(size_t min_slab, size_t* slab_out) {
    if (ARENA_UNLIKELY(blk_cache_count == 0)) return NULL;

    size_t best = SIZE_MAX;
    size_t best_size = SIZE_MAX;
    for (size_t i = 0; i < blk_cache_count; i++) {
        if (blk_cache_slab[i] >= min_slab && blk_cache_slab[i] < best_size) {
            best = i;
            best_size = blk_cache_slab[i];
        }
    }
    if (best == SIZE_MAX) return NULL;

    char* ptr = (char*)blk_cache[best];
    blk_cache_bytes -= blk_cache_slab[best];
    blk_cache[best] = blk_cache[--blk_cache_count];
    blk_cache_slab[best] = blk_cache_slab[blk_cache_count];
    *slab_out = best_size;
    return ptr;
}

/** Offers a slab to the bin; frees it immediately when the bin is full. */
static void blk_cache_put(ArenaBlock* block, size_t slab_size) {
    static THREAD_LOCAL bool registered = false;
    if (ARENA_UNLIKELY(!registered)) {
        blk_cache_register();
        registered = true;
    }

    if (blk_cache_count >= ARENA_BLOCK_CACHE_COUNT || blk_cache_bytes + slab_size > ARENA_BLOCK_CACHE_BYTES) {
        aligned_free_xp(block);
        return;
    }
    blk_cache[blk_cache_count] = block;
    blk_cache_slab[blk_cache_count] = slab_size;
    blk_cache_count++;
    blk_cache_bytes += slab_size;
}

#else

    #define ARENA_HAVE_BLOCK_CACHE 0
/** Recycling disabled: drain is a no-op. */
static void blk_cache_drain(void) {}
/** Recycling disabled: never yields a slab. @return NULL unconditionally. */
static char* blk_cache_take(size_t min_slab, size_t* slab_out) {
    (void)min_slab;
    (void)slab_out;
    return NULL;
}
/** Recycling disabled: slabs are freed immediately. */
static void blk_cache_put(ArenaBlock* block, size_t slab_size) {
    (void)slab_size;
    aligned_free_xp(block);
}

#endif

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/** Returns the OS page size used to round arena block allocations. */
static ARENA_INLINE size_t get_page_size(void) {
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (size_t)si.dwPageSize;
#else
    return (size_t)sysconf(_SC_PAGESIZE);
#endif
}

/* -------------------------------------------------------------------------
 * Public API — lifecycle
 * ---------------------------------------------------------------------- */

/** @brief Initialises @p a using caller-provided storage as its first block (no heap allocation, no TLS lookup). The
 * arena never frees @p buf; overflow blocks are heap-owned and freed by arena_destroy(). @param a Caller-owned Arena
 * struct. @param buf Backing buffer for the first block; must outlive the arena. @param size Size of @p buf in bytes.
 */
void arena_init(Arena* a, void* buf, size_t size) {
    memset(a, 0, sizeof(Arena));
    a->page_size = get_page_size();
    a->heap_allocated = false;
    a->tls_in_use_origin = NULL;

    a->first_block.base = (char*)buf;
    a->first_block.end = (char*)buf + size;
    a->first_block.is_static = true;
    a->first_block.next = NULL;

    a->head = &a->first_block;
    a->current_block = a->head;
    a->curr = a->head->base;
    a->end = a->head->end;
    a->total_committed = size;
}

/** @brief Allocates and initialises a heap-backed Arena, claiming the per-thread TLS buffer as the first block when it
 * is free and @p reserve_size fits in it; otherwise heap-allocates a page-rounded initial block. @param reserve_size
 * Hint for the initial block size in bytes; 0 selects the default (TLS buffer or ARENA_MIN_BLOCK_SIZE). @return
 * Ready-to-use Arena, or NULL on allocation failure. */
Arena* arena_create(size_t reserve_size) {
    Arena* a = (Arena*)aligned_alloc_xp(64, sizeof(Arena));
#ifdef ARENA_ABORT_ON_OOM
    if (ARENA_UNLIKELY(!a)) ARENA_OOM_HANDLER(sizeof(Arena));
#endif
    if (!a) return NULL;

    if (!static_buffer_in_use && reserve_size <= STATIC_BUFFER_SIZE) {
        arena_init(a, static_buffer, STATIC_BUFFER_SIZE);
        static_buffer_in_use = true;

        // Avoid race condition if the arena is handed off to another thread
        // after creation since we are storing this threads address.
        a->tls_in_use_origin = &static_buffer_in_use;
    } else {
        size_t page_size = get_page_size();
        size_t initial_size = reserve_size > 0 ? reserve_size : ARENA_MIN_BLOCK_SIZE;
        /* Round up to page boundary. */
        initial_size = (initial_size + page_size - 1) & ~(page_size - 1);

        char* buf = (char*)aligned_alloc_xp(64, initial_size);
        if (!buf) {
            aligned_free_xp(a);
#ifdef ARENA_ABORT_ON_OOM
            ARENA_OOM_HANDLER(initial_size);
            ARENA_UNREACHABLE(); /* handler aborts; silences MSVC C4702 */
#else
            return NULL;
#endif
        }
        arena_init(a, buf, initial_size);
        /* Mark the first block as heap-owned so arena_destroy frees it. */
        a->first_block.is_static = false;
    }

    a->heap_allocated = true;
    return a;
}

/** @brief Releases all arena resources: overflow blocks are offered to the thread-local recycle bin, a heap-allocated
 * first block is freed (caller-owned buffers are not), a claimed TLS buffer is unclaimed via its origin flag, and the
 * struct itself is freed when heap-allocated. @param a Arena to destroy; NULL is safely ignored. */
void arena_destroy(Arena* a) {
    if (!a) return;

    ArenaBlock* block = a->head;

    /* Free the first block's buffer only if we heap-allocated it.
     * Static/stack/TLS-backed buffers are caller-owned and must not be freed. */
    if (block && !block->is_static) {
        aligned_free_xp(block->base);
    }

    /* If the first block was the TLS static buffer, mark it available again
     * so the next arena_create() can reuse it without leaking capacity.
     Comparing block->base == static_buffer is a bug if the arena switched threads.
     */
    if (block && block->is_static && a->tls_in_use_origin) {
        *a->tls_in_use_origin = false;
    }

    /* Walk overflow blocks.  Each was allocated as a single slab where the
     * ArenaBlock header lives at the start of the pointer returned by
     * aligned_alloc_xp, so we free the block pointer itself (not block->base).
     * Blocks are offered to the thread-local recycle bin first so a future
     * arena can reuse them without syscalls or page faults. */
    block = block ? block->next : NULL;
    while (block) {
        ArenaBlock* next = block->next;
        blk_cache_put(block, (size_t)(block->end - (char*)block));
        block = next;
    }

    if (a->heap_allocated) aligned_free_xp(a);
}

/* -------------------------------------------------------------------------
 * Slow path — new block allocation
 * ---------------------------------------------------------------------- */

/** @private Slow path for arena_alloc_align(): first searches blocks after current_block for one with room, else
 * allocates a fresh page-rounded slab (recycle bin first, doubling capacity up to ARENA_MAX_BLOCK_SIZE), links it at
 * the chain tail so skipped blocks are revisited, and bumps the cursor. @param a Owning arena. @param size Bytes
 * requested. @param alignment Required power-of-two alignment. @return Aligned pointer into the block, or NULL on
 * allocation failure. */
void* _arena_alloc_slow(Arena* a, size_t size, size_t alignment) {
    /* --- Try existing cached blocks after current_block first ------------ */

    ArenaBlock* next = a->current_block->next;
    while (next) {
        uintptr_t aligned = ((uintptr_t)next->base + alignment - 1) & ~(uintptr_t)(alignment - 1);
        if (aligned + size <= (uintptr_t)next->end) {
            /* Found a cached block with enough room. */
            a->current_block = next;
            a->curr = (char*)(aligned + size);
            a->end = next->end;
            return (void*)aligned;
        }
        next = next->next;
    }

    /* --- Allocate a fresh block ----------------------------------------- */

    /* The new block slab must hold: ArenaBlock header + worst-case alignment
     * padding + the requested allocation. */
    size_t current_capacity = (size_t)(a->current_block->end - a->current_block->base);
    size_t needed = sizeof(ArenaBlock) + (alignment - 1) + size;

    // Check for overflow.
    size_t next_size = (current_capacity <= ARENA_MAX_BLOCK_SIZE / 2) ? current_capacity * 2 : ARENA_MAX_BLOCK_SIZE;
    if (next_size < needed) next_size = needed;
    if (next_size < ARENA_MIN_BLOCK_SIZE) next_size = ARENA_MIN_BLOCK_SIZE;

    /* Round up to page boundary so mmap-based backends work efficiently. */
    next_size = (next_size + a->page_size - 1) & ~(a->page_size - 1);

    /* Recycle bin first: reusing a cached slab avoids the allocator call
     * and, more importantly, keeps pages mapped so no page faults occur. */
    size_t got = 0;
    char* ptr = blk_cache_take(next_size, &got);
    if (ptr) {
        next_size = got; /* adopt the full slab so no capacity is stranded */
    } else {
        ptr = (char*)aligned_alloc_xp(64, next_size);
    }
    if (!ptr) return NULL;

    ArenaBlock* block = (ArenaBlock*)ptr;

    /* base starts right after the header, already accounting for the 64-byte
     * slab alignment from aligned_alloc_xp.  If the requested alignment is
     * <= 64 (the common case) block->base is already correctly aligned — the
     * extra alignment arithmetic below reduces to a no-op. */
    uintptr_t base_addr = (uintptr_t)(ptr + sizeof(ArenaBlock));
    uintptr_t aligned = (base_addr + alignment - 1) & ~(uintptr_t)(alignment - 1);

    block->base = (char*)base_addr; /* record the true start for capacity math */
    block->end = ptr + next_size;
    block->is_static = false;
    /* Insert at the tail of the chain so skipped cached blocks are revisited
     * on future slow-path calls instead of being orphaned mid-chain. */
    block->next = NULL;
    a->current_block->next = block;

    a->current_block = block;
    a->total_committed += next_size;
    a->curr = (char*)(aligned + size);
    a->end = block->end;

    return (void*)aligned;
}
