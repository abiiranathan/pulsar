/**
 * arena.h - High-performance arena allocator
 *
 * Pure bump-pointer allocator. Overflow blocks are co-located with their
 * ArenaBlock header (one allocation per block instead of two). Blocks double
 * in size on each expansion up to ARENA_MAX_BLOCK_SIZE, then grow linearly.
 * Reset is O(1) and keeps committed pages alive for reuse.
 *
 * Two creation modes:
 *
 *   // Heap-allocated arena struct (uses per-thread TLS buffer as first block):
 *   Arena* a = arena_create(0);
 *   arena_destroy(a);
 *
 *   // Stack/static arena struct (zero heap overhead at init):
 *   char buf[64 * 1024];
 *   Arena a;
 *   arena_init(&a, buf, sizeof(buf));
 *   arena_destroy(&a);  // frees overflow blocks; buf is caller-owned
 *
 * Overflow-block recycling
 * ------------------------
 * When an arena that outgrew its first block is destroyed, its overflow
 * blocks are placed in a bounded per-thread recycle bin instead of being
 * returned to the system allocator.  The next arena on that thread reuses
 * a cached slab (best fit) for its overflow needs, which eliminates both
 * the allocator call and — more importantly — the page faults of touching
 * freshly mapped memory.  In the bundled benchmark this makes cold arenas
 * as fast as warm ones (~190x faster than without recycling for large
 * working sets).
 *
 * The bin holds at most ARENA_BLOCK_CACHE_COUNT slabs totalling at most
 * ARENA_BLOCK_CACHE_BYTES bytes (both defined in src/arena.c; defaults:
 * 8 slabs, 16 MB per thread).  Surplus blocks are freed immediately, and
 * the bin is drained automatically when a thread exits or the process
 * shuts down, so nothing is ever leaked or held past thread lifetime.
 * Define ARENA_BLOCK_CACHE_COUNT=0 when building src/arena.c to disable
 * recycling entirely (e.g. under strict alloc/free accounting tools,
 * where it is already auto-disabled for AddressSanitizer builds).
 *
 * OOM behaviour
 * -------------
 * By default all allocation functions return NULL on failure, leaving error
 * handling to the caller.  Define ARENA_ABORT_ON_OOM before including this
 * header (or via -DARENA_ABORT_ON_OOM) to make every failing allocation abort
 * the process immediately instead.  A custom handler can be supplied:
 *
 *   #define ARENA_ABORT_ON_OOM
 *   #define ARENA_OOM_HANDLER(size) my_oom_handler(size)
 *   #include "arena.h"
 *
 * The handler receives the failed allocation size and must not return.
 * When ARENA_ABORT_ON_OOM is set, allocation functions that can never return
 * NULL are annotated __attribute__((returns_nonnull)) so the compiler can
 * eliminate caller-side null checks entirely.
 *
 * Note: arena_realloc() is intentionally NOT annotated returns_nonnull even
 * when ARENA_ABORT_ON_OOM is set, because new_size==0 is a valid shrink-to-
 * nothing call that returns NULL by contract, not an allocation failure.
 */

#ifndef ARENA_H
#define ARENA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Portability / compiler helpers
 * ---------------------------------------------------------------------- */

#ifdef _MSC_VER
#include <intrin.h>
#define ARENA_INLINE               __forceinline
#define ARENA_PREFETCH(addr)       _mm_prefetch((const char*)(addr), _MM_HINT_T0)
#define ARENA_LIKELY(x)            (x)
#define ARENA_UNLIKELY(x)          (x)
#define ARENA_ATTR_MALLOC          __declspec(restrict)
#define ARENA_ATTR_ALLOC_SIZE(n)   /* not available on MSVC */
#define ARENA_ATTR_RETURNS_NONNULL /* not available on MSVC */
#define ARENA_UNREACHABLE()        __assume(0)
#else
#define ARENA_INLINE               inline __attribute__((always_inline))
#define ARENA_PREFETCH(addr)       __builtin_prefetch((addr), 1, 3)
#define ARENA_LIKELY(x)            __builtin_expect(!!(x), 1)
#define ARENA_UNLIKELY(x)          __builtin_expect(!!(x), 0)
/** Tells the compiler the returned pointer aliases no existing object. */
#define ARENA_ATTR_MALLOC          __attribute__((malloc))
/** Tells the compiler which argument encodes the allocation size. */
#define ARENA_ATTR_ALLOC_SIZE(n)   __attribute__((alloc_size(n)))
#define ARENA_ATTR_RETURNS_NONNULL __attribute__((returns_nonnull))
#define ARENA_UNREACHABLE()        __builtin_unreachable()
#endif

/* -------------------------------------------------------------------------
 * OOM crash-on-fail hook
 *
 * Activated by -DARENA_ABORT_ON_OOM or a #define before this header.
 * The default handler prints to stderr and calls abort().  Supply your own
 * ARENA_OOM_HANDLER(size) to log, longjmp, or terminate differently — it
 * must never return.
 * ---------------------------------------------------------------------- */

#ifdef ARENA_ABORT_ON_OOM
#include <stdio.h>  /* fprintf  */
#include <stdlib.h> /* abort    */
#ifndef ARENA_OOM_HANDLER
/**
 * Called by arena allocators when an allocation fails and ARENA_ABORT_ON_OOM
 * is defined.  @p size is the byte count that could not be satisfied.
 * The default implementation prints a diagnostic and calls abort().
 * Define your own before including arena.h to override.
 */
#define ARENA_OOM_HANDLER(size)                                                         \
    do {                                                                                \
        fprintf(stderr, "arena: out of memory allocating %zu bytes\n", (size_t)(size)); \
        abort();                                                                        \
    } while (0)
#endif /* ARENA_OOM_HANDLER */

/** Internal: applied to functions that abort on OOM so callers skip NULL checks. */
#define ARENA_NONNULL_ ARENA_ATTR_RETURNS_NONNULL

#else /* !ARENA_ABORT_ON_OOM */

#define ARENA_NONNULL_ /* nothing — callers must check for NULL */
/* ARENA_UNREACHABLE() is already defined in the compiler-helpers block above. */

#endif /* ARENA_ABORT_ON_OOM */

/* -------------------------------------------------------------------------
 * Tuning constants
 * ---------------------------------------------------------------------- */

/** Default alignment for arena_alloc(). Suitable for all scalar types, SSE/AVX, and NEON. */
#define ARENA_DEFAULT_ALIGN 16

/** Minimum heap block size. Prevents pathological tiny-block chains. */
#define ARENA_MIN_BLOCK_SIZE (64 * 1024) /* 64 KB */

/**
 * Maximum heap block size. Once the current block reaches this capacity the
 * allocator switches from exponential to linear growth, bounding virtual
 * memory consumption for long-lived arenas.
 */
#define ARENA_MAX_BLOCK_SIZE (8 * 1024 * 1024) /* 8 MB */

/* -------------------------------------------------------------------------
 * Core types
 * ---------------------------------------------------------------------- */

/**
 * Descriptor for a single contiguous memory region within the arena chain.
 *
 * For overflow blocks the ArenaBlock header is co-located at the start of the
 * heap allocation (one aligned_alloc_xp call per block, not two). The usable
 * region begins at @c base, immediately after the header and any alignment
 * padding imposed by the first allocation in that block.
 *
 * The initial block embeds this struct inside Arena::first_block and points
 * into a caller- or TLS-supplied buffer; @c is_static is set and the buffer
 * is never freed by the arena.
 */
typedef struct ArenaBlock {
    struct ArenaBlock* next; /**< Next block in the chain, or NULL.                      */
    char* base;              /**< Start of usable region (after header + padding).       */
    char* end;               /**< One past the last byte of this block's allocation.     */
    bool is_static;          /**< True when the backing buffer is caller-owned.          */
} ArenaBlock;

/**
 * Lightweight save/restore token for O(1) allocation checkpointing.
 *
 * Obtained via arena_save(); passed back to arena_restore() to roll back all
 * allocations made since the snapshot.  Blocks are never freed by restore —
 * they remain committed and available for subsequent allocations.
 *
 * Behaviour is undefined if the checkpoint is used after arena_destroy(), or
 * with an arena other than the one that produced it.
 */
typedef struct ArenaCheckpoint {
    char* saved_curr;        /**< Allocation cursor at the time of the save.  */
    char* saved_end;         /**< Block end pointer at the time of the save.  */
    ArenaBlock* saved_block; /**< Active block at the time of the save.       */
} ArenaCheckpoint;

/**
 * Arena control structure.
 *
 * The two hottest fields — @c curr and @c end — are placed first so they
 * share a cache line with each other and with @c current_block, regardless
 * of where the struct is allocated.  @c aligned_alloc_xp(64, sizeof(Arena))
 * in arena_create() ensures the heap-allocated instance starts on a 64-byte
 * boundary, keeping the fast path in a single cache line fetch.
 */
typedef struct Arena {
    char* curr;                /**< Next byte to dispense (bump pointer).                   */
    char* end;                 /**< One past the last byte of the current block.            */
    ArenaBlock* current_block; /**< Block currently being allocated from.                   */
    ArenaBlock* head;          /**< Head of the block chain (always the first block).       */
    size_t page_size;          /**< OS page size used to round block sizes (usually 4096).  */
    size_t total_committed;    /**< Total bytes across all committed blocks.              */
    bool heap_allocated;       /**< True when this struct was allocated by arena_create(). */
    bool* tls_in_use_origin;   /* == &static_buffer_in_use on creating thread */
    ArenaBlock first_block;    /**< Embedded descriptor for the initial backing buffer.     */
} Arena;

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */

/**
 * Initialises an arena using caller-provided storage as the first block.
 *
 * The arena never frees @p buf.  Overflow blocks allocated during use are
 * heap-allocated and freed by arena_destroy().  This function performs no
 * heap allocation and no TLS lookup.
 *
 * @param a    Caller-owned Arena struct (stack, static, or embedded in another struct).
 * @param buf  Backing buffer for the first block.  Must outlive the arena.
 * @param size Size of @p buf in bytes.
 */
void arena_init(Arena* a, void* buf, size_t size);

/**
 * Allocates and initialises a heap-backed Arena.
 *
 * Uses the per-thread 1 MB TLS buffer as the first block when it is not
 * already claimed and @p reserve_size fits within it; otherwise
 * heap-allocates the initial block.
 *
 * @param reserve_size Hint for the initial block size in bytes.  Pass 0 to
 *                     use the default (TLS buffer or ARENA_MIN_BLOCK_SIZE).
 * @return Pointer to a ready-to-use Arena, or NULL on allocation failure.
 */
Arena* arena_create(size_t reserve_size);

/**
 * Resets the arena, making all committed memory available for reuse.
 *
 * All pointers previously returned by this arena become invalid.  Committed
 * pages are retained so subsequent allocations avoid page faults.  O(1).
 *
 * If the arena is already clean (no allocations since the last reset or
 * init), this is a no-op — no stores are issued.
 *
 * @param a Arena to reset.  NULL is safely ignored.
 */
static ARENA_INLINE void arena_reset(Arena* a) {
    if (!a || !a->head) return;

    /* Dirty check: if we're still on the head block and the cursor hasn't
     * moved off its base, no allocation has happened since the last reset.
     * Skip the writes entirely rather than re-storing identical values. */
    if (a->current_block == a->head && a->curr == a->head->base) return;

    a->current_block = a->head;
    a->curr = a->head->base;
    a->end = a->head->end;
}

/**
 * Destroys the arena and releases all heap-allocated resources.
 *
 * Frees every overflow block in the chain.  If the initial block's buffer
 * was heap-allocated by arena_create() it is freed too; caller-owned buffers
 * (arena_init()) are left untouched.  If the Arena struct itself was
 * allocated by arena_create() it is freed last.
 *
 * @param a Arena to destroy.  NULL is safely ignored.
 */
void arena_destroy(Arena* a);

/* -------------------------------------------------------------------------
 * Checkpoint (save / restore)
 * ---------------------------------------------------------------------- */

/**
 * Captures the current allocation cursor as a lightweight checkpoint.
 *
 * Use arena_restore() to roll back all allocations made after this call.
 * Typical pattern:
 *
 *   ArenaCheckpoint cp = arena_save(a);
 *   // ... tentative allocations ...
 *   if (failed) arena_restore(a, cp);  // discard
 *
 * O(1), no allocation.
 *
 * @param a Arena to snapshot.
 * @return  Opaque checkpoint token.
 */
static ARENA_INLINE ArenaCheckpoint arena_save(const Arena* a) {
    return (ArenaCheckpoint){
        .saved_curr = a->curr,
        .saved_end = a->end,
        .saved_block = a->current_block,
    };
}

/**
 * Rolls back the arena to the state captured by arena_save().
 *
 * All allocations made after the corresponding arena_save() are discarded.
 * Overflow blocks are not freed — they remain committed for future use.
 * O(1), no allocation.
 *
 * @param a   Arena to restore.
 * @param cp  Checkpoint returned by arena_save() on the same arena.
 */
static ARENA_INLINE void arena_restore(Arena* a, ArenaCheckpoint cp) {
    a->curr = cp.saved_curr;
    a->end = cp.saved_end;
    a->current_block = cp.saved_block;
}

/* -------------------------------------------------------------------------
 * Size queries
 * ---------------------------------------------------------------------- */

/**
 * Returns the total number of bytes committed across all blocks.
 *
 * This reflects physical memory in use, not the amount consumed by live
 * allocations.  After arena_reset() committed memory is retained.
 *
 * @param a Arena to query.
 * @return  Total committed bytes.
 */
static ARENA_INLINE size_t arena_committed_size(const Arena* a) { return a->total_committed; }

/**
 * Returns the number of bytes consumed by live allocations.
 *
 * Counts all bytes in fully-used blocks before @c current_block plus the
 * used portion of @c current_block.  Accurate as long as the arena has not
 * been reset mid-chain.
 *
 * @param a Arena to query.
 * @return  Bytes in use, or 0 if @p a or its block chain is NULL.
 */
static ARENA_INLINE size_t arena_used_size(const Arena* a) {
    if (!a || !a->current_block) return 0;
    size_t block_capacity = (size_t)(a->current_block->end - a->current_block->base);
    size_t block_used = (size_t)(a->curr - a->current_block->base);
    return (a->total_committed - block_capacity) + block_used;
}

/* -------------------------------------------------------------------------
 * Internal slow path — not for direct use
 * ---------------------------------------------------------------------- */

/**
 * @private
 * Allocates a new block and satisfies the request when the current block is
 * full.  First searches the cached block chain; allocates a fresh slab only
 * if no cached block is large enough.  Not for direct use by callers.
 *
 * @param arena     The arena needing a new block.
 * @param size      Bytes requested.
 * @param alignment Required power-of-two alignment.
 * @return Aligned pointer into the new block, or NULL on failure.
 */
void* _arena_alloc_slow(Arena* arena, size_t size, size_t alignment);

/* -------------------------------------------------------------------------
 * Core allocation functions
 * ---------------------------------------------------------------------- */

/**
 * Allocates @p size bytes aligned to @p alignment.
 *
 * @p alignment must be a non-zero power of two.  The fast path is two pointer
 * additions and one branch (~2 ns).  Falls back to _arena_alloc_slow() when
 * the current block is exhausted.
 *
 * When ARENA_ABORT_ON_OOM is defined the function is annotated
 * returns_nonnull and the compiler can eliminate caller-side NULL checks.
 *
 * @param arena     The owning arena.
 * @param size      Bytes to allocate.  Passing 0 returns NULL (or 1 byte when
 *                  ARENA_ABORT_ON_OOM is set, to preserve the nonnull contract).
 * @param alignment Power-of-two alignment in bytes.
 * @return Aligned pointer valid until the next arena_reset() or
 *         arena_destroy(), or NULL on failure.
 */
static ARENA_NONNULL_ ARENA_INLINE ARENA_ATTR_MALLOC
ARENA_ATTR_ALLOC_SIZE(2) void* arena_alloc_align(Arena* arena, size_t size, size_t alignment) {
#ifdef ARENA_ABORT_ON_OOM
    /* Preserve the returns_nonnull contract: treat size==0 as size==1. */
    if (size == 0) size = 1;
#else
    if (size == 0) return NULL;
#endif

    uintptr_t curr = (uintptr_t)arena->curr;
    uintptr_t aligned = (curr + alignment - 1) & ~(uintptr_t)(alignment - 1);
    uintptr_t next = aligned + size;

    if (ARENA_LIKELY(next <= (uintptr_t)arena->end)) {
        arena->curr = (char*)next;
        /* Prefetch the allocated region; hides DRAM latency when the caller
         * immediately writes the object (the common case). */
        ARENA_PREFETCH((void*)aligned);
        return (void*)aligned;
    }

    void* ptr = _arena_alloc_slow(arena, size, alignment);
    if (ARENA_UNLIKELY(!ptr)) {
#ifdef ARENA_ABORT_ON_OOM
        ARENA_OOM_HANDLER(size);
        ARENA_UNREACHABLE();
#else
        return NULL;
#endif
    }
    return ptr;
}

/**
 * Allocates @p size bytes with ARENA_DEFAULT_ALIGN (16-byte) alignment.
 *
 * This is the primary allocation entry point for typed objects.  Use
 * arena_alloc_align() when a specific alignment is required.
 *
 * @param arena The owning arena.
 * @param size  Bytes to allocate.
 * @return 16-byte-aligned pointer, or NULL on failure.
 */
static ARENA_NONNULL_ ARENA_INLINE ARENA_ATTR_MALLOC
ARENA_ATTR_ALLOC_SIZE(2) void* arena_alloc(Arena* arena, size_t size) {
    return arena_alloc_align(arena, size, ARENA_DEFAULT_ALIGN);
}

/**
 * Allocates @p size bytes with no alignment (1-byte aligned).
 *
 * Skips the alignment arithmetic on the fast path, making it marginally
 * cheaper than arena_alloc().  Suitable for byte buffers and strings where
 * alignment is irrelevant.
 *
 * @param arena The owning arena.
 * @param size  Bytes to allocate.
 * @return Unaligned pointer, or NULL on failure.
 */
static ARENA_NONNULL_ ARENA_INLINE ARENA_ATTR_MALLOC
ARENA_ATTR_ALLOC_SIZE(2) void* arena_alloc_unaligned(Arena* arena, size_t size) {
#ifdef ARENA_ABORT_ON_OOM
    if (size == 0) size = 1;
#else
    if (size == 0) return NULL;
#endif

    char* ptr = arena->curr;
    char* next = ptr + size;

    if (ARENA_LIKELY(next <= arena->end)) {
        arena->curr = next;
        ARENA_PREFETCH(ptr);
        return ptr;
    }

    void* p = _arena_alloc_slow(arena, size, 1);
    if (ARENA_UNLIKELY(!p)) {
#ifdef ARENA_ABORT_ON_OOM
        ARENA_OOM_HANDLER(size);
        ARENA_UNREACHABLE();
#else
        return NULL;
#endif
    }
    return p;
}

/* -------------------------------------------------------------------------
 * In-place realloc
 * ---------------------------------------------------------------------- */

/**
 * Resizes the most recent allocation, preferring an in-place cursor move.
 *
 * When @p old_ptr is exactly the last pointer dispensed by this arena and the
 * new size fits in the current block, the bump cursor is adjusted in place —
 * zero copies, zero allocations.  Shrinking is always O(1) regardless of
 * position.  Falls back to arena_alloc_align() + memcpy() only when the
 * in-place extend would cross a block boundary.
 *
 * Special cases:
 *  - @p old_ptr == NULL or @p old_size == 0: behaves like arena_alloc_align().
 *  - @p new_size == 0: reclaims the allocation if it was last, returns NULL.
 *    This is a valid shrink-to-nothing, not an error.  The function is
 *    intentionally not annotated returns_nonnull for this reason.
 *
 * @param arena     The owning arena.
 * @param old_ptr   Pointer from the most recent arena_alloc* call, or NULL.
 * @param old_size  Size of the original allocation (bytes).
 * @param new_size  Desired new size in bytes.
 * @param alignment Power-of-two alignment used for the original allocation.
 * @return Pointer to @p new_size bytes, or NULL if @p new_size is 0 or
 *         allocation fails without ARENA_ABORT_ON_OOM.
 */
static ARENA_INLINE void* arena_realloc(Arena* arena, void* old_ptr, size_t old_size,
                                        size_t new_size, size_t alignment) {
    if (!old_ptr || old_size == 0) {
        return arena_alloc_align(arena, new_size, alignment);
    }

    if (new_size == 0) {
        /* Shrink to nothing: reclaim bytes only if this was the last alloc. */
        if ((char*)old_ptr + old_size == arena->curr) {
            arena->curr = (char*)old_ptr;
        }
        /* NULL here is a defined contract value, not an OOM — do not invoke
         * ARENA_OOM_HANDLER. */
        return NULL;
    }

    /* Fast path: old_ptr was the last allocation in the current block. */
    if ((char*)old_ptr + old_size == arena->curr) {
        char* new_end = (char*)old_ptr + new_size;
        if (new_size <= old_size || new_end <= arena->end) {
            arena->curr = new_end;
            return old_ptr;
        }
    }

    /* Slow path: fresh allocation + copy; old bytes are stranded until reset. */
    void* new_ptr = arena_alloc_align(arena, new_size, alignment);
    if (ARENA_UNLIKELY(!new_ptr)) {
        /* arena_alloc_align already invoked ARENA_OOM_HANDLER if the macro is
         * set, so we only reach here in the non-abort build. */
        return NULL;
    }
    memcpy(new_ptr, old_ptr, old_size < new_size ? old_size : new_size);
    return new_ptr;
}

/* -------------------------------------------------------------------------
 * Zero-initialised helpers
 * ---------------------------------------------------------------------- */

/**
 * Allocates @p size bytes aligned to @p alignment, zero-initialised.
 *
 * Equivalent to arena_alloc_align() followed by memset(ptr, 0, size).
 *
 * @param arena     The owning arena.
 * @param size      Bytes to allocate.
 * @return Zero-filled pointer, or NULL on failure.
 */
static ARENA_NONNULL_ ARENA_INLINE void* arena_alloc_zero(Arena* arena, size_t size) {
    void* ptr = arena_alloc_align(arena, size, ARENA_DEFAULT_ALIGN);
    if (ptr) memset(ptr, 0, size);
    return ptr;
}

/**
 * Allocates an array of @p count elements of @p elem_size bytes each,
 * zero-initialised, with overflow detection.
 *
 * If @p elem_size × @p count would overflow @c size_t the function returns
 * NULL (or aborts when ARENA_ABORT_ON_OOM is set) rather than silently
 * allocating a too-small region.  This is an arithmetic overflow, not an
 * OOM condition, so the OOM handler receives @p elem_size as a best-effort
 * size hint when aborting.
 *
 * @param arena     The owning arena.
 * @param elem_size Size of each element in bytes.
 * @param alignment Power-of-two alignment in bytes.
 * @param count     Number of elements.
 * @return Zero-filled pointer, or NULL on failure.
 */
static ARENA_NONNULL_ ARENA_INLINE void* arena_alloc_array_zero(Arena* arena, size_t elem_size,
                                                                size_t alignment, size_t count) {
    if (ARENA_UNLIKELY(count != 0 && elem_size > (size_t)-1 / count)) {
#ifdef ARENA_ABORT_ON_OOM
        ARENA_OOM_HANDLER(elem_size);
        ARENA_UNREACHABLE();
#else
        return NULL;
#endif
    }
    size_t total = elem_size * count;
    void* ptr = arena_alloc_align(arena, total, alignment);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

/* -------------------------------------------------------------------------
 * Batch allocation
 * ---------------------------------------------------------------------- */

/**
 * Allocates @p count variable-sized blocks in a single contiguous region.
 *
 * Each sub-block is aligned to ARENA_DEFAULT_ALIGN (16 bytes).  The entire
 * region is obtained with one arena_alloc() call, so there is at most one
 * block transition and one bounds check regardless of @p count.
 *
 * The operation is all-or-nothing: if allocation fails, @p out_ptrs is left
 * untouched and the function returns false.
 *
 * @note If any element type requires alignment stricter than 16 bytes, use
 *       individual arena_alloc_align() calls instead.
 *
 * @param arena    The owning arena.
 * @param sizes    Array of @p count per-block sizes in bytes.
 * @param count    Number of blocks to allocate.
 * @param out_ptrs Output array of @p count pointers; populated on success.
 * @return true on success, false on allocation failure or invalid arguments.
 *         Returns false (not abort) on integer overflow in size accumulation,
 *         as that is a programming error rather than an OOM condition.
 */
static ARENA_INLINE bool arena_alloc_batch(Arena* arena, const size_t* sizes, size_t count,
                                           void** out_ptrs) {
    if (!arena || !sizes || !out_ptrs || count == 0) return false;

    const size_t mask = ARENA_DEFAULT_ALIGN - 1;
    size_t total = 0;
    for (size_t i = 0; i < count; ++i) {
        size_t rounded = (total + mask) & ~mask;
        /* Detect integer overflow in the size accumulation.  This is a
         * caller bug, not OOM — return false without invoking the OOM handler
         * regardless of ARENA_ABORT_ON_OOM. */
        if (ARENA_UNLIKELY(sizes[i] > (size_t)-1 - rounded)) return false;
        total = rounded + sizes[i];
    }

    char* base = (char*)arena_alloc(arena, total);
    if (ARENA_UNLIKELY(!base)) {
        /* arena_alloc already called ARENA_OOM_HANDLER if the macro is set. */
        return false;
    }

    char* cur = base;
    for (size_t i = 0; i < count; ++i) {
        cur = (char*)(((uintptr_t)cur + mask) & ~mask);
        out_ptrs[i] = cur;
        cur += sizes[i];
    }
    return true;
}

/* -------------------------------------------------------------------------
 * String helpers
 * ---------------------------------------------------------------------- */

/**
 * Duplicates a null-terminated string into the arena.
 *
 * The resulting string is owned by the arena and becomes invalid after
 * arena_reset() or arena_destroy().  No alignment padding is inserted since
 * strings carry no alignment requirement.
 *
 * @param arena The owning arena.
 * @param str   Null-terminated source string.
 * @return Pointer to the arena-owned copy, or NULL if @p arena or @p str is
 *         NULL, or if allocation fails.
 */
static ARENA_INLINE char* arena_strdup(Arena* arena, const char* str) {
    /* NULL arguments are a programming error, not OOM.  Return NULL silently
     * (or rely on the caller to guard); do not invoke ARENA_OOM_HANDLER. */
    if (ARENA_UNLIKELY(!arena || !str)) return NULL;
    size_t len = strlen(str);
    char* dup = (char*)arena_alloc_unaligned(arena, len + 1);
    if (ARENA_UNLIKELY(!dup)) return NULL;
    memcpy(dup, str, len + 1);
    return dup;
}

/**
 * Copies exactly @p length bytes from @p str into the arena and appends a
 * null terminator.
 *
 * @p str need not be null-terminated; only the first @p length bytes are
 * read.  No alignment padding is inserted.
 *
 * @param arena  The owning arena.
 * @param str    Source data of at least @p length bytes.
 * @param length Number of bytes to copy (excluding the null terminator).
 * @return Pointer to the null-terminated arena-owned copy, or NULL if
 *         @p arena or @p str is NULL, or if allocation fails.
 */
static ARENA_INLINE char* arena_strdupn(Arena* arena, const char* str, size_t length) {
    if (ARENA_UNLIKELY(!arena || !str)) return NULL;
    char* dup = (char*)arena_alloc_unaligned(arena, length + 1);
    if (ARENA_UNLIKELY(!dup)) return NULL;
    memcpy(dup, str, length);
    dup[length] = '\0';
    return dup;
}

#if defined(__cplusplus)
}
#endif

#endif /* ARENA_H */
