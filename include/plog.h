#ifndef PLOG_H
#define PLOG_H

/**
 * plog — Pulsar async logger
 *
 * Architecture
 * ============
 * Worker threads (producers) call plog_submit() which atomically claims a
 * slot in a power-of-two MPSC ring buffer, copies the pre-formatted line,
 * and publishes it.  A single background thread drains ready slots with one
 * writev(2) per batch, amortising syscall cost across all concurrent
 * producers.
 *
 * Hot-path cost per request (uncontended ring):
 *   1. Atomic CAS on prod_seq (claims slot + checks fullness) (~3 ns)
 *   2. __builtin_memcpy into the slot                     (~8 ns)
 *   3. Release store of READY on the slot                 (~1 ns)
 *   4. Atomic fetch-add on pending (signals consumer)     (~2 ns)
 *  ──────────────────────────────────────────────────────────────
 *  Total                                                  ~14 ns
 *
 * No malloc on the hot path.  No spin loops.  No per-entry locks.
 *
 * Slot state machine
 * ==================
 *
 *   FREE ──(producer store)──► READY ──(drain store)──► FREE
 * The two-state machine is safe because:
 *   - prod_seq is a monotonically increasing counter; the CAS on prod_seq
 *     gives one thread exclusive ownership of a unique index and guarantees
 *     that the slot is not currently in use.
 *   - The drain thread advances cons_seq only after writev completes, so it
 *     can never reach a slot whose producer has not yet stored READY.
 *
 * Backpressure
 * ============
 * plog_submit() checks for a full ring BEFORE claiming a sequence number.
 * If full, the entry is dropped and the drop counter incremented.  No spin.
 * A CAS failure after the pre-check (possible under high concurrency) is
 * also handled as a drop.  Tune PLOG_RING_CAPACITY upward if drops occur.
 * Retrieve the cumulative drop count with plog_drop_count().
 *
 * Thread safety
 * =============
 * plog_submit()          — safe for concurrent use by any number of threads.
 * plog_init/destroy()    — call from one thread only, before/after all
 *                          submit calls.
 */

#include <inttypes.h>  /* PRIu64                             */
#include <stdalign.h>  /* alignas                            */
#include <stdatomic.h> /* _Atomic, atomic_*                  */
#include <stdbool.h>   /* bool                               */
#include <stddef.h>    /* size_t                             */
#include <stdint.h>    /* uint32_t, uint64_t                 */
#include <sys/uio.h>   /* struct iovec, writev               */
#include <unistd.h>    /* STDOUT_FILENO, usleep              */

#include <solidc/lock.h>   /* Lock, Condition, lock_*, cond_*   */
#include <solidc/thread.h> /* Thread, thread_create, thread_join */

/* -------------------------------------------------------------------------
 * Tunables — override with -DPLOG_XXX=value before including.
 * ---------------------------------------------------------------------- */

/** Ring capacity.  Must be a power of two.  Increase if drops occur. */
#ifndef PLOG_RING_CAPACITY
#define PLOG_RING_CAPACITY 4096
#endif

/** Maximum bytes per log line including the trailing newline. */
#ifndef PLOG_LINE_MAX
#define PLOG_LINE_MAX 256
#endif

/** Maximum iovec entries per writev(2) batch.  POSIX guarantees >= 16. */
#ifndef PLOG_BATCH_MAX
#define PLOG_BATCH_MAX 256
#endif

_Static_assert((PLOG_RING_CAPACITY & (PLOG_RING_CAPACITY - 1)) == 0, "PLOG_RING_CAPACITY must be a power of two");
_Static_assert(PLOG_LINE_MAX > 0, "PLOG_LINE_MAX must be positive");
_Static_assert(PLOG_BATCH_MAX > 0, "PLOG_BATCH_MAX must be positive");

/* -------------------------------------------------------------------------
 * Ring slot
 * ---------------------------------------------------------------------- */

/** Slot state: FREE means available to a producer; READY means written and
 *  waiting for the drain thread. */
typedef enum {
    PLOG_SLOT_FREE = 0,  /* available for a new producer             */
    PLOG_SLOT_READY = 1, /* written, waiting to be drained           */
} PlogSlotState;

/**
 * One ring slot.
 *
 * Padded to a multiple of 64 bytes (one cache line) to prevent false
 * sharing between adjacent slots on different cores.
 *
 * Layout for PLOG_LINE_MAX=256:
 *   state  4 B  +  len  4 B  +  line  256 B  +  pad  56 B  =  320 B
 */
typedef struct {
    _Atomic(PlogSlotState) state; /* two-state machine; see above       */
    uint32_t len;                 /* valid bytes in line[]              */
    char line[PLOG_LINE_MAX];     /* pre-formatted text   */
    /* Pad to next 64-byte boundary to eliminate false sharing. */
    char _pad[64 - ((sizeof(_Atomic(PlogSlotState)) + sizeof(uint32_t) + PLOG_LINE_MAX) % 64)];
} PlogSlot;

/* -------------------------------------------------------------------------
 * Logger state
 * ---------------------------------------------------------------------- */

/**
 * PlogState — logger instance.
 *
 * Declare as a static or global variable and pass to all plog_* functions.
 * Zero-initialised by plog_init(); do not memset manually.
 *
 * NOTE: If allocating PlogState on the heap, use aligned_alloc(64, sizeof(PlogState))
 * or posix_memalign() to guarantee alignment of its members and prevent false sharing.
 */
typedef struct {
    /** Ring buffer.  Indexed by (sequence & (PLOG_RING_CAPACITY - 1)). */
    alignas(64) PlogSlot ring[PLOG_RING_CAPACITY];

    /* -- Producer side -------------------------------------------------- */

    /** Next sequence number to claim.  Each fetch-add gives one thread an
     *  exclusive slot index.  Only the low PLOG_RING_CAPACITY bits matter. */
    alignas(64) _Atomic uint64_t prod_seq;

    /* -- Consumer side -------------------------------------------------- */

    /** Next sequence number to drain.  Advanced by the drain thread after
     *  each writev batch completes. */
    alignas(64) _Atomic uint64_t cons_seq;

    /** Cumulative entries dropped due to a full ring.  Read with
     *  plog_drop_count(). */
    _Atomic uint64_t drops;

    /** Outstanding entries in the ring not yet drained.  The drain thread
     *  sleeps on wake only when this is zero, preventing missed-wakeup
     *  stalls under sustained load. */
    _Atomic uint64_t pending;

    /* -- Drain thread --------------------------------------------------- */

    alignas(64) Lock mu;        /* protects the cond_wait predicate        */
    Condition wake;             /* drain thread sleeps here when idle      */
    _Atomic bool drain_running; /* cleared by plog_destroy to stop thread */
    Thread thread_handle;       /* opaque handle returned by thread_create */
    int out_fd;                 /* destination fd (e.g. STDOUT_FILENO)     */
} PlogState;

/* -------------------------------------------------------------------------
 * Internal — drain thread
 * ---------------------------------------------------------------------- */

/** Maps a raw sequence number to a ring index. */
static inline size_t plog__idx(uint64_t seq) { return (size_t)(seq & (uint64_t)(PLOG_RING_CAPACITY - 1)); }

/**
 * plog__drain_thread — background consumer.
 *
 * Sleeps on `wake` when the ring is empty (pending == 0).  On each wakeup
 * it drains all consecutive READY slots into a single writev(2) call, then
 * loops back — only re-entering cond_wait when genuinely idle.  This
 * prevents the missed-wakeup stall observed under 100c load where the drain
 * thread slept while READY slots were waiting.
 */
static void* plog__drain_thread(void* arg) {
    PlogState* lg = (PlogState*)arg;
    struct iovec iov[PLOG_BATCH_MAX];

    while (atomic_load_explicit(&lg->drain_running, memory_order_acquire)) {
        bool shutting_down = false;

        /* Sleep only when the ring is genuinely empty.  Holding the mutex
         * across the predicate check + cond_wait is required by POSIX to
         * avoid lost wakeups. */
        lock_acquire(&lg->mu);
        while (atomic_load_explicit(&lg->pending, memory_order_acquire) == 0) {
            cond_wait(&lg->wake, &lg->mu);
            if (!atomic_load_explicit(&lg->drain_running, memory_order_acquire)) {
                shutting_down = true;
                break; /* exits inner while, still holds mutex */
            }
        }
        lock_release(&lg->mu); /* single release covers both paths */

        if (shutting_down) break;

    drain_batch:;
        int batch = 0;
        uint64_t seq = atomic_load_explicit(&lg->cons_seq, memory_order_acquire);

        while (batch < PLOG_BATCH_MAX) {
            size_t idx = plog__idx(seq + (uint64_t)batch);
            PlogSlot* slot = &lg->ring[idx];

            /* Peek slot readiness. No CAS on slot read to minimize RMW cycles. */
            if (atomic_load_explicit(&slot->state, memory_order_acquire) != PLOG_SLOT_READY) {
                break;
            }

            iov[batch].iov_base = slot->line;
            iov[batch].iov_len = slot->len;
            batch++;
        }

        if (batch > 0) {
            (void)writev(lg->out_fd, iov, batch);

            /* Release processed slots to FREE.
             * relaxed store is correct because the release increment of cons_seq below
             * enforces transitiveness for the producer acquire on cons_seq. */
            for (int i = 0; i < batch; i++) {
                size_t idx = plog__idx(seq + (uint64_t)i);
                atomic_store_explicit(&lg->ring[idx].state, PLOG_SLOT_FREE, memory_order_relaxed);
            }

            atomic_fetch_add_explicit(&lg->cons_seq, (uint64_t)batch, memory_order_release);
            atomic_fetch_sub_explicit(&lg->pending, (uint64_t)batch, memory_order_release);
            /* Keep draining without sleeping — there may be more slots. */
            goto drain_batch;
        }
    }

    /* --- Shutdown flush: drain whatever remains in the ring. ----------- */
    while (true) {
        uint64_t seq = atomic_load_explicit(&lg->cons_seq, memory_order_acquire);
        uint64_t end = atomic_load_explicit(&lg->prod_seq, memory_order_acquire);
        if (seq == end) {
            break;
        }

        int batch = 0;
        while (seq + (uint64_t)batch < end && batch < PLOG_BATCH_MAX) {
            size_t idx = plog__idx(seq + (uint64_t)batch);
            PlogSlot* slot = &lg->ring[idx];
            if (atomic_load_explicit(&slot->state, memory_order_acquire) == PLOG_SLOT_READY) {
                iov[batch].iov_base = slot->line;
                iov[batch].iov_len = slot->len;
                batch++;
            } else {
                break;
            }
        }

        if (batch > 0) {
            (void)writev(lg->out_fd, iov, batch);
            for (int i = 0; i < batch; i++) {
                size_t idx = plog__idx(seq + (uint64_t)i);
                atomic_store_explicit(&lg->ring[idx].state, PLOG_SLOT_FREE, memory_order_relaxed);
            }
            atomic_fetch_add_explicit(&lg->cons_seq, (uint64_t)batch, memory_order_release);
            atomic_fetch_sub_explicit(&lg->pending, (uint64_t)batch, memory_order_release);
        } else {
            /* Wait briefly for a concurrent producer to finish writing to its claimed slot */
            usleep(10);
        }
    }

    return NULL;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/**
 * Initialises the logger and starts the background drain thread.
 *
 * @param lg     Caller-allocated PlogState (static or global).
 * @param out_fd Destination file descriptor (e.g. STDOUT_FILENO).
 * @return true on success, false if the drain thread could not be created.
 * @note   Not thread-safe.  Call once before any plog_submit().
 */
static inline bool plog_init(PlogState* lg, int out_fd) {
    *lg = (PlogState){0};
    lg->out_fd = out_fd;

    lock_init(&lg->mu);
    cond_init(&lg->wake);
    atomic_store_explicit(&lg->drain_running, true, memory_order_release);

    return thread_create(&lg->thread_handle, plog__drain_thread, lg) == 0;
}

/**
 * Submits a pre-formatted log line to the async ring.
 *
 * Hot path: no heap allocation, no spin loop, no blocking I/O.
 * On an uncontended ring the only shared writes are one fetch-add
 * (prod_seq), one CAS (slot state), and one fetch-add (pending).
 *
 * @param lg   Logger initialised with plog_init().
 * @param buf  Formatted text.  Need not be NUL-terminated.
 * @param len  Byte length.  Silently clamped to PLOG_LINE_MAX.
 * @note  Safe for concurrent use by multiple threads.
 */
static inline void plog_submit(PlogState* lg, const char* buf, uint32_t len) {
    if (len > PLOG_LINE_MAX) len = PLOG_LINE_MAX;

    /* Cache cons_seq in a local variable/register.
     * By doing so, we completely bypass reloading it on CAS failure retries,
     * eliminating unnecessary memory accesses and LSU pressure inside the loop. */
    uint64_t cons = atomic_load_explicit(&lg->cons_seq, memory_order_relaxed);
    uint64_t prod = atomic_load_explicit(&lg->prod_seq, memory_order_relaxed);

    while (true) {
        /* Since cons is cached, this check runs entirely in registers.
         * If the queue appears full, we do a fresh acquire load to check if
         * the consumer has indeed advanced. */
        if (prod - cons >= (uint64_t)PLOG_RING_CAPACITY) {
            cons = atomic_load_explicit(&lg->cons_seq, memory_order_acquire);
            if (prod - cons >= (uint64_t)PLOG_RING_CAPACITY) {
                atomic_fetch_add_explicit(&lg->drops, 1, memory_order_relaxed);
                return;
            }
        }

        /* Try to claim our sequence number. On failure, 'prod' is automatically
         * updated to the latest 'prod_seq' value, and we loop back. */
        if (atomic_compare_exchange_weak_explicit(&lg->prod_seq, &prod, prod + 1, memory_order_relaxed,
                                                  memory_order_relaxed)) {
            break;
        }
    }

    size_t idx = plog__idx(prod);
    PlogSlot* slot = &lg->ring[idx];

    /* Slot is exclusively ours. Copy raw payload. */
    __builtin_memcpy(slot->line, buf, len);
    slot->len = len;

    /* Release payload before storing READY status so consumer reads valid data. */
    atomic_store_explicit(&slot->state, PLOG_SLOT_READY, memory_order_release);

    /* Increment outstanding entries. */
    uint64_t prev_pending = atomic_fetch_add_explicit(&lg->pending, 1, memory_order_release);

    /* Wake the consumer ONLY if the queue transitioned from empty to active.
     * Bypasses heavy mutex/cond lock paths under sustained high loads. */
    if (prev_pending == 0) {
        lock_acquire(&lg->mu);
        cond_signal(&lg->wake);
        lock_release(&lg->mu);
    }
}

/**
 * Stops the drain thread, flushes all buffered entries, and releases
 * resources.
 *
 * @param lg Logger previously initialised with plog_init().
 * @note  Not thread-safe.  Call after all plog_submit() calls have returned.
 */
static inline void plog_destroy(PlogState* lg) {
    atomic_store_explicit(&lg->drain_running, false, memory_order_release);

    /* Hold the mutex across the signal so the drain thread cannot miss it
     * while transitioning into cond_wait. */
    lock_acquire(&lg->mu);
    cond_signal(&lg->wake);
    lock_release(&lg->mu);

    thread_join(lg->thread_handle, NULL);

    lock_free(&lg->mu);
    cond_free(&lg->wake);
}

/**
 * Returns the cumulative number of log entries dropped due to backpressure.
 *
 * A non-zero value means PLOG_RING_CAPACITY should be increased, or the
 * drain fd is too slow (e.g. a synchronous file on a busy disk).
 *
 * @param lg Logger instance.
 * @return   Drop count since plog_init().
 */
static inline uint64_t plog_drop_count(const PlogState* lg) {
    return atomic_load_explicit((_Atomic uint64_t*)&lg->drops, memory_order_relaxed);
}

#endif /* PLOG_H */
