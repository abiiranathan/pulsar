#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

/* ============================================================================
 * threadpool.c — Work-Stealing Threadpool
 * ============================================================================
 *
 * ARCHITECTURE
 * ------------
 *
 *   submitter(s)                      N workers, each owning a private deque
 *        │                          ┌────────────────────────────────────┐
 *        │  threadpool_submit(_batch)│ W0   W1   W2  ...  Wn-1            │
 *        ▼                           │ ▲    ▲    ▲         ▲              │
 *   ┌──────────────────┐   batch     │ │    │    │ steal   │              │
 *   │  GlobalQueue gq   │──pull(64)──▶│ │    │    │ (CAS)   │              │
 *   │  mutex + ring     │             │ ▼    ▼    ▼         ▼              │
 *   └──────────────────┘             │ LIFO pop / FIFO steal deques       │
 *        ▲                           └────────────────────────────────────┘
 *        └──────── unpark_n / cascade wakeups ◀───── worker_park on idle
 *
 * Every worker owns a Chase-Lev work-stealing deque:
 *
 *   OWNER  — pushes and pops at BOTTOM.  No lock; a release store publishes.
 *   THIEVES— steal from TOP via a seq_cst CAS.  Losers retry elsewhere.
 *
 * External threads push into GlobalQueue, a mutex-protected MPMC ring.
 * Workers drain it in batches of BATCH_SIZE: the first task executes
 * immediately, the rest are pushed onto the thief's own deque so the cost
 * of one mutex acquisition amortises over up to BATCH_SIZE tasks.
 *
 * MEMORY LAYOUT / FALSE SHARING
 * -----------------------------
 * Every hot field sits on its own cache line (CACHE_ALIGNED):
 *   - WorkStealDeque.bottom (owner-written only) and .top (CAS by thieves)
 *     live on separate lines so owner pops never bounce against steals.
 *   - Each worker struct is line-aligned; workers[] entries are pointers,
 *     so scanning victims touches only their deque headers.
 *   - park_lock / num_parked / idle_lock / num_pending each get their own
 *     line inside Threadpool.
 *
 * THE OWNERSHIP INVARIANT — num_pending
 * -------------------------------------
 * A single atomic counter, num_pending, counts tasks that have been
 * accepted but not yet completed.  It is the SOLE source of truth for
 * idleness ("num_pending == 0") used by threadpool_wait(), destroy() and
 * worker parking.  Two rules make that sound:
 *
 *   1. Credit BEFORE enqueue.  Submitters increment num_pending before the
 *      task becomes visible to any consumer (and debit for tasks rejected
 *      due to shutdown/overflow).  A task therefore never exists without
 *      outstanding credit, so pending can never hit zero early.  This also
 *      makes the accounting wrap-proof: a completion decrement can never
 *      race below zero on a task that has not been credited yet.
 *
 *   2. Debit at completion, in batches.  Workers accumulate completions in
 *      local_done and flush to num_pending every PENDING_FLUSH_BATCH tasks
 *      or at drain points (no work found / before parking / exit).  Pending
 *      may be OVERSTATED between flushes (waiters just wait slightly
 *      longer); it can never be understated, which is what correctness
 *      requires.  Batching keeps the shared line off the per-task path.
 *
 * This design eliminated an entire class of false-idle races that plagued
 * earlier revisions (Bug #4/Bug #5): those scanned gq head/tail and every
 * deque's bottom/top to decide idleness, and transient states mid-pop /
 * mid-steal / mid-batch-distribution made "queues look empty while a task
 * is in flight" observable.  With num_pending, no queue inspection is
 * needed at all.
 *
 * PARKING & THE WAKEUP PROTOCOL
 * -----------------------------
 * Idle workers first run an exponential PAUSE backoff (YIELD_THRESHOLD
 * rounds), then park on Condition work_available under park_lock.
 *
 *   Bug #6 (lost wakeup): a racing submitter and a parking worker can both
 *   observe stale zeros on two DIFFERENT variables (pending vs parked)
 *   unless their four ops share a total order.  The fix marks exactly four
 *   operations seq_cst — worker_park's parked++, its pending check, the
 *   submitter's pending++, and unpark_*'s parked read.  If the worker's
 *   check reads pre-increment pending, seq_cst order forces the submitter's
 *   later parked read to see >0, so a signal is guaranteed.  On x86 this is
 *   free: seq_cst loads are plain MOV and the RMW was already LOCK'd.
 *
 * Wakeup volume scales with work size:
 *   - threadpool_submit():       wakes ONE worker.
 *   - threadpool_submit_batch(): wakes count/BATCH_SIZE + 1 workers (Perf
 *     #7a) — waking a single worker let it drain entire multi-thousand-task
 *     submissions alone at single-thread speed.
 *   - try_steal() after pulling a global-queue batch wakes one more worker
 *     (cascade propagation), giving O(work) fan-out with zero extra
 *     submission-side signalling.
 *
 * Bug #7 (producer deadlock): when the global queue fills, submitters
 * sleep on Condition not_full — but consumers were only woken after the
 * whole submission finished streaming.  A batch larger than GLOBAL_Q_SIZE
 * deadlocked whenever all workers had already parked.  Producers now call
 * unpark_all() immediately before cond_wait(not_full).
 *
 * IDLE DETECTION FOR WAITERS
 * --------------------------
 * Completing workers broadcast all_idle under idle_lock when their flush
 * drives num_pending to 0.  threadpool_wait() first checks the fast path,
 * then adaptively spins ~ADAPTIVE_SPIN_NS polling pending (Perf #8 — in
 * ping-pong workloads >60% of wall time was futex sys-time), then falls
 * back to cond_wait.  The broadcast-under-idle_lock handshake makes the
 * slow path lossless: a completing worker cannot emit the final broadcast
 * between the waiter's predicate check and its sleep.
 *
 * BACKOFF POLICY (Perf #9)
 * ------------------------
 * strace profiling showed the previous middle tier of sched_yield() calls
 * cost ~16 yield syscalls (~45us service time each) per submitted task —
 * losing threads paid kernel timeslices to retry almost immediately.  The
 * backoff is now pure PAUSE loops (2..256 pauses) followed directly by a
 * proper park; measured ping-pong latency improved 13x at 1 worker.
 *
 * BUG HISTORY (abridged; see inline comments)
 * -------------------------------------------
 *  #1 external+worker concurrent deque_push_bottom corruption -> GlobalQueue
 *  #2 stale TLS worker index across pool lifetimes            -> SIZE_MAX guard
 *  #3 steal before workers[] fully populated                  -> startup barrier
 *  #4/#5 false-idle races orphaning tasks                     -> num_pending redesign
 *  #6 lost wakeup across two variables                        -> seq_cst quartet
 *  #7 producer deadlock on full queue                         -> unpark before sleep
 *
 * TUNABLES
 * --------
 *   DEQUE_SIZE           private deque capacity (power of 2).  16384.
 *   GLOBAL_Q_SIZE        shared queue capacity (power of 2).    65536.
 *                        Note: submissions larger than this stream through
 *                        in chunks and block on not_full when full.
 *   BATCH_SIZE           tasks pulled from the global queue per lock hold.
 *   PENDING_FLUSH_BATCH  completions accumulated before flushing the
 *                        shared pending counter.
 *   YIELD_THRESHOLD      PAUSE-backoff rounds before parking.
 *   ADAPTIVE_SPIN_NS     bounded poll duration in threadpool_wait().
 *
 * BENCHMARK EVIDENCE (see benchmarks/threadpool_micro.c)
 * ------------------------------------------------------
 *   pingpong (submit 1 task + wait):      4034ns -> 304ns @1T (13x)
 *   burst drain tail (65536 no-op tasks): deadlock-free, ~0.9ms @8T
 *   mproducers (4x262144 tiny tasks):     33ns/task @2T -> 20ns/task @8T
 *   granular sweep:                       4.6x @2T .. 6.7x @8T for >=220ns
 *                                         tasks; <25ns tasks are producer-bound
 * ============================================================================ */

#include "../include/threadpool.h"

#include "../include/align.h"
#include "../include/aligned_alloc.h"
#include "../include/lock.h"
#include "../include/spinlock.h"
#include "../include/thread.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
    #include "../include/platform.h"
    #define thread_yield() SwitchToThread()
#else
    #include <sched.h>
    #include <unistd.h>
    #define thread_yield() sched_yield()
#endif

/* ── Hardware hints ──────────────────────────────────────────────────────── */
#ifndef cpu_relax
    #if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
        #if defined(_MSC_VER)
            #include <intrin.h>
            #define cpu_relax() _mm_pause()
        #else
            #define cpu_relax() __builtin_ia32_pause()
        #endif
    #elif defined(__aarch64__) || defined(__arm__)
        #define cpu_relax() __asm__ __volatile__("yield" ::: "memory")
    #else
        #define cpu_relax() ((void)0)
    #endif
#endif

#define DEQUE_SIZE    (1u << 14) /* 16384 slots per private deque */
#define DEQUE_MASK    (DEQUE_SIZE - 1)
#define GLOBAL_Q_SIZE (1u << 16) /* 65536 slots in global queue   */
#define GLOBAL_Q_MASK (GLOBAL_Q_SIZE - 1)

#ifndef BATCH_SIZE
    #define BATCH_SIZE 64
#endif

#define PENDING_FLUSH_BATCH 64
#define CACHE_LINE_SIZE     64
#define YIELD_THRESHOLD     8
#define CACHE_ALIGNED       ALIGN(CACHE_LINE_SIZE)

typedef enum { STEAL_SUCCESS, STEAL_EMPTY, STEAL_ABORT } StealResult;

/* ── Chase-Lev private deque ─────────────────────────────────────────────── */
/*
 * Single-producer (owner), multi-consumer LIFO/FIFO deque.
 *
 *   bottom: written ONLY by the owner (relaxed reads, release writes).
 *   top:    read by everyone; advanced by owner (last-item pop) and thieves
 *           via seq_cst CAS — the linearisation point of every removal.
 *
 * Indices are unbounded size_t; only b - t is meaningful, so wraparound at
 * 2^64 is harmless.  Slots are addressed with & DEQUE_MASK.
 */
typedef struct {
    CACHE_ALIGNED atomic_size_t bottom;
    CACHE_ALIGNED atomic_size_t top;
    CACHE_ALIGNED Task tasks[DEQUE_SIZE];
} WorkStealDeque;

/* ── Global submission queue ─────────────────────────────────────────────── */
/*
 * Mutex-protected MPMC ring for external submitters (and overflow from
 * worker-side batch submission).  head/tail are uint32_t counters stored
 * MASKED; all arithmetic is done on (h - t) & GLOBAL_Q_MASK so wraparound
 * is safe.  One slot of capacity is sacrificed as the full/empty sentinel.
 *
 * not_full: producers blocked because the ring filled.  Consumers broadcast
 * after every successful pull; producers also unpark consumers before
 * sleeping here (Bug #7).
 */
typedef struct {
    CACHE_ALIGNED Lock mutex;
    CACHE_ALIGNED atomic_uint head;
    CACHE_ALIGNED atomic_uint tail;
    CACHE_ALIGNED Task tasks[GLOBAL_Q_SIZE];
    Condition not_full;
    struct Threadpool* pool;
} GlobalQueue;

/* ── Per-worker ──────────────────────────────────────────────────────────── */
typedef struct worker {
    CACHE_ALIGNED WorkStealDeque deque;
    CACHE_ALIGNED Thread pthread;
    CACHE_ALIGNED size_t index;
    struct Threadpool* pool;
} worker;

/* ── Threadpool ──────────────────────────────────────────────────────────── */
/*
 * shutdown         set by destroy(); workers exit their loop after observing
 *                  it.  seq_cst store, acquire reads.
 * num_threads_alive workers decrement on exit; destroy spins until zero.
 * workers_ready    startup barrier: each worker increments before entering
 *                  its main loop and spins until the count reaches
 *                  num_workers, guaranteeing no worker steals from a
 *                  half-initialised workers[] (Bug #3).
 * num_pending      outstanding-task counter — see ownership invariant in
 *                  the file header.  Sole idle predicate.
 */
struct Threadpool {
    CACHE_ALIGNED atomic_int shutdown;
    CACHE_ALIGNED atomic_int num_threads_alive;

    CACHE_ALIGNED worker** workers;
    CACHE_ALIGNED size_t num_workers;

    /* Startup barrier */
    CACHE_ALIGNED atomic_size_t workers_ready;

    CACHE_ALIGNED GlobalQueue gq;

    /* Parking */
    CACHE_ALIGNED Lock park_lock;
    CACHE_ALIGNED atomic_int num_parked;
    Condition work_available;

    /* Idle detection */
    CACHE_ALIGNED Lock idle_lock;
    CACHE_ALIGNED atomic_size_t num_pending;
    Condition all_idle;
};

/* TLS: SIZE_MAX = external thread; anything else = worker index */
static _Thread_local size_t tls_worker_index = SIZE_MAX;

/* ============================================================================
 * Global Queue (Batch-Optimized Direct Streaming)
 * ============================================================================ */

static inline void unpark_all(Threadpool* pool); /* Bug #7: used by full-queue wait below */

static void gq_init(GlobalQueue* gq, struct Threadpool* pool) {
    lock_init(&gq->mutex);
    cond_init(&gq->not_full);
    atomic_store_explicit(&gq->head, 0, memory_order_relaxed);
    atomic_store_explicit(&gq->tail, 0, memory_order_relaxed);
    gq->pool = pool;
}

static void gq_destroy(GlobalQueue* gq) {
    lock_free(&gq->mutex);
    cond_free(&gq->not_full);
}

/**
 * gq_push — push one task, blocking while the ring is full.
 *
 * Only reached from threadpool_submit() (single-task path) and the rare
 * deque-overflow spill in try_steal().  Before sleeping on a full ring the
 * producer wakes all consumers (Bug #7): they are the only ones who can
 * make progress on our behalf.
 */
static bool gq_push(GlobalQueue* gq, Task task) {
    lock_acquire(&gq->mutex);

    while (((atomic_load_explicit(&gq->head, memory_order_relaxed) + 1) & GLOBAL_Q_MASK) ==
           atomic_load_explicit(&gq->tail, memory_order_relaxed)) {
        if (atomic_load_explicit(&gq->pool->shutdown, memory_order_acquire)) {
            lock_release(&gq->mutex);
            return false;
        }
        unpark_all(gq->pool); /* Bug #7: wake consumers before sleeping full */
        cond_wait(&gq->not_full, &gq->mutex);
    }

    uint32_t h = atomic_load_explicit(&gq->head, memory_order_relaxed);
    gq->tasks[h] = task;
    atomic_store_explicit(&gq->head, (h + 1) & GLOBAL_Q_MASK, memory_order_release);
    lock_release(&gq->mutex);
    return true;
}

/** Zero-Allocation, Zero-Copy Direct Stream into Global Queue.
 *
 * NULL function slots are silently skipped so callers may pass sparse
 * arrays.  The return value counts only tasks actually enqueued, which
 * keeps num_pending credit/debit balanced at every call site. */
static size_t gq_push_batch_direct(GlobalQueue* gq, void (**functions)(void*), void** args, size_t count) {
    size_t done = 0;   /* caller-array slots consumed                   */
    size_t pushed = 0; /* non-NULL tasks actually enqueued (returned)   */

    while (done < count) {
        /* Compact leading NULLs out of the remaining window first. */
        while (done < count && !functions[done]) done++;
        if (done >= count) break;

        lock_acquire(&gq->mutex);

        while (((atomic_load_explicit(&gq->head, memory_order_relaxed) + 1) & GLOBAL_Q_MASK) ==
               atomic_load_explicit(&gq->tail, memory_order_relaxed)) {
            if (atomic_load_explicit(&gq->pool->shutdown, memory_order_acquire)) {
                lock_release(&gq->mutex);
                return pushed;
            }
            /*
             * Bug #7 (deadlock): we are about to sleep on a FULL queue, but
             * consumers are only signalled AFTER submit_batch() finishes
             * streaming.  A batch larger than the queue therefore deadlocks
             * here whenever every worker managed to park before this point:
             * we wait for a drain that nobody was woken to perform.
             * Wake consumers BEFORE sleeping — they will drain the queue
             * and broadcast not_full back to us.
             */
            unpark_all(gq->pool);
            cond_wait(&gq->not_full, &gq->mutex);
        }

        uint32_t h = atomic_load_explicit(&gq->head, memory_order_relaxed);
        uint32_t t = atomic_load_explicit(&gq->tail, memory_order_relaxed);
        size_t free_slots = (GLOBAL_Q_SIZE - 1) - ((h - t) & GLOBAL_Q_MASK);

        /* Pack as many non-NULL entries as fit in one hold of the lock.
         * At least one fits: functions[done] is non-NULL and the queue
         * has room, so progress per iteration is guaranteed. */
        size_t i = done;
        size_t n = 0;
        while (i < count && n < free_slots) {
            if (functions[i]) {
                gq->tasks[(h + n) & GLOBAL_Q_MASK] = (Task){functions[i], args ? args[i] : NULL};
                n++;
            }
            i++;
        }

        atomic_store_explicit(&gq->head, (h + (uint32_t)n) & GLOBAL_Q_MASK, memory_order_release);
        pushed += n;
        done = i;

        lock_release(&gq->mutex);
    }

    return pushed;
}

/**
 * gq_pull_batch — remove up to @p max tasks in one mutex hold.
 *
 * Returns the number taken, 0 when empty, or -1 when empty AND shut down
 * (the caller treats -1 as "no more work will ever arrive").  Broadcasts
 * not_full unconditionally after taking tasks: glibc condvars make this a
 * no-op when no producers wait, and it is what guarantees blocked
 * producers eventually proceed.
 */
static int gq_pull_batch(GlobalQueue* gq, Task* out, size_t max) {
    lock_acquire(&gq->mutex);

    uint32_t h = atomic_load_explicit(&gq->head, memory_order_relaxed);
    uint32_t t = atomic_load_explicit(&gq->tail, memory_order_relaxed);

    if (h == t) {
        lock_release(&gq->mutex);
        return atomic_load_explicit(&gq->pool->shutdown, memory_order_acquire) ? -1 : 0;
    }

    size_t available = (h - t) & GLOBAL_Q_MASK;
    size_t to_take = available < max ? available : max;

    for (size_t i = 0; i < to_take; i++) {
        out[i] = gq->tasks[(t + i) & GLOBAL_Q_MASK];
    }
    atomic_store_explicit(&gq->tail, (t + (uint32_t)to_take) & GLOBAL_Q_MASK, memory_order_release);

    cond_broadcast(&gq->not_full);
    lock_release(&gq->mutex);
    return (int)to_take;
}

/* ============================================================================
 * Chase-Lev Deque
 * ============================================================================ */

static void deque_init(WorkStealDeque* dq) {
    atomic_store_explicit(&dq->bottom, 0, memory_order_relaxed);
    atomic_store_explicit(&dq->top, 0, memory_order_relaxed);
}

/**
 * deque_push_bottom — owner only.  Release store publishes both the slot
 * contents and the new index; thieves reading top with acquire either see
 * the task or don't see the incremented count at all.
 * Returns false only when full (b - t >= DEQUE_SIZE; practically
 * unreachable at 16384 slots, but handled).
 */
static inline bool deque_push_bottom(WorkStealDeque* dq, Task task) {
    size_t b = atomic_load_explicit(&dq->bottom, memory_order_relaxed);
    size_t t = atomic_load_explicit(&dq->top, memory_order_acquire);

    if (b - t >= DEQUE_SIZE) return false;

    dq->tasks[b & DEQUE_MASK] = task;
    atomic_store_explicit(&dq->bottom, b + 1, memory_order_release);
    return true;
}

/**
 * deque_pop_bottom — owner reclaims its own newest task.
 *
 * Protocol: decrement bottom with a seq_cst store, then read top with a
 * seq_cst load.  The seq_cst pair is what synchronises against a thief's
 * seq_cst CAS on top — exactly one of {owner pop, thief steal} can win the
 * last item:
 *   b - t > 0 after decrement : more items remain, no race possible.
 *   b == t                    : last item; owner must CAS top to claim it.
 *   b < t                     : a thief stole it while we decremented;
 *                               restore bottom and report failure.
 */
static inline bool deque_pop_bottom(WorkStealDeque* dq, Task* out) {
    size_t b = atomic_load_explicit(&dq->bottom, memory_order_relaxed);
    size_t t = atomic_load_explicit(&dq->top, memory_order_acquire);

    if ((ptrdiff_t)(b - t) <= 0) return false;

    b--;
    atomic_store_explicit(&dq->bottom, b, memory_order_seq_cst);
    t = atomic_load_explicit(&dq->top, memory_order_seq_cst);

    if ((ptrdiff_t)(b - t) > 0) {
        *out = dq->tasks[b & DEQUE_MASK];
        return true;
    }

    if (b == t) {
        *out = dq->tasks[b & DEQUE_MASK];
        size_t expected = t;
        bool won = atomic_compare_exchange_strong_explicit(&dq->top, &expected, t + 1, memory_order_seq_cst,
                                                           memory_order_relaxed);
        atomic_store_explicit(&dq->bottom, b + 1, memory_order_relaxed);
        return won;
    }

    atomic_store_explicit(&dq->bottom, b + 1, memory_order_relaxed);
    return false;
}

/**
 * deque_steal_top — any thread except the owner.
 *
 * Reads top then bottom (both acquire), copies the slot, and commits with
 * a seq_cst CAS on top.  STEAL_ABORT means the CAS lost (owner popped or
 * another thief won) — the caller simply tries the next victim.
 */
static inline StealResult deque_steal_top(WorkStealDeque* dq, Task* out) {
    size_t t = atomic_load_explicit(&dq->top, memory_order_acquire);
    size_t b = atomic_load_explicit(&dq->bottom, memory_order_acquire);

    if ((ptrdiff_t)(b - t) <= 0) return STEAL_EMPTY;

    *out = dq->tasks[t & DEQUE_MASK];

    if (!atomic_compare_exchange_strong_explicit(&dq->top, &t, t + 1, memory_order_seq_cst, memory_order_relaxed)) {
        return STEAL_ABORT;
    }
    return STEAL_SUCCESS;
}

/* ============================================================================
 * Parking
 * ============================================================================ */

static void worker_park(Threadpool* pool) {
    /*
     * Lost-wakeup proof (Bug #6): the four ops below — our parked++ and
     * pending check here, plus the submitter's pending++ and parked read
     * in unpark_*() — must be seq_cst so they share one total order.
     *
     * Suppose our pending check reads 0 (pre-increment value of a racing
     * submitter).  Seq_cst program order then forces:
     *   parked++ < pending-check < submitter's pending++ < its parked read,
     * so the submitter MUST observe num_parked > 0 and signal us.
     * Relaxed/acquire on either side allows both sides to see stale zeros
     * and the worker would sleep through work that already arrived.
     *
     * On x86 this costs nothing: seq_cst loads compile to plain MOV and
     * the RMW was already a LOCK'd instruction.
     */
    atomic_fetch_add_explicit(&pool->num_parked, 1, memory_order_seq_cst);
    lock_acquire(&pool->park_lock);

    /* Direct pending check avoids scanning every worker's deque headers */
    bool has_work = (atomic_load_explicit(&pool->num_pending, memory_order_seq_cst) > 0);

    if (!has_work && !atomic_load_explicit(&pool->shutdown, memory_order_acquire)) {
        cond_wait(&pool->work_available, &pool->park_lock);
    }

    lock_release(&pool->park_lock);
    atomic_fetch_sub_explicit(&pool->num_parked, 1, memory_order_relaxed);
}

static inline void unpark_one(Threadpool* pool) {
    if (atomic_load_explicit(&pool->num_parked, memory_order_seq_cst) > 0) {
        lock_acquire(&pool->park_lock);
        cond_signal(&pool->work_available);
        lock_release(&pool->park_lock);
    }
}

/**
 * unpark_n — wake up to @p n parked workers under ONE park_lock acquisition
 * (Perf #7a).
 *
 * Waking a single worker per submission was sufficient when tasks were
 * heavy, but with light tasks that worker drains an entire submission
 * alone: it pulls BATCH_SIZE, executes in microseconds, repeats — while
 * everyone else sleeps.  Throughput then plateaus at single-worker speed.
 * Waking proportionally to the work size restores parallel drain; excess
 * signals are harmless (awakened workers finding no work re-park).
 *
 * Uses cond_broadcast when waking most or all parked workers (cheaper than
 * n individual signals), else a bounded signal loop.
 */
static inline void unpark_n(Threadpool* pool, size_t n) {
    int parked = atomic_load_explicit(&pool->num_parked, memory_order_seq_cst);
    if (parked <= 0) return;

    lock_acquire(&pool->park_lock);
    if ((size_t)parked <= n && parked > 1) {
        cond_broadcast(&pool->work_available);
    } else {
        if ((size_t)parked > n) parked = (int)n;
        while (parked-- > 0) {
            cond_signal(&pool->work_available);
        }
    }
    lock_release(&pool->park_lock);
}

static inline void unpark_all(Threadpool* pool) {
    lock_acquire(&pool->park_lock);
    cond_broadcast(&pool->work_available);
    lock_release(&pool->park_lock);
}

/* ============================================================================
 * Steal Engine (Modulo-Free Victim Selection)
 * ============================================================================ */

/**
 * try_steal — find work when our own deque is empty.
 *
 * 1. Scan victims in a randomised order.  Each worker keeps a private
 *    xorshift64 PRNG (register-local, zero synchronisation); the start
 *    index is derived with Lemire's multiply-shift reduction, avoiding a
 *    division per call.  Wraparound is an increment-and-compare rather
 *    than a modulo.
 *
 * 2. On failure, drain up to BATCH_SIZE tasks from the global queue under
 *    one mutex acquisition (Perf #1).  The first executes immediately; the
 *    rest are pushed to our own deque so subsequent iterations are
 *    lock-free pops from bottom.
 *
 * Cascade wakeup: after a successful global-queue pull we unpark_one() so
 * remaining queued work drains in parallel — the woken worker repeats this
 * on its own pull, giving O(work) propagation without extra submission-
 * side signalling.
 */
static bool try_steal(worker* self, Task* out) {
    Threadpool* pool = self->pool;
    size_t n = pool->num_workers;

    static _Thread_local uint64_t rng = 0;
    if (rng == 0) rng = ((uint64_t)self->index + 1) * 6364136223846793005ULL;
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;

    /* Lemire's fast reduction replaces integer division with multiply+shift */
    size_t start = (size_t)(((uint64_t)(uint32_t)rng * (uint64_t)n) >> 32);

    /* 1. Lock-free steal from private deques */
    size_t v = start;
    for (size_t i = 0; i < n; i++) {
        if (v != self->index) {
            StealResult r = deque_steal_top(&pool->workers[v]->deque, out);
            if (r == STEAL_SUCCESS) return true;
        }
        if (++v >= n) v = 0;
    }

    /* 2. Batch drain from global queue */
    Task batch[BATCH_SIZE];
    int got = gq_pull_batch(&pool->gq, batch, BATCH_SIZE);
    if (got <= 0) return false;

    unpark_one(pool);

    for (int i = 1; i < got; i++) {
        if (!deque_push_bottom(&self->deque, batch[i])) {
            for (int j = i; j < got; j++) {
                gq_push(&pool->gq, batch[j]);
            }
            break;
        }
    }

    *out = batch[0];
    return true;
}

/* ============================================================================
 * Worker Loop
 * ============================================================================ */

/**
 * worker_thread — the worker main loop.
 *
 * Priority order per iteration:
 *   1. pop our own deque (LIFO — best cache locality, no synchronisation)
 *   2. steal from a victim deque / drain the global queue (try_steal)
 *   3. flush pending-completion balance (drain point)
 *   4. exponential PAUSE backoff, growing 2..256 pauses
 *   5. park on work_available until signalled
 *
 * Completion accounting: each executed task increments local_done; the
 * shared num_pending is decremented in PENDING_FLUSH_BATCH chunks or at
 * the drain point above, whichever comes first.  A flush that drives the
 * global count to zero broadcasts all_idle under idle_lock so waiters in
 * threadpool_wait()/destroy() wake.  See the ownership invariant in the
 * file header for why this batching is safe.
 */
static void* worker_thread(void* arg) {
    worker* self = (worker*)arg;
    Threadpool* pool = self->pool;
    Task task;
    int spin = 0;
    size_t local_done = 0;

    tls_worker_index = self->index;

    atomic_fetch_add_explicit(&pool->workers_ready, 1, memory_order_release);
    while (atomic_load_explicit(&pool->workers_ready, memory_order_acquire) < pool->num_workers) {
        thread_yield();
    }

    atomic_fetch_add_explicit(&pool->num_threads_alive, 1, memory_order_relaxed);

    while (!atomic_load_explicit(&pool->shutdown, memory_order_acquire)) {
        if (deque_pop_bottom(&self->deque, &task)) goto execute;

        if (try_steal(self, &task)) goto execute;

        /* Drain point: publish completions so wait()/destroy() never lag */
        if (local_done) {
            size_t done = local_done;
            local_done = 0;
            size_t pending = atomic_fetch_sub_explicit(&pool->num_pending, done, memory_order_acq_rel) - done;
            if (pending == 0) {
                lock_acquire(&pool->idle_lock);
                if (atomic_load_explicit(&pool->num_pending, memory_order_relaxed) == 0) {
                    cond_broadcast(&pool->all_idle);
                }
                lock_release(&pool->idle_lock);
            }
        }

        /*
         * Exponential PAUSE backoff, then park (Perf #9).
         *
         * An earlier tier called sched_yield() between pauses and parking;
         * strace showed ~16 yield syscalls per submitted task with a ~45us
         * average service time — losing threads were paying kernel time
         * slices for the privilege of trying again almost immediately.
         * Pure pause-spinning bounded by YIELD_THRESHOLD followed by a
         * proper park gives the same latency benefit at a fraction of the
         * system cost.
         */
        if (spin < YIELD_THRESHOLD) {
            spin++;
            int pauses = 1 << spin;
            for (int k = 0; k < pauses; k++) {
                cpu_relax();
            }
            continue;
        }

        spin = 0;
        worker_park(pool);
        continue;

    execute:
        spin = 0;
        task.function(task.arg);

        if (++local_done >= PENDING_FLUSH_BATCH) {
            size_t done = local_done;
            local_done = 0;
            size_t pending = atomic_fetch_sub_explicit(&pool->num_pending, done, memory_order_acq_rel) - done;
            if (pending == 0) {
                lock_acquire(&pool->idle_lock);
                if (atomic_load_explicit(&pool->num_pending, memory_order_relaxed) == 0) {
                    cond_broadcast(&pool->all_idle);
                }
                lock_release(&pool->idle_lock);
            }
        }
    }

    if (local_done) {
        atomic_fetch_sub_explicit(&pool->num_pending, local_done, memory_order_acq_rel);
    }

    int alive = atomic_fetch_sub_explicit(&pool->num_threads_alive, 1, memory_order_acq_rel) - 1;
    if (alive == 0) {
        lock_acquire(&pool->idle_lock);
        cond_broadcast(&pool->all_idle);
        lock_release(&pool->idle_lock);
    }

    return NULL;
}

/* ============================================================================
 * Worker Init
 * ============================================================================ */

static int worker_init(Threadpool* pool, worker** w, size_t index) {
    *w = (worker*)ALIGNED_ALLOC(CACHE_LINE_SIZE, sizeof(worker));
    if (!*w) return -1;
    (*w)->pool = pool;
    (*w)->index = index;
    deque_init(&(*w)->deque);
    return thread_create(&(*w)->pthread, worker_thread, *w);
}

/* ============================================================================
 * Public API
 * ============================================================================ */

/**
 * threadpool_create — spawn @p num_threads workers (minimum 1).
 *
 * The pool struct and every worker are cache-line aligned.  Workers are
 * zeroed into the array BEFORE spawning so a partially-started cohort can
 * never dereference NULL entries (Bug #3); if any worker fails to start,
 * workers_ready is released, num_workers is truncated to the survivors,
 * and destroy(-1) tears the pool down cleanly.
 *
 * Returns the pool or NULL on allocation/thread failure.
 */
Threadpool* threadpool_create(size_t num_threads) {
    if (num_threads == 0) num_threads = 1;

    Threadpool* pool = (Threadpool*)ALIGNED_ALLOC(CACHE_LINE_SIZE, sizeof(Threadpool));
    if (!pool) return NULL;

    atomic_store_explicit(&pool->shutdown, 0, memory_order_relaxed);
    atomic_store_explicit(&pool->num_threads_alive, 0, memory_order_relaxed);
    atomic_store_explicit(&pool->num_parked, 0, memory_order_relaxed);
    atomic_store_explicit(&pool->num_pending, 0, memory_order_relaxed);
    atomic_store_explicit(&pool->workers_ready, 0, memory_order_relaxed);

    pool->num_workers = num_threads;
    gq_init(&pool->gq, pool);

    lock_init(&pool->park_lock);
    cond_init(&pool->work_available);
    lock_init(&pool->idle_lock);
    cond_init(&pool->all_idle);

    pool->workers = (worker**)malloc(num_threads * sizeof(worker*));
    if (!pool->workers) {
        gq_destroy(&pool->gq);
        lock_free(&pool->park_lock);
        cond_free(&pool->work_available);
        lock_free(&pool->idle_lock);
        cond_free(&pool->all_idle);
        free(pool);
        return NULL;
    }

    for (size_t i = 0; i < num_threads; i++) pool->workers[i] = NULL;

    for (size_t i = 0; i < num_threads; i++) {
        if (worker_init(pool, &pool->workers[i], i) != 0) {
            atomic_store_explicit(&pool->workers_ready, num_threads, memory_order_release);
            pool->num_workers = i;
            threadpool_destroy(pool, -1);
            return NULL;
        }
    }

    return pool;
}

/**
 * threadpool_submit — enqueue one task.
 *
 * Worker callers push directly onto their own deque (lock-free hot path);
 * external callers go through the global queue.  num_pending is credited
 * BEFORE the task becomes visible (ownership invariant rule 1) and debited
 * if the queue rejects the task due to shutdown.  Wakes one parked worker.
 */
bool threadpool_submit(Threadpool* pool, void (*function)(void*), void* arg) {
    if (!pool || !function) return false;

    Task task = {function, arg};
    atomic_fetch_add_explicit(&pool->num_pending, 1, memory_order_seq_cst);

    if (tls_worker_index != SIZE_MAX) {
        if (deque_push_bottom(&pool->workers[tls_worker_index]->deque, task)) {
            unpark_one(pool);
            return true;
        }
    }

    bool ok = gq_push(&pool->gq, task);
    if (ok) {
        unpark_one(pool);
    } else {
        atomic_fetch_sub_explicit(&pool->num_pending, 1, memory_order_relaxed);
    }
    return ok;
}

/**
 * threadpool_submit_batch — enqueue @p count tasks from flat arrays.
 *
 * NULL function entries are silently skipped; the return value is the
 * number of tasks actually enqueued, and num_pending is debited by
 * (count - pushed) so credit always matches live tasks exactly.
 *
 * Worker callers fill their own deque first, then stream the remainder
 * straight into the global queue with gq_push_batch_direct — no
 * intermediate allocation, ever.  External callers stream the whole batch
 * the same way.
 *
 * Wakes pushed/BATCH_SIZE + 1 parked workers (Perf #7a): proportional
 * wakeup is what keeps light-task throughput scaling instead of one worker
 * draining everything serially.
 */
size_t threadpool_submit_batch(Threadpool* pool, void (**functions)(void*), void** args, size_t count) {
    if (!pool || !functions || count == 0) return 0;

    if (tls_worker_index != SIZE_MAX) {
        atomic_fetch_add_explicit(&pool->num_pending, count, memory_order_seq_cst);

        size_t pushed = 0;
        for (size_t i = 0; i < count; i++) {
            if (!functions[i]) continue;
            Task task = {functions[i], args ? args[i] : NULL};
            if (deque_push_bottom(&pool->workers[tls_worker_index]->deque, task)) {
                pushed++;
            } else {
                pushed += gq_push_batch_direct(&pool->gq, &functions[i], args ? &args[i] : NULL, count - i);
                break;
            }
        }
        if (pushed < count) {
            atomic_fetch_sub_explicit(&pool->num_pending, count - pushed, memory_order_relaxed);
        }
        if (pushed > 0) unpark_n(pool, pushed / BATCH_SIZE + 1);
        return pushed;
    }

    /* External thread: Zero-alloc direct stream into global queue */
    atomic_fetch_add_explicit(&pool->num_pending, count, memory_order_seq_cst);
    size_t pushed = gq_push_batch_direct(&pool->gq, functions, args, count);
    if (pushed < count) {
        atomic_fetch_sub_explicit(&pool->num_pending, count - pushed, memory_order_relaxed);
    }

    if (pushed > 0) unpark_n(pool, pushed / BATCH_SIZE + 1);
    return pushed;
}

/*
 * Adaptive wait threshold (Perf #8): after a submit, the last task is
 * typically finished within a few microseconds.  Sleeping in threadpool_wait()
 * costs two futex transitions (block + wake) plus an idle broadcast from the
 * completing worker — measurable in sub-millisecond submit/wait cycles
 * (perf: >60% of wall time was sys-time in ping-pong workloads).
 *
 * Before blocking we therefore poll num_pending with PAUSE-backed spins for
 * roughly ADAPTIVE_SPIN_NS nanoseconds.  If the pool drains inside that
 * window we return without ANY syscall; otherwise we fall through to the
 * cond_wait slow path unchanged.
 */
#define ADAPTIVE_SPIN_NS 4000

/**
 * threadpool_wait — block until every accepted task has completed
 * (num_pending == 0).
 *
 * Fast path: a single acquire load when the pool is already idle.
 * Adaptive path: ~ADAPTIVE_SPIN_NS of PAUSE-backed polling (Perf #8) —
 * completions usually land within microseconds and this avoids two futex
 * transitions plus the completing worker's broadcast.
 * Slow path: cond_wait on all_idle.  Lossless by construction: the final
 * flush that drives pending to zero holds idle_lock while broadcasting,
 * so no wakeup can slip between our predicate check and our sleep.
 *
 * Safe to call concurrently with submissions from other threads; it waits
 * for tasks submitted before its final predicate check.
 */
void threadpool_wait(Threadpool* pool) {
    if (!pool) return;

    if (atomic_load_explicit(&pool->num_pending, memory_order_acquire) == 0) {
        return;
    }

    uint64_t spins = ADAPTIVE_SPIN_NS / 20; /* ~20ns per pause+load pair */
    do {
        if (atomic_load_explicit(&pool->num_pending, memory_order_acquire) == 0) {
            return;
        }
        cpu_relax();
    } while (--spins);

    lock_acquire(&pool->idle_lock);
    while (atomic_load_explicit(&pool->num_pending, memory_order_relaxed) != 0) {
        cond_wait(&pool->all_idle, &pool->idle_lock);
    }
    lock_release(&pool->idle_lock);
}

/**
 * threadpool_destroy — drain, stop, and free the pool.
 *
 * Phase 1 (drain): wait for num_pending == 0.
 *   timeout_ms <  0 : block indefinitely; every completion flush that hits
 *                     zero broadcasts all_idle, so this is lossless.
 *   timeout_ms >= 0 : wait up to @p timeout_ms per cond_wait cycle and
 *                     abandon the drain on expiry — tasks still queued are
 *                     then discarded by phase 2 without being executed.
 *
 * Phase 2 (shutdown): store shutdown=1 (seq_cst), then repeatedly
 * unpark_all() while workers exit.  The loop also covers workers blocked
 * in gq_push/gq_pull_batch: those observe shutdown after waking from
 * not_full and return failure to their callers.
 *
 * Phase 3 (join + teardown): join every worker, free per-worker structs,
 * destroy primitives, free the pool.  NULL-safe.
 */
void threadpool_destroy(Threadpool* pool, int timeout_ms) {
    if (!pool) return;

    if (timeout_ms >= 0) {
        lock_acquire(&pool->idle_lock);
        while (atomic_load_explicit(&pool->num_pending, memory_order_relaxed) != 0) {
            int r = cond_wait_timeout(&pool->all_idle, &pool->idle_lock, timeout_ms);
            if (r != 0) break;
        }
        lock_release(&pool->idle_lock);
    } else {
        lock_acquire(&pool->idle_lock);
        while (atomic_load_explicit(&pool->num_pending, memory_order_relaxed) != 0) {
            cond_wait(&pool->all_idle, &pool->idle_lock);
        }
        lock_release(&pool->idle_lock);
    }

    atomic_store_explicit(&pool->shutdown, 1, memory_order_seq_cst);

    unpark_all(pool);

    while (atomic_load_explicit(&pool->num_threads_alive, memory_order_acquire) > 0) {
        unpark_all(pool);
        thread_yield();
    }

    for (size_t i = 0; i < pool->num_workers; i++) {
        if (pool->workers[i]) {
            thread_join(pool->workers[i]->pthread, NULL);
            free(pool->workers[i]);
        }
    }
    free(pool->workers);

    gq_destroy(&pool->gq);
    lock_free(&pool->park_lock);
    cond_free(&pool->work_available);
    lock_free(&pool->idle_lock);
    cond_free(&pool->all_idle);
    free(pool);
}
