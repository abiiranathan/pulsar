/**
 * @file threadpool.h
 * @brief Work-stealing thread pool for concurrent task execution.
 *
 * @details
 * This thread pool uses the Chase-Lev (2005) work-stealing deque algorithm
 * with the Le et al. (2013) correction for the last-item ABA hazard.
 *
 * ## Architecture
 *
 * Each worker thread owns a private double-ended queue (deque):
 * - The **owner** pushes and pops tasks at the **bottom** end using a single
 *   release store — no CAS, no lock, no contention with other threads.
 * - **Thieves** (idle workers) steal one task at a time from the **top** end
 *   using a single seq_cst CAS.
 *
 * External submitters (threads that are not pool workers) push tasks into a
 * shared @c GlobalQueue protected by a mutex.  Workers drain this queue in
 * batches of @c BATCH_SIZE tasks per mutex acquisition, then distribute the
 * extras into their own private deques for subsequent lock-free consumption.
 *
 * ```
 *   External submitter
 *        │
 *        ▼
 *   [ GlobalQueue ]  ──batch drain──▶  worker[0] deque  ◀── steal ── worker[1]
 *                                      worker[1] deque  ◀── steal ── worker[2]
 *                                      ...
 * ```
 *
 * ## Threading model
 *
 * | Operation                 | Cost                                        |
 * |---------------------------|---------------------------------------------|
 * | Worker push/pop (own deque) | One release store — zero contention      |
 * | Thief steal               | One seq_cst CAS — contended only between thieves |
 * | External submit (single)  | One mutex round-trip per task              |
 * | External submit (batch)   | One mutex round-trip per @c GLOBAL_Q_SIZE tasks |
 * | Worker drain from global  | One mutex round-trip per @c BATCH_SIZE tasks |
 *
 * ## Compile-time knobs
 *
 *
 * Internal constants (defined in threadpool.c, not overridable from the header):
 *
 * | Constant             | Value  | Meaning                                    |
 * |----------------------|--------|--------------------------------------------|
 * | @c DEQUE_SIZE        | 16384  | Slots per private Chase-Lev deque          |
 * | @c GLOBAL_Q_SIZE     | 65536  | Slots in the shared external submission queue |
 * | @c BATCH_SIZE        | 64     | Tasks pulled from the global queue per mutex acquisition |
 * | @c PENDING_FLUSH_BATCH | 64   | Completions accumulated before flushing the shared idle counter |
 * | @c YIELD_THRESHOLD   | 8      | PAUSE-backoff rounds before a worker parks on a condvar |
 * | @c ADAPTIVE_SPIN_NS  | ~4000  | Bounded poll duration in threadpool_wait() before blocking |
 *
 * Submissions larger than @c GLOBAL_Q_SIZE stream through in chunks; the
 * submitter blocks when the queue fills and is woken as consumers drain it.
 *
 * ## Idle detection
 *
 * A single atomic counter (@c num_pending) tracks accepted-but-incomplete
 * tasks.  It is credited before a task becomes visible to any consumer and
 * debited on completion (in batches of PENDING_FLUSH_BATCH), so
 * "num_pending == 0" is an exact idle predicate — no queue scanning.  A
 * completing flush that drives the count to zero wakes threadpool_wait()
 * and destroy() sleepers.
 *
 * ## Lifecycle
 *
 * ```c
 * Threadpool* pool = threadpool_create(8);
 *
 * // Single-task submission
 * threadpool_submit(pool, my_fn, my_arg);
 *
 * // Batch submission (preferred for large workloads)
 * void (*fns[N])(void*) = { ... };
 * void*  args[N]        = { ... };
 * threadpool_submit_batch(pool, fns, args, N);
 *
 * // Wait for all current tasks to complete (pool remains usable)
 * threadpool_wait(pool);
 *
 * // Tear down
 * threadpool_destroy(pool, -1);
 * ```
 *
 * ## Thread safety
 *
 * All public functions are safe to call from any thread concurrently, including
 * from within a running task.  A task may call @c threadpool_submit or
 * @c threadpool_submit_batch to enqueue follow-on work; in that case the task
 * is treated as a worker thread and pushes directly into its own private deque
 * at zero contention cost.
 */

#ifndef __THREADPOOL_H__
#define __THREADPOOL_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque handle to a thread pool instance.
 *
 * Obtain via @c threadpool_create().  All fields are private; interact with
 * the pool exclusively through the functions declared in this header.
 */
typedef struct Threadpool Threadpool;

/**
 * @brief A unit of work submitted to the pool.
 *
 * Tasks are value types — they are copied into the pool's internal queues on
 * submission.  The caller does not need to keep the @c Task object alive after
 * @c threadpool_submit or @c threadpool_submit_batch returns.
 */
typedef struct Task {
    void (*function)(void* arg); /**< Function to execute.  Must not be NULL. */
    void* arg;                   /**< Opaque argument forwarded to @c function unchanged. */
} Task;

/**
 * @brief Create a new thread pool.
 *
 * Spawns @p num_threads worker threads and returns a handle to the pool.
 * Workers enter a startup barrier and do not begin stealing or executing tasks
 * until every worker slot in the internal array has been initialised — this
 * prevents a race where an early-starting worker dereferences a NULL pointer
 * while the creation loop is still running.
 *
 * @param num_threads Number of worker threads to create.  Clamped to 1 if 0
 *                    is passed.
 *
 * @return Pointer to the new pool, or @c NULL if memory allocation or thread
 *         creation fails.  On partial failure all successfully created threads
 *         are joined and all memory is freed before returning @c NULL.
 *
 * @note The returned pointer must be freed with @c threadpool_destroy().
 *
 * @par Complexity
 * O(@p num_threads) — one @c pthread_create per worker.
 */
Threadpool* threadpool_create(size_t num_threads);

/**
 * @brief Submit a single task to the pool.
 *
 * Determines the submission path based on the calling thread's identity:
 *
 * - **Worker thread** (a thread created by this pool): pushes the task
 *   directly into the caller's own Chase-Lev deque bottom with a single
 *   release store — zero lock contention, zero shared cache-line traffic.
 *   Falls back to the global queue if the private deque is full (capacity
 *   4096 slots; this path is not reached under normal load).
 *
 * - **External thread** (any other thread): pushes the task into the shared
 *   @c GlobalQueue under a mutex.  Costs one @c pthread_mutex_lock +
 *   @c pthread_mutex_unlock round-trip.  Blocks if the global queue is full
 *   (capacity 16384 slots) until a worker drains a slot.
 *
 * After pushing, wakes one parked worker if any are sleeping.
 *
 * @param pool     Pool to submit to.  Must not be @c NULL.
 * @param function Task function.  Must not be @c NULL.
 * @param arg      Argument passed verbatim to @p function.  May be @c NULL.
 *
 * @return @c true if the task was enqueued, @c false if @p pool or
 *         @p function is @c NULL or if the pool is shutting down.
 *
 * @note For bulk external submission prefer @c threadpool_submit_batch, which
 *       amortises the mutex cost across many tasks.
 *
 * @par Complexity
 * O(1) amortised.
 */
bool threadpool_submit(Threadpool* pool, void (*function)(void*), void* arg);

/**
 * @brief Submit multiple tasks to the pool in a single call.
 *
 * Reduces mutex acquisition overhead from O(@p count) to
 * O(@p count / @c GLOBAL_Q_SIZE) compared to calling @c threadpool_submit
 * in a loop.  For a batch of 10 000 tasks with @c GLOBAL_Q_SIZE = 16384,
 * this is a single mutex acquisition instead of 10 000.
 *
 * ### Submission paths
 *
 * **Worker thread**: iterates @p functions and pushes each task into the
 * caller's own deque with @c deque_push_bottom (lock-free).  Any tasks that
 * do not fit in the private deque (overflow past 4096 slots) are forwarded to
 * the global queue via @c gq_push_batch.
 *
 * **External thread**: builds a flat @c Task array on the stack (if
 * @p count ≤ @c BATCH_SIZE) or heap, then hands it to @c gq_push_batch which
 * holds @c gq_mutex for the duration of each chunk write.  If the global queue
 * fills up mid-batch, @c gq_push_batch waits on @c not_full and resumes from
 * where it left off — the caller blocks until all @p count tasks are enqueued
 * or the pool shuts down.
 *
 * @param pool      Pool to submit to.  Must not be @c NULL.
 * @param functions Array of @p count function pointers.  @c NULL entries are
 *                  silently skipped and do not count toward the return value.
 * @param args      Array of @p count argument pointers, or @c NULL to pass
 *                  @c NULL as the argument to every task.
 * @param count     Number of entries in @p functions (and @p args if non-NULL).
 *
 * @return Number of tasks successfully enqueued.  Equal to the number of
 *         non-NULL entries in @p functions under normal operation.  May be
 *         less than @p count if the pool begins shutting down mid-batch; the
 *         caller should treat a short return as a fatal error.
 *         Returns 0 if @p pool is @c NULL, @p functions is @c NULL, or
 *         @p count is 0.
 *
 * @par Example
 * @code
 * #define N 10000
 * void (*fns[N])(void*);
 * void*  args_arr[N];
 * for (int i = 0; i < N; i++) { fns[i] = process; args_arr[i] = &items[i]; }
 *
 * size_t submitted = threadpool_submit_batch(pool, fns, args_arr, N);
 * assert(submitted == N);
 * @endcode
 *
 * @par Complexity
 * O(@p count / @c GLOBAL_Q_SIZE) mutex acquisitions for external threads;
 * O(@p count) deque stores (lock-free) for worker threads.
 */
size_t threadpool_submit_batch(Threadpool* pool, void (**functions)(void*), void** args, size_t count);

/**
 * @brief Block until all currently submitted tasks have completed.
 *
 * Returns only when both conditions hold simultaneously:
 * 1. Every worker's private deque is empty.
 * 2. The global submission queue is empty.
 * 3. No worker is currently executing a task (@c num_active == 0).
 *
 * Condition 3 ensures correctness when a task itself calls
 * @c threadpool_submit or @c threadpool_submit_batch — the pool is not
 * considered idle until those follow-on tasks have also completed.
 *
 * The pool remains fully operational after @c threadpool_wait returns.
 * New tasks may be submitted immediately.
 *
 * @param pool Pool to wait on.  If @c NULL the function returns immediately.
 *
 * @note Do **not** call @c threadpool_wait from within a running task.
 *       The task holds a slot in @c num_active, so the wait condition can
 *       never be satisfied while that task is still on the call stack —
 *       this will deadlock.
 *
 * @par Typical usage
 * @code
 * // Phase 1
 * threadpool_submit_batch(pool, fns1, args1, N1);
 * threadpool_wait(pool);
 * process_phase1_results();
 *
 * // Phase 2 — pool is still alive and ready
 * threadpool_submit_batch(pool, fns2, args2, N2);
 * threadpool_wait(pool);
 *
 * threadpool_destroy(pool, -1);
 * @endcode
 */
void threadpool_wait(Threadpool* pool);

/**
 * @brief Drain all pending tasks, stop all workers, and free the pool.
 *
 * Shutdown sequence:
 * 1. Acquires @c idle_lock and waits until all queues are empty and
 *    @c num_active reaches zero (subject to @p timeout_ms).
 * 2. Sets the @c shutdown flag atomically while still holding @c idle_lock,
 *    preventing workers from re-entering their park condvar between the flag
 *    store and the subsequent broadcast.
 * 3. Broadcasts on @c work_available to wake every parked worker.
 * 4. Spin-waits for @c num_threads_alive to reach zero.
 * 5. Joins every worker thread, frees per-worker memory, destroys all
 *    synchronisation objects, and frees the pool struct.
 *
 * The @p pool pointer is invalid after this function returns.
 *
 * @param pool       Pool to destroy.  If @c NULL the function returns
 *                   immediately without error.
 * @param timeout_ms Maximum milliseconds to wait for in-flight tasks to
 *                   complete before proceeding with shutdown.
 *                   Pass @c -1 to wait indefinitely (recommended for
 *                   correctness; use a positive value only when a hard
 *                   deadline is required and task cancellation is acceptable).
 *
 * @warning Calling @c threadpool_submit or @c threadpool_submit_batch after
 *          @c threadpool_destroy is undefined behaviour — the pool memory has
 *          been freed.
 *
 * @warning Do **not** call @c threadpool_destroy from within a running task.
 *          The @c num_active counter will never reach zero while the calling
 *          task is still executing, causing an infinite wait (with
 *          @p timeout_ms == -1) or a forceful shutdown that frees memory
 *          still on the call stack.
 */
void threadpool_destroy(Threadpool* pool, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* __THREADPOOL_H__ */
