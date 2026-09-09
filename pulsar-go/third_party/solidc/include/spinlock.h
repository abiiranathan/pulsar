/**
 * @file spinlock.h
 * @brief High-performance reader-writer spinlock implementation
 *
 * This header provides a custom RW-spinlock optimized for short critical
 * sections and high-concurrency scenarios. It significantly outperforms
 * pthread_rwlock_t when lock hold times are very brief (microseconds) due to
 * lower overhead.
 *
 * The spinlock uses a single atomic integer to track state:
 *   - state >= 1: Number of active readers
 *   - state == 0: Unlocked
 *   - state == -1: Write lock held
 *
 * @warning This spinlock busy-waits (spins) when contended. Use only for:
 *   - Very short critical sections (< 100 microseconds)
 *   - Low to moderate contention scenarios
 *   - Systems where context switching overhead exceeds spin cost
 *
 * For longer critical sections or high contention, use pthread_rwlock_t
 * instead.
 *
 * @note Thread-safe: All operations are atomic and safe for concurrent use.
 * @note Not reentrant: A thread cannot acquire the same lock recursively.
 */

#ifndef SPINLOCK_H
#define SPINLOCK_H

#ifdef __cplusplus
    #include <atomic>
extern "C" {
#else
    #include <stdatomic.h>
#endif

#if defined(__x86_64__) || defined(__i386__)
    #include <emmintrin.h>  // For _mm_pause on x86
#endif

/**
 * @brief Reader-writer spinlock structure.
 *
 * Internal representation of the RW-spinlock. The state field tracks:
 *   - Positive values: Number of concurrent readers holding the lock
 *   - Zero: Lock is free
 *   - Negative one (-1): A writer holds the lock
 */
typedef struct {
    /** Lock state: >0 = reader count, 0 = unlocked, -1 = writer locked */
#ifdef __cplusplus
    std::atomic<int> state;
#else
    _Atomic(int) state;
#endif
} fast_rwlock_t;

/**
 * @brief CPU-specific pause instruction for busy-wait loops.
 *
 * Inserts a platform-specific hint to the CPU that we're in a spin-wait loop.
 * This improves performance by:
 *   - Reducing power consumption during spinning
 *   - Avoiding memory order violation penalties on some architectures
 *   - Improving hyper-threading efficiency by yielding execution resources
 *
 * On x86/x64, uses the PAUSE instruction. On ARM64, uses the YIELD instruction.
 * On other platforms, this is a no-op.
 *
 * @note This is not a scheduling yield - it's a CPU-level hint within the same
 * thread.
 */
static inline void cpu_relax(void) {
#if defined(__x86_64__) || defined(__i386__)
    _mm_pause();
#elif defined(__aarch64__) || defined(__arm__)
    __asm__ volatile("yield");
#else
        /* No-op on other platforms */
#endif
}

/**
 * @brief Initialize a reader-writer spinlock.
 *
 * Must be called before first use of the lock. Sets the lock to the unlocked
 * state.
 *
 * @param l Pointer to the spinlock to initialize. Must not be NULL.
 *
 * @note Not thread-safe during initialization. Ensure no other threads access
 *       the lock until initialization completes.
 *
 * Example:
 * @code
 * fast_rwlock_t lock;
 * fast_rwlock_init(&lock);
 * @endcode
 */
static inline void fast_rwlock_init(fast_rwlock_t* l) {
#ifdef __cplusplus
    new (&l->state) std::atomic<int>(0);
#else
    atomic_init(&l->state, 0);
#endif
}

/**
 * @brief Acquire the lock for reading (shared access).
 *
 * Multiple readers can hold the lock simultaneously. Blocks if a writer
 * currently holds the lock, spinning until the writer releases.
 *
 * Uses acquire semantics to ensure subsequent reads see all memory operations
 * that happened before the corresponding unlock.
 *
 * @param l Pointer to the spinlock. Must not be NULL.
 *
 * @warning This function spins (busy-waits) if the lock is write-locked.
 *          Ensure critical sections are brief to avoid wasting CPU cycles.
 *
 * @note Safe for concurrent use by multiple threads.
 * @note Must be paired with fast_rwlock_unlock_rd().
 * @note Not reentrant - a thread cannot recursively acquire the same lock.
 *
 * Example:
 * @code
 * fast_rwlock_rdlock(&lock);
 * // Read shared data
 * fast_rwlock_unlock_rd(&lock);
 * @endcode
 */
static inline void fast_rwlock_rdlock(fast_rwlock_t* l) {
    while (true) {
#ifdef __cplusplus
        int state = l->state.load(std::memory_order_relaxed);
#else
        int state = atomic_load_explicit(&l->state, memory_order_relaxed);
#endif
        if (state < 0) {
            cpu_relax();
            continue;
        }
#ifdef __cplusplus
        if (l->state.compare_exchange_weak(state, state + 1, std::memory_order_acquire, std::memory_order_relaxed))
#else
        if (atomic_compare_exchange_weak_explicit(&l->state, &state, state + 1, memory_order_acquire,
                                                  memory_order_relaxed))
#endif
            return;
        cpu_relax();
    }
}

/**
 * @brief Release the read lock.
 *
 * Decrements the reader count. Uses release semantics to ensure all memory
 * operations in the critical section are visible to other threads before
 * the lock is released.
 *
 * @param l Pointer to the spinlock. Must not be NULL.
 *
 * @warning Behavior is undefined if called without a matching
 * fast_rwlock_rdlock().
 * @warning Behavior is undefined if called by a thread that doesn't hold the
 * read lock.
 *
 * @note Safe for concurrent use by multiple threads.
 *
 * Example:
 * @code
 * fast_rwlock_rdlock(&lock);
 * // Read shared data
 * fast_rwlock_unlock_rd(&lock);
 * @endcode
 */
static inline void fast_rwlock_unlock_rd(fast_rwlock_t* l) {
#ifdef __cplusplus
    l->state.fetch_sub(1, std::memory_order_release);
#else
    atomic_fetch_sub_explicit(&l->state, 1, memory_order_release);
#endif
}

/**
 * @brief Acquire the lock for writing (exclusive access).
 *
 * Waits until no readers or writers hold the lock, then acquires exclusive
 * access. Blocks all other readers and writers until released.
 *
 * Uses acquire semantics to ensure subsequent reads/writes see all memory
 * operations that happened before the corresponding unlock.
 *
 * @param l Pointer to the spinlock. Must not be NULL.
 *
 * @warning This function spins (busy-waits) until the lock is free.
 *          Can spin for extended periods under high read contention.
 * @warning Writer starvation is possible if readers continuously hold the lock.
 *
 * @note Safe for concurrent use by multiple threads.
 * @note Must be paired with fast_rwlock_unlock_wr().
 * @note Not reentrant - a thread cannot recursively acquire the same lock.
 *
 * Example:
 * @code
 * fast_rwlock_wrlock(&lock);
 * // Modify shared data
 * fast_rwlock_unlock_wr(&lock);
 * @endcode
 */
static inline void fast_rwlock_wrlock(fast_rwlock_t* l) {
    while (true) {
        int expected = 0;
#ifdef __cplusplus
        if (l->state.compare_exchange_weak(expected, -1, std::memory_order_acquire, std::memory_order_relaxed))
#else
        if (atomic_compare_exchange_weak_explicit(&l->state, &expected, -1, memory_order_acquire, memory_order_relaxed))
#endif
            return;
        cpu_relax();
    }
}

/**
 * @brief Release the write lock.
 *
 * Resets the lock to the unlocked state. Uses release semantics to ensure all
 * memory operations in the critical section are visible to other threads before
 * the lock is released.
 *
 * @param l Pointer to the spinlock. Must not be NULL.
 *
 * @warning Behavior is undefined if called without a matching
 * fast_rwlock_wrlock().
 * @warning Behavior is undefined if called by a thread that doesn't hold the
 * write lock.
 *
 * @note Safe for concurrent use by multiple threads.
 *
 * Example:
 * @code
 * fast_rwlock_wrlock(&lock);
 * // Modify shared data
 * fast_rwlock_unlock_wr(&lock);
 * @endcode
 */
static inline void fast_rwlock_unlock_wr(fast_rwlock_t* l) {
#ifdef __cplusplus
    l->state.store(0, std::memory_order_release);
#else
    atomic_store_explicit(&l->state, 0, memory_order_release);
#endif
}

#ifdef __cplusplus
}
#endif

#endif  // SPINLOCK_H
