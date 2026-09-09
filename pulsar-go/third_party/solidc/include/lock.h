/**
 * @file lock.h
 * @brief Cross-platform mutex and condition variable wrapper.
 *
 * Provides a unified interface for synchronization primitives across
 * Windows (Critical Sections/Condition Variables) and POSIX systems
 * (pthread mutexes/condition variables).
 *
 * All functions return integer error codes instead of terminating the program,
 * allowing for proper error handling and recovery.
 *
 * @note This library is thread-safe where documented, but initialization
 *       and destruction functions are NOT thread-safe.
 */

#ifndef LOCK_H
#define LOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
    #include "platform.h"
/** Platform-specific lock type (Windows Critical Section). */
typedef CRITICAL_SECTION Lock;
/** Platform-specific condition variable type (Windows Condition Variable). */
typedef CONDITION_VARIABLE Condition;
#else
    #include <pthread.h>
/** Platform-specific lock type (POSIX mutex). */
typedef pthread_mutex_t Lock;
/** Platform-specific condition variable type (POSIX condition variable). */
typedef pthread_cond_t Condition;
#endif

/* Lock (Mutex) Functions */

/**
 * Initializes a lock.
 * @param lock Pointer to the lock to initialize. Must not be NULL.
 * @return 0 on success, -1 on failure.
 * @note Not thread-safe. Caller must ensure exclusive access during initialization.
 */
int lock_init(Lock* lock);

/**
 * Acquires a lock, blocking until available.
 * @param lock Pointer to an initialized lock. Must not be NULL.
 * @return 0 on success, -1 on failure.
 * @note Thread-safe. This function will block until the lock is acquired.
 */
int lock_acquire(Lock* lock);

/**
 * Releases a previously acquired lock.
 * @param lock Pointer to an initialized lock currently held by this thread. Must not be NULL.
 * @return 0 on success, -1 on failure.
 * @note Thread-safe, but only the thread that acquired the lock should release it.
 */
int lock_release(Lock* lock);

/**
 * Destroys a lock and releases its resources.
 * @param lock Pointer to the lock to destroy. NULL is allowed (no-op).
 * @return 0 on success, -1 on failure.
 * @note Not thread-safe. Caller must ensure no other threads are using the lock.
 */
int lock_free(Lock* lock);

/**
 * Attempts to acquire a lock without blocking.
 * @param lock Pointer to an initialized lock. Must not be NULL.
 * @return 0 if acquired, -1 if the lock was busy or on error.
 * @note Thread-safe. Returns immediately whether the lock was acquired or not.
 */
int lock_try_acquire(Lock* lock);

/**
 * Waits on a condition variable with a timeout while holding a lock.
 * This is a convenience function equivalent to cond_wait_timeout().
 * @param lock Pointer to an initialized lock currently held by this thread. Must not be NULL.
 * @param condition Pointer to an initialized condition variable. Must not be NULL.
 * @param timeout_ms Timeout in milliseconds. Negative values mean wait indefinitely.
 * @return 0 on success, -1 on timeout, other error codes on failure.
 * @note Thread-safe, but lock must be held by calling thread.
 */
int lock_wait(Lock* lock, Condition* condition, int timeout_ms);

/* Condition Variable Functions */

/**
 * Initializes a condition variable.
 * @param condition Pointer to the condition variable to initialize. Must not be NULL.
 * @return 0 on success, -1 on failure.
 * @note Not thread-safe. Caller must ensure exclusive access during initialization.
 */
int cond_init(Condition* condition);

/**
 * Signals one thread waiting on the condition variable.
 * @param condition Pointer to an initialized condition variable. Must not be NULL.
 * @return 0 on success, -1 on failure.
 * @note Thread-safe. Wakes up at most one waiting thread.
 */
int cond_signal(Condition* condition);

/**
 * Signals all threads waiting on the condition variable.
 * @param condition Pointer to an initialized condition variable. Must not be NULL.
 * @return 0 on success, -1 on failure.
 * @note Thread-safe. Wakes up all waiting threads.
 */
int cond_broadcast(Condition* condition);

/**
 * Waits indefinitely on a condition variable while holding a lock.
 * @param condition Pointer to an initialized condition variable. Must not be NULL.
 * @param lock Pointer to an initialized lock currently held by this thread. Must not be NULL.
 * @return 0 on success, -1 on failure.
 * @note Thread-safe, but lock must be held by calling thread. Lock is atomically
 *       released during wait and re-acquired before returning.
 */
int cond_wait(Condition* condition, Lock* lock);

/**
 * Waits on a condition variable with a timeout while holding a lock.
 * @param condition Pointer to an initialized condition variable. Must not be NULL.
 * @param lock Pointer to an initialized lock currently held by this thread. Must not be NULL.
 * @param timeout_ms Timeout in milliseconds. Negative values mean wait indefinitely.
 * @return 0 if signalled, -1 on timeout or error.
 * @note Thread-safe, but lock must be held by calling thread. Lock is atomically
 *       released during wait and re-acquired before returning.
 *       On POSIX, condition variables created with cond_init() use the
 *       CLOCK_MONOTONIC clock: the timeout is immune to wall-clock
 *       adjustments (NTP steps, manual time changes).  Pair cond_wait_timeout()
 *       only with conditions initialized via cond_init().
 */
int cond_wait_timeout(Condition* condition, Lock* lock, int timeout_ms);

/**
 * Destroys a condition variable and releases its resources.
 * @param condition Pointer to the condition variable to destroy. NULL is allowed (no-op).
 * @return 0 on success, -1 on failure.
 * @note Not thread-safe. Caller must ensure no other threads are using the condition variable.
 */
int cond_free(Condition* condition);

/* Utility Functions */

#ifdef __cplusplus
}
#endif

#endif  // LOCK_H
