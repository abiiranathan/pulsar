/**
 * @file rwlock.h
 * @brief Read-write lock implementation for concurrent access.
 */

#ifndef __RWLOCK_H__
#define __RWLOCK_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Cross-platform thread synchronization
#ifdef _WIN32
    #include "platform.h"
typedef SRWLOCK rwlock_t;
#else
    #include <pthread.h>
typedef pthread_rwlock_t rwlock_t;
#endif

// Cross-platform rwlock helpers
#ifdef _WIN32

/**
 * Initializes a read-write lock.
 * @param lock Pointer to the lock to initialize.
 * @return true on success, false on failure. On Windows, always returns true.
 * @note On Windows, this wraps InitializeSRWLock(). On POSIX, wraps pthread_rwlock_init().
 */
static inline bool rwlock_init(rwlock_t* lock) {
    InitializeSRWLock(lock);
    return true;  // Windows SRWLOCK initialization cannot fail
}

/**
 * Acquires a read (shared) lock.
 * @param lock Pointer to the lock to acquire.
 * @note Blocks until the lock can be acquired. Multiple readers can hold the lock simultaneously.
 *       Thread-safe.
 */
static inline void rwlock_rdlock(rwlock_t* lock) { AcquireSRWLockShared(lock); }

/**
 * Acquires a write (exclusive) lock.
 * @param lock Pointer to the lock to acquire.
 * @note Blocks until the lock can be acquired exclusively. Only one writer can hold the lock,
 *       and no readers can hold it simultaneously. Thread-safe.
 */
static inline void rwlock_wrlock(rwlock_t* lock) { AcquireSRWLockExclusive(lock); }

/**
 * Releases a read (shared) lock.
 * @param lock Pointer to the lock to release.
 * @note Must be called by the same thread that acquired the read lock. Thread-safe.
 */
static inline void rwlock_unlock_rd(rwlock_t* lock) { ReleaseSRWLockShared(lock); }

/**
 * Releases a write (exclusive) lock.
 * @param lock Pointer to the lock to release.
 * @note Must be called by the same thread that acquired the write lock. Thread-safe.
 */
static inline void rwlock_unlock_wr(rwlock_t* lock) { ReleaseSRWLockExclusive(lock); }

/**
 * Destroys a read-write lock and frees associated resources.
 * @param lock Pointer to the lock to destroy.
 * @note On Windows (SRWLOCK), this is a no-op as no cleanup is needed.
 *       On POSIX, wraps pthread_rwlock_destroy(). The lock must not be held by any thread.
 */
static inline void rwlock_destroy(rwlock_t* lock) {
    // SRWLOCK doesn't need explicit destruction
    (void)lock;
}
#else
/**
 * Initializes a read-write lock.
 * @param lock Pointer to the lock to initialize.
 * @return true on success, false on failure. On Windows, always returns true.
 * @note On Windows, this wraps InitializeSRWLock(). On POSIX, wraps pthread_rwlock_init().
 */
static inline bool rwlock_init(rwlock_t* lock) { return pthread_rwlock_init(lock, NULL) == 0; }

/**
 * Acquires a read (shared) lock.
 * @param lock Pointer to the lock to acquire.
 * @note Blocks until the lock can be acquired. Multiple readers can hold the lock simultaneously.
 *       Thread-safe.
 */
static inline void rwlock_rdlock(rwlock_t* lock) { pthread_rwlock_rdlock(lock); }

/**
 * Acquires a write (exclusive) lock.
 * @param lock Pointer to the lock to acquire.
 * @note Blocks until the lock can be acquired exclusively. Only one writer can hold the lock,
 *       and no readers can hold it simultaneously. Thread-safe.
 */
static inline void rwlock_wrlock(rwlock_t* lock) { pthread_rwlock_wrlock(lock); }

/**
 * Releases a read (shared) lock.
 * @param lock Pointer to the lock to release.
 * @note Must be called by the same thread that acquired the read lock. Thread-safe.
 */
static inline void rwlock_unlock_rd(rwlock_t* lock) { pthread_rwlock_unlock(lock); }

/**
 * Releases a write (exclusive) lock.
 * @param lock Pointer to the lock to release.
 * @note Must be called by the same thread that acquired the write lock. Thread-safe.
 */
static inline void rwlock_unlock_wr(rwlock_t* lock) { pthread_rwlock_unlock(lock); }

/**
 * Destroys a read-write lock and frees associated resources.
 * @param lock Pointer to the lock to destroy.
 * @note On Windows (SRWLOCK), this is a no-op as no cleanup is needed.
 *       On POSIX, wraps pthread_rwlock_destroy(). The lock must not be held by any thread.
 */
static inline void rwlock_destroy(rwlock_t* lock) { pthread_rwlock_destroy(lock); }
#endif

#ifdef __cplusplus
}
#endif

#endif  // __RWLOCK_H__
