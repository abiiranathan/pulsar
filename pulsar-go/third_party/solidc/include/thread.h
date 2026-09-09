/**
 * @file thread.h
 * @brief Cross-platform thread management and system information utilities.
 *
 * Provides a unified interface for thread creation, synchronization, and system
 * information queries across Windows and POSIX systems. All thread functions
 * return 0 on success and non-zero on error for consistency with POSIX conventions.
 *
 * Thread safety is documented per function. Generally, thread creation and
 * attribute management functions are thread-safe, but individual thread
 * attribute objects should not be modified concurrently.
 *
 * @note This library requires linking with pthread on POSIX systems (-lpthread).
 *
 * @section limitations Platform Limitations
 *
 * **Windows Return Value Limitation:**
 * On Windows, thread return values (void*) are stored as 32-bit DWORD values.
 * If your thread returns a 64-bit pointer on 64-bit Windows, the upper 32 bits
 * will be lost. For portable code, return values should fit in 32 bits
 * (e.g., cast integer status codes to void*).
 *
 * **Thread ID Portability:**
 * The get_tid() function returns unsigned long, but pthread_t is an opaque type
 * that may not be convertible to an integer on all platforms. Use get_tid()
 * for logging/debugging only, not as a unique identifier for synchronization.
 *
 * **Thread Handle Lifetime:**
 * After calling thread_detach() on Windows, the thread handle becomes invalid
 * and must not be used for any subsequent operations. This matches POSIX semantics
 * where detached threads cannot be joined.
 */

#ifndef SOLIDC_THREADS_H
#define SOLIDC_THREADS_H

#if !defined(_GNU_SOURCE)
    #define _GNU_SOURCE  // for nanosleep and extended POSIX features
#endif

#include <stdint.h>  // for uintptr_t

#ifdef _WIN32
    // Windows comes first before tlhelp32.h
    #include "platform.h"

    // This comment prevents clang-format messing order of imports
    #include <io.h>
    #include <lmcons.h>    // for UNLEN constant (get_username)
    #include <tlhelp32.h>  // for CreateToolhelp32Snapshot (get_ppid)
#else
    #include <errno.h>     // for error constants
    #include <grp.h>       // for getgrgid
    #include <pthread.h>   // for pthread functions
    #include <pwd.h>       // for getpwuid
    #include <sys/stat.h>  // for file operations
    #include <sys/wait.h>  // for process waiting
    #include <unistd.h>    // for POSIX system calls
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Type Definitions */

#ifdef _WIN32
/** Platform-specific thread handle (Windows HANDLE). */
typedef HANDLE Thread;

/** Thread attribute configuration for Windows. */
typedef struct ThreadAttr {
    SECURITY_ATTRIBUTES sa; /**< Security attributes for thread creation. */
    DWORD stackSize;        /**< Stack size in bytes (0 = system default). */
} ThreadAttr;
#else
/** Platform-specific thread handle (POSIX pthread_t). */
typedef pthread_t Thread;

/** Thread attribute configuration (POSIX pthread_attr_t). */
typedef pthread_attr_t ThreadAttr;
#endif

/**
 * Thread start routine function pointer type.
 * @param arg User-provided argument passed to the thread.
 * @return Thread exit value (can be retrieved via thread_join).
 * @note On Windows, only the lower 32 bits of pointer return values are preserved.
 *       For portable code, return integer status codes cast to void*.
 * @note The return value should be a pointer or integer cast to void*.
 */
typedef void* (*ThreadStartRoutine)(void* arg);

/* Thread Management Functions */

/**
 * Creates a new thread with default attributes.
 * @param thread Pointer to store the created thread handle. Must not be NULL.
 * @param start_routine Function to execute in the new thread. Must not be NULL.
 * @param data Argument to pass to the start routine. Can be NULL.
 * @return 0 on success, EINVAL for invalid parameters, ENOMEM for allocation failure,
 *         or other non-zero error code on failure.
 * @note Thread-safe: Yes.
 * @note Created thread is joinable by default. Call thread_detach() to make it detached.
 * @note On success, the thread handle stored in *thread is valid until thread_join()
 *       or thread_detach() is called.
 */
int thread_create(Thread* thread, ThreadStartRoutine start_routine, void* data);

/**
 * Creates a new thread with custom attributes.
 * @param thread Pointer to store the created thread handle. Must not be NULL.
 * @param attr Pointer to initialized thread attributes. Must not be NULL.
 * @param start_routine Function to execute in the new thread. Must not be NULL.
 * @param data Argument to pass to the start routine. Can be NULL.
 * @return 0 on success, EINVAL for invalid parameters, ENOMEM for allocation failure,
 *         or other non-zero error code on failure.
 * @note Thread-safe: Yes.
 * @note The attr object can be destroyed immediately after this call returns.
 */
int thread_create_attr(Thread* thread, ThreadAttr* attr, ThreadStartRoutine start_routine, void* data);

/**
 * Waits for a thread to terminate and retrieves its exit value.
 * @param tid Thread handle to wait for. Must be a valid handle from thread_create().
 * @param retval Pointer to store thread's return value. Can be NULL if not needed.
 * @return 0 on success, EINVAL for invalid handle, or other non-zero error code on failure.
 * @note Thread-safe: Yes, but each thread can only be joined once.
 * @note On Windows, closes the thread handle automatically after join. On POSIX, the
 *       thread resources are freed but the pthread_t value may still be compared.
 * @note Joining a detached thread results in undefined behavior.
 * @note On Windows, only the lower 32 bits of pointer return values are preserved.
 */
int thread_join(Thread tid, void** retval);

/**
 * Detaches a thread, allowing system to reclaim resources when it terminates.
 * @param tid Thread handle to detach. Must be a valid handle from thread_create().
 * @return 0 on success, EINVAL for invalid handle, or other non-zero error code on failure.
 * @note Thread-safe: Yes.
 * @note After detaching, the thread handle becomes invalid and must not be used
 *       for any operations, including join. This applies to both Windows and POSIX.
 * @note After detaching, the thread cannot be joined - calling thread_join() on
 *       a detached thread results in undefined behavior.
 * @note The thread continues to run after detachment and will clean up automatically
 *       when it exits.
 */
int thread_detach(Thread tid);

/**
 * Terminates the calling thread and returns a value to the caller.
 * @param retval The return value for the thread. On POSIX, this is a void pointer.
 *               On Windows, this should be cast from a DWORD exit code.
 * @note On Windows, only the lower 32 bits of the pointer are used as the exit code.
 * @note This function does not return.
 */
void thread_exit(void* retval);

#ifdef _WIN32
/**
 * Returns the current thread's ID (Windows-specific).
 * @return Current thread ID as a DWORD.
 * @note Thread-safe: Yes.
 * @note This is the Windows thread ID, not the thread handle.
 * @note Thread IDs may be reused by the system after a thread terminates.
 */
DWORD thread_self();
#else
/**
 * Returns the current thread's handle (POSIX-specific).
 * @return Current thread handle as pthread_t.
 * @note Thread-safe: Yes.
 * @note This returns the pthread_t handle, not a numeric ID.
 * @note pthread_t is an opaque type - use pthread_equal() to compare threads.
 */
pthread_t thread_self();
#endif

/* Thread Attribute Management */

/**
 * Initializes thread attributes to default values.
 * @param attr Pointer to thread attributes structure. Must not be NULL.
 * @return 0 on success, EINVAL for invalid parameter, or other non-zero error code.
 * @note Thread-safe: Yes (different attr objects), No (same attr object).
 * @note Must call thread_attr_destroy() to release resources.
 * @note Default attributes: joinable thread, default stack size, default security.
 */
int thread_attr_init(ThreadAttr* attr);

/**
 * Destroys thread attributes and releases associated resources.
 * @param attr Pointer to initialized thread attributes. Must not be NULL.
 * @return 0 on success, EINVAL for invalid parameter, or other non-zero error code.
 * @note Thread-safe: Yes (different attr objects), No (same attr object).
 * @note After destruction, the attr structure should not be used unless reinitialized.
 * @note On Windows, this zeros the structure for security but has no other effect.
 */
int thread_attr_destroy(ThreadAttr* attr);

/* Utility Functions */

/**
 * Suspends execution of the calling thread for specified milliseconds.
 * @param ms Number of milliseconds to sleep. Must be non-negative and <= INT_MAX.
 * @note Thread-safe: Yes.
 * @note Other threads continue to run during sleep.
 * @note Actual sleep time may be longer due to system scheduling.
 * @note If ms <= 0, the function returns immediately without sleeping.
 * @note On POSIX systems, sleep is interruptible by signals but will continue
 *       for the remaining time after handling EINTR.
 */
void sleep_ms(int ms);

/* System Information Functions */

/**
 * Returns the current process ID.
 * @return Process ID as an integer, or -1 on error (rare).
 * @note Thread-safe: Yes.
 * @note Process ID remains constant throughout the process lifetime.
 */
int get_pid();

/**
 * Returns the current thread ID as an unsigned long.
 * @return Thread ID as unsigned long for cross-platform compatibility.
 * @note Thread-safe: Yes.
 * @note On Windows, returns the thread ID. On POSIX, returns pthread_t cast to unsigned long.
 * @warning pthread_t is an opaque type and may not be safely convertible to unsigned long
 *          on all platforms. Use this function for logging/debugging only, not as a
 *          reliable unique identifier for thread synchronization.
 */
unsigned long get_tid();

/**
 * Returns the number of available CPU cores.
 * @return Number of CPU cores, or -1 on error.
 * @note Thread-safe: Yes.
 * @note Returns online processors, which may be less than total processors.
 * @note The returned value may change if CPUs are hot-plugged or taken offline.
 * @note Returns 0 is never expected - if you receive 0, treat it as an error.
 */
long get_ncpus();

/**
 * Returns the parent process ID.
 * @return Parent process ID as an integer, or -1 on error.
 * @note Thread-safe: Yes.
 * @note On POSIX: Returns the parent process ID directly via getppid().
 * @note On Windows: Uses toolhelp API to enumerate processes and find parent.
 *       This may be slightly slower and can fail if process access is restricted.
 * @note The parent process ID may change if the parent exits (POSIX: reparented
 *       to init/systemd; Windows: orphaned processes retain original parent PID).
 */
int get_ppid();

/**
 * Returns the current user ID or equivalent identifier.
 * @return User identifier as unsigned integer, or (unsigned int)-1 on error.
 * @note Thread-safe: Yes.
 * @note On POSIX: Returns the real user ID (UID) via getuid().
 * @note On Windows: Returns a hash of the user's Security Identifier (SID).
 *       Windows SIDs are variable-length, so a 32-bit hash is computed for
 *       compatibility. The hash is consistent for the same user but may not
 *       match numeric values from other Windows APIs.
 */
unsigned int get_uid();

/**
 * Returns the current group ID or equivalent identifier.
 * @return Group identifier as unsigned integer, or (unsigned int)-1 on error.
 * @note Thread-safe: Yes.
 * @note On POSIX: Returns the real group ID (GID) via getgid().
 * @note On Windows: Returns a hash of the primary group's Security Identifier (SID).
 *       Windows SIDs are variable-length, so a 32-bit hash is computed for
 *       compatibility. The hash is consistent for the same group.
 */
unsigned int get_gid();

/**
 * Returns the current user name.
 * @return Pointer to static string containing username, or NULL on error.
 * @note Thread-safe: No (returns pointer to static data).
 * @note On POSIX: Uses getpwuid() which returns pointer to static data that may
 *       be overwritten by subsequent calls to getpwuid or related functions.
 * @note On Windows: Uses GetUserNameA() with a static buffer. The buffer may be
 *       overwritten by subsequent calls to get_username().
 * @note Caller should not modify or free the returned string.
 * @note Copy the string if you need to keep it across multiple calls or threads.
 */
char* get_username();

/**
 * Returns the current group name.
 * @return Pointer to static string containing group name, or NULL on error.
 * @note Thread-safe: No (returns pointer to static data).
 * @note On POSIX: Uses getgrgid() which returns pointer to static data that may
 *       be overwritten by subsequent calls to getgrgid or related functions.
 * @note On Windows: Looks up the primary group name from the user token using
 *       LookupAccountSidA() with a static buffer. May be slower than POSIX version.
 * @note Caller should not modify or free the returned string.
 * @note Copy the string if you need to keep it across multiple calls or threads.
 * @note On Windows, returns the primary group from the user's access token.
 */
char* get_groupname();

#ifdef __cplusplus
}
#endif

#endif /* SOLIDC_THREADS_H */
