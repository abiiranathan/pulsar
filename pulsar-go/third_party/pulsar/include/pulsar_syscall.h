#ifndef PULSAR_SYSCALL_H
#define PULSAR_SYSCALL_H

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define INLINE      __attribute__((always_inline)) static inline

/**
 * ============================================================================
 * PULSAR ZERO-OVERHEAD RAW SYSCALL SUBSYSTEM
 * ============================================================================
 *
 * @file pulsar_syscall.h
 * @brief Direct Linux x86-64 kernel syscall wrappers bypassing Glibc
 *        cancellation points and thread-local storage overhead.
 *
 * Scope: Linux, x86-64, kernel >= 6.0 only. This header assumes _GNU_SOURCE
 * is defined by the build (see CMakeLists.txt) so accept4() and friends are
 * visible from <sys/socket.h>. There is no portability fallback for other
 * OSes or architectures — pulsar does not target them.
 *
 * ----------------------------------------------------------------------------
 * 1. THE PROBLEM WITH STANDARD GLIBC WRAPPERS
 * ----------------------------------------------------------------------------
 * Standard Glibc I/O functions (read, write, recv, send, close, accept4) are
 * mandated by POSIX to be thread cancellation points. On every single call:
 *   a) Glibc checks thread cancellation state (__pthread_enable_asynccancel /
 *      internal_syscall_cancel).
 *   b) Glibc tests thread-local storage (TLS) control structures.
 *   c) On error, Glibc translates the kernel's negative return value and writes
 *      to the thread-local `errno` variable via `__errno_location()`.
 *
 * In high-throughput event loops servicing hundreds of thousands of requests
 * per second, Glibc's cancellation infrastructure accounts for ~5-8% of total
 * CPU cycles and induces needless L1/TLS cache misses.
 *
 * ----------------------------------------------------------------------------
 * 2. LINUX x86-64 SYSCALL ABI SPECIFICATION
 * ----------------------------------------------------------------------------
 * Syscall Instruction: `syscall`
 *   - Syscall Number: Loaded into %rax
 *   - Arguments:      %rdi (arg1), %rsi (arg2), %rdx (arg3),
 *                     %r10 (arg4), %r8  (arg5), %r9  (arg6)
 *     *CRITICAL*: Kernel ABI uses %r10 for arg4, whereas the userland C ABI
 *                 uses %rcx.
 *   - Clobbered:      %rcx (kernel stores user %rip),
 *                     %r11 (kernel stores user %rflags)
 *   - Return Value:   Returned in %rax, as a FULL 64-BIT WORD regardless of
 *                     the C return type of the wrapper (int, ssize_t, ...).
 *                     * Success: Non-negative value (>= 0).
 *                     * Failure: Negative error code in range [-4095, -1]
 *                                (i.e. -errno, such as -EAGAIN = -11).
 *     *CRITICAL*: The `"=a"(ret)` output constraint must bind to a 64-bit
 *                 (`long`) variable. Binding it to a narrower type (`int`)
 *                 causes the compiler to read only the low 32 bits of %rax,
 *                 silently discarding the high bits before the ABI success/
 *                 error range check ever runs. Narrow to the wrapper's
 *                 declared return type only *after* that check has passed.
 *
 * ----------------------------------------------------------------------------
 * 3. TWO CONVENTIONS PROVIDED
 * ----------------------------------------------------------------------------
 * A) `raw_*` functions (POSIX-compatible):
 *    - On failure, sets thread-local `errno = -ret` and returns `-1`.
 *    - Drop-in replacement for standard libc calls with zero cancellation tax.
 *
 * B) `sys_*_direct` functions (Pure Kernel Register ABI):
 *    - Returns positive bytes on success, or negative errno (e.g. `-EAGAIN`) on error.
 *    - NEVER touches `errno` or Thread-Local Storage. Maximum possible performance.
 *
 * ============================================================================
 * CAVEATS & SAFETY INVARIANTS
 * ============================================================================
 * 1. PTHREAD CANCELLATION:
 *    Threads blocked on these raw syscalls will NOT wake up from `pthread_cancel()`
 *    until a non-raw cancellation point is reached or a signal is delivered.
 *    (Safe and desirable for non-blocking epoll event loops).
 *
 * 2. ADDRESS SANITIZER & VALGRIND:
 *    Memory sanitizers intercept Glibc wrappers to track memory initialization.
 *    Raw assembly bypasses these hooks. When compiling with AddressSanitizer
 *    (-fsanitize=address), this file automatically falls back to Glibc wrappers.
 *
 * 3. DIRECT RETURN ERROR CHECKING:
 *    When using `sys_*_direct()`, you MUST check `ret == -EAGAIN` or `ret < 0`.
 *    Checking `errno` after calling a `_direct` function is a BUG because `errno`
 *    will retain its old, stale value.
 *
 * 4. SIGPIPE ON WRITE/SEND TO A CLOSED PEER:
 *    Bypassing Glibc does NOT bypass kernel signal delivery. `raw_write`,
 *    `sys_write_direct`, `raw_send`, and `sys_send_direct` will still raise
 *    `SIGPIPE` (default action: process termination) if the peer has closed
 *    its end of a stream socket or pipe. Callers in a server event loop must
 *    either ignore/handle `SIGPIPE` (e.g. `signal(SIGPIPE, SIG_IGN)`) or pass
 *    `MSG_NOSIGNAL` in `flags` to the send-family calls, exactly as with the
 *    Glibc equivalents.
 * ============================================================================
 */

/* Raw syscalls are used everywhere except under AddressSanitizer, where
 * inline asm bypasses ASan's interceptors and would hide real bugs in the
 * memory passed to read/recv/write/send. ASan builds fall back to the
 * equivalent Glibc call so buffer instrumentation still works. */
#if defined(__SANITIZE_ADDRESS__)
#define PULSAR_FAST_SYSCALLS 0
#else
#define PULSAR_FAST_SYSCALLS 1
#endif

/* ============================================================================
 * POSIX-COMPATIBLE WRAPPERS (Sets errno, returns -1 on failure)
 * ============================================================================ */

/**
 * @brief Raw non-cancelling write(2) syscall.
 *
 * @param fd    Target file descriptor.
 * @param buf   Buffer to write from.
 * @param count Number of bytes to write.
 * @return Number of bytes written on success, or -1 on error (errno set).
 */
INLINE ssize_t raw_write(int fd, const void* buf, size_t count) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_write), "D"(fd), "S"(buf), "d"(count)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (ssize_t)ret;
#else
    return write(fd, buf, count);
#endif
}

/**
 * @brief Raw non-cancelling read(2) syscall.
 *
 * @param fd    Target file descriptor.
 * @param buf   Buffer to read into.
 * @param count Maximum number of bytes to read.
 * @return Number of bytes read on success, 0 on EOF, or -1 on error (errno set).
 */
INLINE ssize_t raw_read(int fd, void* buf, size_t count) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_read), "D"(fd), "S"(buf), "d"(count)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (ssize_t)ret;
#else
    return read(fd, buf, count);
#endif
}

/**
 * @brief Raw non-cancelling close(2) syscall.
 *
 * @param fd File descriptor to close.
 * @return 0 on success, or -1 on error (errno set).
 */
INLINE int raw_close(int fd) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_close), "D"(fd)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (int)ret;
#else
    return close(fd);
#endif
}

/**
 * @brief Raw non-cancelling recv(2) / recvfrom(2) syscall.
 *
 * @param fd    Socket file descriptor.
 * @param buf   Destination buffer.
 * @param len   Maximum bytes to receive.
 * @param flags Receive flags (e.g. MSG_PEEK, MSG_DONTWAIT).
 * @return Number of bytes received on success, 0 on EOF, or -1 on error (errno set).
 */
INLINE ssize_t raw_recv(int fd, void* buf, size_t len, int flags) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = 0; /* src_addr = NULL */
    register long r9 __asm__("r9") = 0; /* addrlen  = 0    */
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_recvfrom), "D"(fd), "S"(buf), "d"(len), "r"(r10), "r"(r8),
                       "r"(r9)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (ssize_t)ret;
#else
    return recv(fd, buf, len, flags);
#endif
}

/**
 * @brief Raw non-cancelling send(2) / sendto(2) syscall.
 *
 * @param fd    Socket file descriptor.
 * @param buf   Source buffer.
 * @param len   Number of bytes to send.
 * @param flags Send flags (e.g. MSG_NOSIGNAL, MSG_DONTWAIT).
 * @return Number of bytes sent on success, or -1 on error (errno set).
 * @note Does not suppress SIGPIPE. Pass MSG_NOSIGNAL in flags (or block/
 *       ignore SIGPIPE process-wide) when writing to a peer that may have
 *       closed its end of the connection.
 */
INLINE ssize_t raw_send(int fd, const void* buf, size_t len, int flags) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = 0; /* dest_addr = NULL */
    register long r9 __asm__("r9") = 0; /* addrlen   = 0    */
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_sendto), "D"(fd), "S"(buf), "d"(len), "r"(r10), "r"(r8),
                       "r"(r9)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (ssize_t)ret;
#else
    return send(fd, buf, len, flags);
#endif
}

/**
 * @brief Raw non-cancelling accept4(2) syscall.
 *
 * @param sockfd  Listening socket file descriptor.
 * @param addr    Pointer to sockaddr buffer to store client address.
 * @param addrlen Pointer to socklen_t with buffer capacity.
 * @param flags   Socket creation flags (e.g. SOCK_NONBLOCK | SOCK_CLOEXEC).
 * @return Accepted client fd on success, or -1 on error (errno set).
 */
INLINE int raw_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = flags;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_accept4), "D"(sockfd), "S"(addr), "d"(addrlen), "r"(r10)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (int)ret;
#else
    return accept4(sockfd, addr, addrlen, flags);
#endif
}

/* ============================================================================
 * EPOLL SYSCALLS — POSIX-COMPATIBLE WRAPPERS (Sets errno, returns -1)
 * ============================================================================
 *
 * All six epoll syscalls are cancellation points in Glibc (epoll_wait /
 * epoll_pwait / epoll_pwait2 block), so the raw forms below bypass
 * __pthread_enable_asynccancel exactly like the I/O wrappers above.
 * x86-64 numbers: create=213, create1=291, ctl=233, wait=232, pwait=281,
 * pwait2=441. Register map follows the standard ABI (arg4 in %r10, arg5 in
 * %r8, arg6 in %r9; %rcx/%r11 clobbered).
 *
 * The raw epoll_pwait / epoll_pwait2 syscalls take a SIXTH argument,
 * `sigsetsize`, which Glibc's 5-argument wrappers fill in as
 * `sizeof(sigset_t)`. The raw_* helpers here do the same implicitly so
 * callers keep the familiar 5-argument shape.
 *
 * epoll_pwait2 requires Linux >= 5.11; this header targets kernel >= 6.0,
 * so it is always available and no ENOSYS fallback is needed.
 */

/**
 * @brief Raw non-cancelling epoll_create(2) syscall (nr 213, 1 arg).
 *
 * @param size Historical hint, must be > 0; ignored by the kernel since
 *             Linux 2.6.8. Prefer raw_epoll_create1().
 * @return Epoll fd on success (close with raw_close/sys_close_direct),
 *         or -1 on error (errno set).
 */
INLINE int raw_epoll_create(int size) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_create), "D"(size)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (int)ret;
#else
    return epoll_create(size);
#endif
}

/**
 * @brief Raw non-cancelling epoll_create1(2) syscall (nr 291, 1 arg).
 *
 * @param flags 0 or EPOLL_CLOEXEC (set it: prevents fd leaks across exec).
 * @return Epoll fd on success, or -1 on error (errno set).
 */
INLINE int raw_epoll_create1(int flags) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_create1), "D"(flags)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (int)ret;
#else
    return epoll_create1(flags);
#endif
}

/**
 * @brief Raw non-cancelling epoll_ctl(2) syscall (nr 233, 4 args).
 *
 * @param epfd  Epoll instance fd.
 * @param op    EPOLL_CTL_ADD / EPOLL_CTL_MOD / EPOLL_CTL_DEL.
 * @param fd    Target descriptor.
 * @param event Interest + user data (may be NULL when op == EPOLL_CTL_DEL
 *              on kernels >= 2.6.9).
 * @return 0 on success, or -1 on error (errno set; ENOENT if the fd is not
 *         registered, EEXIST if ADD duplicates).
 */
INLINE int raw_epoll_ctl(int epfd, int op, int fd, struct epoll_event* event) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = (long)event;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_ctl), "D"(epfd), "S"(op), "d"(fd), "r"(r10)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (int)ret;
#else
    return epoll_ctl(epfd, op, fd, event);
#endif
}

/**
 * @brief Raw non-cancelling epoll_wait(2) syscall (nr 232, 4 args).
 *
 * This is the blocking poll point of every event loop and hence the most
 * valuable cancellation bypass in this file: Glibc's wrapper enters the
 * cancellation machinery on each of the potentially millions of waits per
 * day; the raw form issues the trap with no TLS traffic.
 *
 * @param epfd      Epoll instance fd.
 * @param events    Caller-allocated buffer for fired events.
 * @param maxevents Capacity of @p events (> 0, kernel caps at ~4096/INT_MAX).
 * @param timeout   Wait bound in milliseconds; -1 blocks indefinitely,
 *                  0 returns immediately.
 * @return Number of ready fds (>= 0), or -1 on error (errno set;
 *         EINTR when a signal arrived before any event).
 */
INLINE int raw_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = timeout;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_wait), "D"(epfd), "S"(events), "d"(maxevents), "r"(r10)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (int)ret;
#else
    return epoll_wait(epfd, events, maxevents, timeout);
#endif
}

/**
 * @brief Raw non-cancelling epoll_pwait(2) syscall (nr 281, 6 raw args).
 *
 * Atomically swaps the thread signal mask for @p sigmask during the wait
 * (the epoll analogue of pselect): the equivalent of pthread_sigmask +
 * epoll_wait + restore with no race window for signal delivery.
 *
 * @param epfd      Epoll instance fd.
 * @param events    Caller-allocated buffer for fired events.
 * @param maxevents Capacity of @p events (> 0).
 * @param timeout   Wait bound in milliseconds; -1 blocks indefinitely.
 * @param sigmask   Temporary signal mask, or NULL for plain epoll_wait
 *                  semantics. The hidden 6th raw argument (sigsetsize) is
 *                  passed as sizeof(sigset_t) automatically.
 * @return Number of ready fds (>= 0), or -1 on error (errno set).
 */
INLINE int raw_epoll_pwait(int epfd, struct epoll_event* events, int maxevents, int timeout,
                           const sigset_t* sigmask) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = timeout;
    register long r8 __asm__("r8") = (long)sigmask;
    register long r9 __asm__("r9") = (long)sizeof(sigset_t);
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_pwait), "D"(epfd), "S"(events), "d"(maxevents), "r"(r10),
                       "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (int)ret;
#else
    return epoll_pwait(epfd, events, maxevents, timeout, sigmask);
#endif
}

/**
 * @brief Raw non-cancelling epoll_pwait2(2) syscall (nr 441, 6 raw args).
 *
 * Identical to raw_epoll_pwait except the timeout is a `struct timespec`
 * (nanosecond resolution, same rules as pselect/ppoll): NULL blocks
 * indefinitely, {0,0} polls once, negative fields are EINVAL.
 *
 * @param epfd      Epoll instance fd.
 * @param events    Caller-allocated buffer for fired events.
 * @param maxevents Capacity of @p events (> 0).
 * @param timeout   Nanosecond-precision deadline, or NULL to block
 *                  indefinitely. The hidden 6th raw argument (sigsetsize)
 *                  is passed as sizeof(sigset_t) automatically.
 * @param sigmask   Temporary signal mask, or NULL for plain wait semantics.
 * @return Number of ready fds (>= 0), or -1 on error (errno set).
 */
INLINE int raw_epoll_pwait2(int epfd, struct epoll_event* events, int maxevents,
                            const struct timespec* timeout, const sigset_t* sigmask) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = (long)timeout;
    register long r8 __asm__("r8") = (long)sigmask;
    register long r9 __asm__("r9") = (long)sizeof(sigset_t);
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_pwait2), "D"(epfd), "S"(events), "d"(maxevents),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return (int)ret;
#else
    return epoll_pwait2(epfd, events, maxevents, timeout, sigmask);
#endif
}

/* ============================================================================
 * EPOLL DIRECT REGISTER ABI HELPERS (Zero TLS / Zero errno writes)
 * ============================================================================
 *
 * Same zero-TLS contract as sys_*_direct above: the raw kernel value is
 * returned untouched (>= 0 success, negative -errno on failure). NEVER read
 * `errno` after calling these; test `ret < 0` and use `-ret` as the error.
 */

/**
 * @brief Direct kernel epoll_create1 returning -errno on failure.
 * @return >= 0: epoll fd. < 0: negative error number (e.g. -EMFILE, -EINVAL).
 */
INLINE int sys_epoll_create1_direct(int flags) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_create1), "D"(flags)
                     : "rcx", "r11", "memory");
    return (int)ret;
#else
    int r = epoll_create1(flags);
    return (r < 0) ? -errno : r;
#endif
}

/**
 * @brief Direct kernel epoll_create returning -errno on failure.
 * @return >= 0: epoll fd. < 0: negative error number.
 */
INLINE int sys_epoll_create_direct(int size) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_create), "D"(size)
                     : "rcx", "r11", "memory");
    return (int)ret;
#else
    int r = epoll_create(size);
    return (r < 0) ? -errno : r;
#endif
}

/**
 * @brief Direct kernel epoll_ctl returning -errno on failure.
 * @return 0: success. < 0: negative error number (e.g. -ENOENT, -EEXIST).
 */
INLINE int sys_epoll_ctl_direct(int epfd, int op, int fd, struct epoll_event* event) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = (long)event;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_ctl), "D"(epfd), "S"(op), "d"(fd), "r"(r10)
                     : "rcx", "r11", "memory");
    return (int)ret;
#else
    int r = epoll_ctl(epfd, op, fd, event);
    return (r < 0) ? -errno : 0;
#endif
}

/**
 * @brief Direct kernel epoll_wait returning -errno on failure.
 * @return >= 0: ready count. < 0: negative error number (e.g. -EINTR, -EBADF).
 */
INLINE int sys_epoll_wait_direct(int epfd, struct epoll_event* events, int maxevents, int timeout) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = timeout;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_wait), "D"(epfd), "S"(events), "d"(maxevents), "r"(r10)
                     : "rcx", "r11", "memory");
    return (int)ret;
#else
    int r = epoll_wait(epfd, events, maxevents, timeout);
    return (r < 0) ? -errno : r;
#endif
}

/**
 * @brief Direct kernel epoll_pwait returning -errno on failure.
 * @return >= 0: ready count. < 0: negative error number (e.g. -EINTR).
 */
INLINE int sys_epoll_pwait_direct(int epfd, struct epoll_event* events, int maxevents, int timeout,
                                  const sigset_t* sigmask) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = timeout;
    register long r8 __asm__("r8") = (long)sigmask;
    register long r9 __asm__("r9") = (long)sizeof(sigset_t);
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_pwait), "D"(epfd), "S"(events), "d"(maxevents), "r"(r10),
                       "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return (int)ret;
#else
    int r = epoll_pwait(epfd, events, maxevents, timeout, sigmask);
    return (r < 0) ? -errno : r;
#endif
}

/**
 * @brief Direct kernel epoll_pwait2 returning -errno on failure.
 * @return >= 0: ready count. < 0: negative error number (e.g. -EINTR).
 */
INLINE int sys_epoll_pwait2_direct(int epfd, struct epoll_event* events, int maxevents,
                                   const struct timespec* timeout, const sigset_t* sigmask) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = (long)timeout;
    register long r8 __asm__("r8") = (long)sigmask;
    register long r9 __asm__("r9") = (long)sizeof(sigset_t);
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_epoll_pwait2), "D"(epfd), "S"(events), "d"(maxevents),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return (int)ret;
#else
    int r = epoll_pwait2(epfd, events, maxevents, timeout, sigmask);
    return (r < 0) ? -errno : r;
#endif
}

/* ============================================================================
 * DIRECT REGISTER ABI HELPERS (Zero TLS / Zero errno writes)
 * ============================================================================ */

/**
 * @brief Direct kernel write(2) returning -errno on failure.
 *
 * @return >= 0: bytes written.
 *         < 0:  negative error number (e.g. -EAGAIN, -EPIPE, -EBADF).
 */
INLINE ssize_t sys_write_direct(int fd, const void* buf, size_t count) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_write), "D"(fd), "S"(buf), "d"(count)
                     : "rcx", "r11", "memory");
    return (ssize_t)ret;
#else
    ssize_t r = write(fd, buf, count);
    return (r < 0) ? -errno : r;
#endif
}

/**
 * @brief Direct kernel writev(2) returning -errno on failure.
 *
 * Single-syscall gather write for split header + body responses. Same
 * zero-TLS contract as sys_write_direct: never touches errno.
 *
 * @param fd     Target file descriptor.
 * @param iov    Scatter/gather vector array.
 * @param iovcnt Number of entries in iov.
 * @return >= 0: bytes written (may be short; loop on partials).
 *         < 0:  negative error number (e.g. -EAGAIN, -EPIPE).
 */
INLINE ssize_t sys_writev_direct(int fd, const struct iovec* iov, int iovcnt) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_writev), "D"(fd), "S"(iov), "d"(iovcnt)
                     : "rcx", "r11", "memory");
    return (ssize_t)ret;
#else
    ssize_t r = writev(fd, iov, iovcnt);
    return (r < 0) ? -errno : r;
#endif
}

/**
 * @brief Direct kernel read(2) returning -errno on failure.
 *
 * @return > 0:  bytes read.
 *         == 0: EOF reached.
 *         < 0:  negative error number (e.g. -EAGAIN, -ECONNRESET).
 */
INLINE ssize_t sys_read_direct(int fd, void* buf, size_t count) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_read), "D"(fd), "S"(buf), "d"(count)
                     : "rcx", "r11", "memory");
    return (ssize_t)ret;
#else
    ssize_t r = read(fd, buf, count);
    return (r < 0) ? -errno : r;
#endif
}

/**
 * @brief Direct kernel close(2) returning -errno on failure.
 *
 * @return 0:   success.
 *         < 0: negative error number (e.g. -EBADF, -EIO).
 */
INLINE int sys_close_direct(int fd) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_close), "D"(fd)
                     : "rcx", "r11", "memory");
    return (int)ret;
#else
    int r = close(fd);
    return (r < 0) ? -errno : 0;
#endif
}

/**
 * @brief Direct kernel sendto(2) returning -errno on failure.
 *
 * @return >= 0: bytes sent.
 *         < 0:  negative error number (e.g. -EAGAIN, -EPIPE).
 * @note Does not suppress SIGPIPE. Pass MSG_NOSIGNAL in flags (or block/
 *       ignore SIGPIPE process-wide) when writing to a peer that may have
 *       closed its end of the connection.
 */
INLINE ssize_t sys_send_direct(int fd, const void* buf, size_t len, int flags) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = 0;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_sendto), "D"(fd), "S"(buf), "d"(len), "r"(r10), "r"(r8),
                       "r"(r9)
                     : "rcx", "r11", "memory");
    return (ssize_t)ret;
#else
    ssize_t r = send(fd, buf, len, flags);
    return (r < 0) ? -errno : r;
#endif
}

/**
 * @brief Direct kernel recvfrom(2) returning -errno on failure.
 *
 * @return > 0:  bytes received.
 *         == 0: orderly peer disconnect (EOF).
 *         < 0:  negative error number (e.g. -EAGAIN, -ECONNRESET).
 */
INLINE ssize_t sys_recv_direct(int fd, void* buf, size_t len, int flags) {
#if PULSAR_FAST_SYSCALLS
    long ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = 0;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_recvfrom), "D"(fd), "S"(buf), "d"(len), "r"(r10), "r"(r8),
                       "r"(r9)
                     : "rcx", "r11", "memory");
    return (ssize_t)ret;
#else
    ssize_t r = recv(fd, buf, len, flags);
    return (r < 0) ? -errno : r;
#endif
}

#endif /* PULSAR_SYSCALL_H */
