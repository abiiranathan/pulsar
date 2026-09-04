#ifndef PULSAR_SYSCALL_H
#define PULSAR_SYSCALL_H

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
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
 * @brief Direct Linux kernel syscall wrappers bypassing Glibc cancellation
 *        points and thread-local storage overhead.
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
 *   - Return Value:   Returned in %rax.
 *                     * Success: Non-negative value (>= 0).
 *                     * Failure: Negative error code in range [-4095, -1]
 *                                (i.e. -errno, such as -EAGAIN = -11).
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
 * 4. PORTABILITY:
 *    On non-x86_64 or non-Linux systems (macOS, FreeBSD, ARM64), all functions
 *    automatically fall back to standard libc/POSIX calls with identical semantics.
 * ============================================================================
 */

#if defined(__x86_64__) && defined(__linux__) && !defined(__SANITIZE_ADDRESS__)
    #define PULSAR_FAST_SYSCALLS 1
#else
    #define PULSAR_FAST_SYSCALLS 0
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
    ssize_t ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_write), "D"(fd), "S"(buf), "d"(count)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return ret;
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
    ssize_t ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_read), "D"(fd), "S"(buf), "d"(count)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return ret;
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
    int ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"((long)SYS_close), "D"(fd) : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = -ret;
        return -1;
    }
    return ret;
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
    ssize_t ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = 0; /* src_addr = NULL */
    register long r9 __asm__("r9") = 0; /* addrlen  = 0    */
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_recvfrom), "D"(fd), "S"(buf), "d"(len), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return ret;
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
 */
INLINE ssize_t raw_send(int fd, const void* buf, size_t len, int flags) {
#if PULSAR_FAST_SYSCALLS
    ssize_t ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = 0; /* dest_addr = NULL */
    register long r9 __asm__("r9") = 0; /* addrlen   = 0    */
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_sendto), "D"(fd), "S"(buf), "d"(len), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = (int)(-ret);
        return -1;
    }
    return ret;
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
#if PULSAR_FAST_SYSCALLS && defined(SYS_accept4)
    int ret;
    register long r10 __asm__("r10") = flags;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_accept4), "D"(sockfd), "S"(addr), "d"(addrlen), "r"(r10)
                     : "rcx", "r11", "memory");
    if (unlikely((unsigned long)ret >= (unsigned long)-4095)) {
        errno = -ret;
        return -1;
    }
    return ret;
#elif defined(__linux__)
    return accept4(sockfd, addr, addrlen, flags);
#else
    int fd = accept(sockfd, addr, addrlen);
    if (fd >= 0 && (flags & SOCK_NONBLOCK)) {
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    }
    return fd;
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
    ssize_t ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_write), "D"(fd), "S"(buf), "d"(count)
                     : "rcx", "r11", "memory");
    return ret;
#else
    ssize_t r失 = write(fd, buf, count);
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
#if PULSAR_FAST_SYSCALLS && defined(SYS_writev)
    ssize_t ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_writev), "D"(fd), "S"(iov), "d"(iovcnt)
                     : "rcx", "r11", "memory");
    return ret;
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
    ssize_t ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_read), "D"(fd), "S"(buf), "d"(count)
                     : "rcx", "r11", "memory");
    return ret;
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
    int ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"((long)SYS_close), "D"(fd) : "rcx", "r11", "memory");
    return ret;
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
 */
INLINE ssize_t sys_send_direct(int fd, const void* buf, size_t len, int flags) {
#if PULSAR_FAST_SYSCALLS
    ssize_t ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = 0;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_sendto), "D"(fd), "S"(buf), "d"(len), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
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
    ssize_t ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = 0;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"((long)SYS_recvfrom), "D"(fd), "S"(buf), "d"(len), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
#else
    ssize_t r骚 = recv(fd, buf, len, flags);
    return (r < 0) ? -errno : r;
#endif
}

#endif /* PULSAR_SYSCALL_H */
