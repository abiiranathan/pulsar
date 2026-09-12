/**
 * @file events.h
 * @brief Thin Linux epoll event-loop wrapper over raw syscalls (no libc).
 *
 * This header is the sole event backend for pulsar. It talks to the kernel
 * exclusively through the zero-overhead traps in pulsar_syscall.h
 * (raw_epoll_create1 / raw_epoll_ctl / raw_epoll_wait), so no call here is
 * a pthread cancellation point and no call touches thread-local `errno`
 * storage on the fast path beyond the single write the POSIX-compatible
 * wrappers perform on failure.
 *
 * ----------------------------------------------------------------------------
 * DESIGN
 * ----------------------------------------------------------------------------
 * This is a thin wrapper, not a registry: it keeps no bookkeeping of its
 * own. The kernel's `struct epoll_event :: data` field is a union
 * (`epoll_data_t`), so it can hold the caller's `void*` directly
 * (`ev.data.ptr`) instead of an fd. event_wait() hands that pointer straight
 * back on the fired event with no lookup, no table, and no allocation.
 *
 * The consequence of storing the pointer instead of the fd: this header
 * cannot report an fd for a fired event, because the kernel never carries
 * one back. Callers wanting to know which descriptor fired must store the
 * fd inside whatever struct they pass as @p data (e.g. PulsarConn already
 * has one) and read it back from there.
 *
 * Per-queue state (private to the event loop thread that owns the queue;
 * no locking is performed):
 *   - epfd        The kernel epoll instance (CLOEXEC).
 *
 * That is the entire struct. There are no growable tables: the caller's
 * pointer lives in the kernel's own event record for as long as the fd is
 * registered, and event_wait()'s scratch buffer for the raw batch is
 * caller-owned (see @p events / @p max_events below), so this header never
 * allocates. The queue storage itself is caller-owned as well: the caller
 * provides the `event_queue_t` (e.g. as an array element) and initializes
 * it with event_queue_create().
 *
 * ----------------------------------------------------------------------------
 * EDGE-TRIGGERED DISCIPLINE
 * ----------------------------------------------------------------------------
 * All registrations use EPOLLET. Events fire only on state *transitions*,
 * so after any readable/writable notification the fd MUST be drained
 * (read/write until -EAGAIN) before returning to the loop, or readiness
 * will be lost. pulsar's handle_read/handle_write already obey this.
 *
 * HUP coalescing: the kernel may report EPOLLRDHUP without EPOLLIN when the
 * last byte was already drained, and EPOLLHUP alone on a full hangup. The
 * translation in event_wait() therefore maps
 *   readable = EPOLLIN | EPOLLRDHUP,
 *   writable = EPOLLOUT,
 *   error    = EPOLLERR | EPOLLHUP,
 *   hup      = EPOLLHUP | EPOLLRDHUP,
 * so every shutdown condition reaches existing dispatch code: RDHUP drives
 * handle_read (which observes EOF), HUP/ERR drives the error branch. Callers
 * MUST still drain on readable even when no bytes arrive (a 0-byte read is
 * the EOF signal), and SHOULD treat event_is_hup() as a close hint.
 *
 * ----------------------------------------------------------------------------
 * SCOPE
 * ----------------------------------------------------------------------------
 * Linux only, via pulsar_syscall.h (Linux/x86-64/kernel >= 6.0). There is no
 * portability fallback; pulsar does not target other platforms.
 *
 * Threading: one queue per event-loop thread (as pulsar_run() creates).
 * Concurrent calls on the SAME queue from several threads are not safe;
 * concurrent calls on DIFFERENT queues are.
 */

#ifndef PULSAR_EVENTS_H
#define PULSAR_EVENTS_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "pulsar_syscall.h"

/* ----------------------------------------------------------------
 * Opaque types
 * ---------------------------------------------------------------- */

/** Kernel event queue. Initialize caller-owned storage with
 *  event_queue_create(), release the kernel resource (without freeing
 *  anything) with event_queue_close(). Only the pointer is ever shared
 *  (e.g. PulsarConn::owner_queue). */
typedef struct event_queue event_queue_t;

/**
 * One readiness notification written by event_wait().
 * `data` is exactly the pointer passed to whichever registration call
 * (event_add_read, event_add_server, event_mod_read, or event_mod_write)
 * last registered the fd; it is NULL only if that call was itself passed
 * NULL (e.g. a listening socket with no per-connection state).
 */
typedef struct event event_t;
struct event {
    void* data;    /**< Opaque pointer registered with the descriptor. */
    bool readable; /**< Read-ready (or incoming connection on a listener). */
    bool writable; /**< Write-ready. */
    bool error;    /**< Fatal condition (EPOLLERR, or hangup EPOLLHUP). */
    bool hup;      /**< Peer shutdown (EPOLLRDHUP) or hangup (EPOLLHUP). */
};

struct event_queue {
    int epfd; /**< Kernel epoll fd (EPOLL_CLOEXEC). */
};

/* ----------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------- */

/**
 * Initializes a caller-provided event queue.
 *
 * Uses raw_epoll_create1(EPOLL_CLOEXEC) — CLOEXEC is mandatory so worker
 * restarts/exec never leak the epoll fd. No cancellation point is entered.
 * Performs no allocation; @p q must point to valid (e.g. array) storage.
 *
 * @param q Caller-owned queue storage to initialize.
 * @return 0 on success, -1 on failure (errno set).
 */
static inline int event_queue_create(event_queue_t* q) {
    if (!q) {
        errno = EINVAL;
        return -1;
    }
    q->epfd = raw_epoll_create1(EPOLL_CLOEXEC);
    if (q->epfd < 0) {
        q->epfd = -1;
        return -1;
    }
    return 0;
}

/**
 * Closes an event queue. Registered descriptors are NOT closed (closing the
 * epoll fd implicitly drops the kernel interest list). Performs no free:
 * the queue storage remains owned by the caller. NULL is safely ignored.
 */
static inline void event_queue_close(event_queue_t* q) {
    if (!q) return;
    if (q->epfd >= 0) {
        sys_close_direct(q->epfd); /* best-effort; nothing to report from close */
        q->epfd = -1;
    }
}

/* ----------------------------------------------------------------
 * Registration
 * ---------------------------------------------------------------- */

/**
 * Registers @p fd on @p queue for edge-triggered read events
 * (EPOLLIN | EPOLLRDHUP | EPOLLET). Re-registering an already-registered
 * fd (EEXIST from the kernel) falls back to EPOLL_CTL_MOD, updating its
 * interest set and data pointer in place.
 *
 * @param queue Event queue.
 * @param fd    Descriptor to monitor (must be non-blocking for ET).
 * @param data  Opaque pointer stored with the event and returned by
 *              event_get_data() when the event fires. Must remain valid
 *              until the fd is removed or re-registered with a new value.
 * @return 0 on success, -1 on failure (errno set).
 */
static inline int event_add_read(event_queue_t* queue, int fd, void* data) {
    if (!queue || fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = (uint32_t)(EPOLLIN | EPOLLRDHUP | EPOLLET);
    ev.data.ptr = data;

    int r = raw_epoll_ctl(queue->epfd, EPOLL_CTL_ADD, fd, &ev);
    if (r != 0 && errno == EEXIST) r = raw_epoll_ctl(queue->epfd, EPOLL_CTL_MOD, fd, &ev);
    return r;
}

/**
 * Registers the listening @p server_fd so only one thread is woken per
 * incoming connection (EPOLLEXCLUSIVE) where the kernel supports it — safe
 * because pulsar gives each worker its own listen fd via SO_REUSEPORT.
 *
 * Unlike event_add_read(), re-registering an already-registered fd is not
 * done via EPOLL_CTL_MOD: the kernel permanently forbids EPOLL_CTL_MOD on
 * any epfd/fd pair that was ever added with EPOLLEXCLUSIVE (EINVAL, by
 * design, not just on first use). Since a server fd's registration never
 * changes (always the same interest set and a NULL data pointer), EEXIST
 * from EPOLL_CTL_ADD means the fd is already registered exactly as
 * intended, so it is treated as success rather than retried as EPOLL_CTL_MOD.
 *
 * @return 0 on success, -1 on failure (errno set).
 */
static inline int event_add_server(event_queue_t* queue, int server_fd) {
    if (!queue || server_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = (uint32_t)(EPOLLIN | EPOLLET | EPOLLEXCLUSIVE);
    ev.data.ptr = NULL;

    int r = raw_epoll_ctl(queue->epfd, EPOLL_CTL_ADD, server_fd, &ev);
    if (r != 0 && errno == EEXIST) return 0;
    return r;
}

/**
 * Removes all registrations for @p fd from @p queue.
 * Safe to call before or after close(fd), or for fds never added:
 * ENOENT/EBADF from the kernel are coalesced to success (0).
 *
 * @return 0 on success, -1 on failure (errno set; only for genuine errors
 *         such as an invalid queue or a dead epoll fd).
 */
static inline int event_delete(event_queue_t* queue, int fd) {
    if (!queue || fd < 0) {
        errno = EINVAL;
        return -1;
    }
    /* NULL event is valid for EPOLL_CTL_DEL since Linux 2.6.9. */
    int r = raw_epoll_ctl(queue->epfd, EPOLL_CTL_DEL, fd, NULL);
    if (r != 0 && (errno == ENOENT || errno == EBADF)) return 0;
    return r;
}

/* ----------------------------------------------------------------
 * Mode switching
 * ---------------------------------------------------------------- */

/**
 * Switches @p fd to edge-triggered write monitoring
 * (EPOLLOUT | EPOLLET | EPOLLRDHUP). Typically called after a send()
 * returns EAGAIN. @p fd must already be registered; the kernel returns
 * -1 with errno == ENOENT otherwise.
 *
 * @return 0 on success, -1 on failure (errno set).
 */
static inline int event_mod_write(event_queue_t* queue, int fd, void* data) {
    if (!queue || fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = (uint32_t)(EPOLLOUT | EPOLLET | EPOLLRDHUP);
    ev.data.ptr = data;
    return raw_epoll_ctl(queue->epfd, EPOLL_CTL_MOD, fd, &ev);
}

/**
 * Switches @p fd back to edge-triggered read monitoring.
 * Call once a pending write has fully drained. @p fd must already be
 * registered; the kernel returns -1 with errno == ENOENT otherwise.
 *
 * @return 0 on success, -1 on failure (errno set).
 */
static inline int event_mod_read(event_queue_t* queue, int fd, void* data) {
    if (!queue || fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = (uint32_t)(EPOLLIN | EPOLLRDHUP | EPOLLET);
    ev.data.ptr = data;
    return raw_epoll_ctl(queue->epfd, EPOLL_CTL_MOD, fd, &ev);
}

/* ----------------------------------------------------------------
 * Waiting
 * ---------------------------------------------------------------- */

/**
 * Waits for events on @p queue via the raw (non-cancelling) wait trap.
 *
 * @param queue       Event queue.
 * @param raw_events  Caller-allocated scratch buffer of at least
 *                    @p max_events `struct epoll_event` elements, used for
 *                    the kernel batch. This header keeps no scratch buffer
 *                    of its own; the caller owns and reuses it.
 * @param events      Caller-allocated array of at least @p max_events
 *                    `event_t` elements; populated on return.
 * @param max_events  Capacity of @p raw_events and @p events (> 0).
 * @param timeout_ms  Milliseconds to wait; -1 blocks indefinitely,
 *                    0 returns immediately.
 * @return Number of events written to @p events (>= 0), or -1 on
 *         error (errno set; EINTR when a signal arrived first — the
 *         caller is expected to retry, as pulsar's workers do).
 */
static inline int event_wait(event_queue_t* queue, struct epoll_event* raw_events, event_t* events,
                             int max_events, int timeout_ms) {
    if (!queue || !raw_events || !events || max_events <= 0) {
        errno = EINVAL;
        return -1;
    }

    int n = raw_epoll_wait(queue->epfd, raw_events, max_events, timeout_ms);
    if (n <= 0) return n;

    for (int i = 0; i < n; i++) {
        uint32_t e = raw_events[i].events;
        events[i].data = raw_events[i].data.ptr;
        /* HUP coalescing: see the header-block rationale above. */
        events[i].readable = (e & (EPOLLIN | EPOLLRDHUP)) != 0;
        events[i].writable = (e & EPOLLOUT) != 0;
        events[i].error = (e & (EPOLLERR | EPOLLHUP)) != 0;
        events[i].hup = (e & (EPOLLHUP | EPOLLRDHUP)) != 0;
    }
    return n;
}

/* ----------------------------------------------------------------
 * Event inspection
 * ---------------------------------------------------------------- */

/** Returns the opaque data pointer registered with this event (NULL if the
 *  registering call was itself passed NULL, e.g. a listening socket). */
static inline void* event_get_data(const event_t* event) { return event ? event->data : NULL; }

/** Returns true if the event indicates data available for reading (or a
 *  new connection on a listening socket, or a peer shutdown to drain). */
static inline bool event_is_read(const event_t* event) { return event && event->readable; }

/** Returns true if the event indicates the socket is ready for writing. */
static inline bool event_is_write(const event_t* event) { return event && event->writable; }

/** Returns true if the event indicates an error or a full hangup. */
static inline bool event_is_error(const event_t* event) { return event && event->error; }

/** Returns true if the peer shut down its write side or hung up
 *  (EPOLLRDHUP/EPOLLHUP). Treat as a close hint: drain reads first
 *  (a 0-byte read confirms EOF), then close. */
static inline bool event_is_hup(const event_t* event) { return event && event->hup; }

#endif /* PULSAR_EVENTS_H */
