/**
 * @file poller.h
 * @brief Cross-platform readiness polling for high-performance servers.
 *
 * A uniform, readiness-style API over the platform multiplexors:
 *
 *   Linux          epoll (edge-triggered capable, EPOLLEXCLUSIVE accept)
 *   macOS / BSD    kqueue (EV_CLEAR for edge semantics, EV_EOF for hup)
 *   Windows        WSAPoll (level-triggered; sockets only)
 *
 * The API shape mirrors what production web servers need (see the pulsar
 * project): edge-triggered registration with an opaque user pointer,
 * explicit read/write mode switching for send-drain loops, and exclusive
 * accept distribution across multiple acceptor threads.
 *
 * Trigger semantics:
 *   - With POLLER_EDGE, events are reported only on state *transitions*
 *     (Linux/kqueue). You must drain until EAGAIN. This is the
 *     high-performance mode.
 *   - Without POLLER_EDGE, events are reported whenever the condition
 *     holds (level-triggered). This is the only mode Windows supports;
 *     the flag is accepted and ignored there, so portable code should
 *     either handle both semantics or require POSIX.
 *
 * Example — minimal accept loop:
 * @code
 *   Poller* p = poller_new();
 *   poller_add(p, server_fd, POLLER_READ | POLLER_EDGE, NULL);
 *
 *   PollerEvent ev[64];
 *   int n = poller_wait(p, ev, 64, -1);
 *   for (int i = 0; i < n; i++) {
 *       if (poller_event_is_read(&ev[i])) {
 *           for (;;) {
 *               Socket* c = socket_accept(server, NULL, NULL); // EAGAIN -> break
 *               if (!c) break;
 *               poller_add(p, socket_fd(c), POLLER_READ | POLLER_EDGE, c);
 *           }
 *       }
 *   }
 * @endcode
 */

#ifndef SOLIDC_POLLER_H
#define SOLIDC_POLLER_H

#include "macros.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Interest flags for poller_add()/poller_mod(). */
typedef enum {
    POLLER_READ = 1 << 0, /**< Monitor/deliver read-readiness. */
    POLLER_WRITE = 1 << 1 /**< Monitor/deliver write-readiness. */
} PollerEvents;

/** Registration modifiers (OR with PollerEvents). */
typedef enum {
    POLLER_EDGE = 1 << 8,     /**< Edge-triggered (POSIX only; ignored on Windows). */
    POLLER_EXCLUSIVE = 1 << 9 /**< Wake one waiter only — for accept sockets
                                   (Linux EPOLLEXCLUSIVE; ignored elsewhere). */
} PollerFlags;

/** One readiness event returned by poller_wait(). */
typedef struct PollerEvent {
    int fd;        /**< Descriptor the event refers to. */
    void* data;    /**< Opaque pointer registered with the descriptor. */
    bool readable; /**< Read-ready (or new connection on a listen socket). */
    bool writable; /**< Write-ready. */
    bool error;    /**< Error condition (POLLERR). */
    bool hup;      /**< Peer closed / hung up (RDHUP / EV_EOF / HUP). */
} PollerEvent;

/** Opaque poller handle. Create with poller_new(), free with poller_free(). */
typedef struct Poller Poller;

/**
 * @brief Creates a new poller instance.
 * @return Ready-to-use poller, or NULL on failure (errno set).
 * @note Free with poller_free(). Not thread-safe for concurrent
 *       modification of the same poller; one poller per event loop.
 */
Poller* poller_new(void);

/**
 * @brief Frees a poller. Registered descriptors are NOT closed.
 * @param p Poller to free; NULL is safely ignored.
 */
void poller_free(Poller* p);

/**
 * @brief Registers a descriptor for the given events.
 *
 * @param p     Poller.
 * @param fd    Descriptor to monitor (socket on Windows; any fd on POSIX).
 * @param events POLLER_READ / POLLER_WRITE OR-combined, optionally with
 *              POLLER_EDGE and/or POLLER_EXCLUSIVE.
 * @param data  Opaque pointer returned by poller_event_data() when events
 *              fire. May be NULL.
 * @return 0 on success, -1 on failure (errno set).
 * @note Re-registering an existing descriptor updates its interest set
 *       (equivalent to poller_mod).
 */
int poller_add(Poller* p, int fd, int events, void* data);

/**
 * @brief Updates the interest set / user data of a registered descriptor.
 *
 * Typical use: switch to POLLER_WRITE after send() returns EAGAIN, then
 * back to POLLER_READ once the send buffer drains.
 *
 * @return 0 on success, -1 on failure (errno set; ENOENT if not added).
 */
int poller_mod(Poller* p, int fd, int events, void* data);

/**
 * @brief Removes a descriptor from the poller.
 *
 * Safe to call for a descriptor that was never added (returns 0). On
 * Linux, closing a descriptor removes it implicitly; calling poller_del
 * first is still recommended for clarity and for kqueue correctness.
 *
 * @return 0 on success, -1 on failure (errno set).
 */
int poller_del(Poller* p, int fd);

/**
 * @brief Waits for readiness events.
 *
 * @param p           Poller.
 * @param events      Caller-allocated array of at least @p max events.
 * @param max         Capacity of @p events (> 0).
 * @param timeout_ms  Milliseconds to wait; -1 blocks indefinitely,
 *                    0 returns immediately.
 * @return Number of events written to @p events (>= 0), or -1 on error
 *         (errno set). EINTR is reported as -1 with errno == EINTR.
 */
int poller_wait(Poller* p, PollerEvent* events, int max, int timeout_ms);

/**
 * @brief The descriptor a fired event refers to.
 * @param ev Event returned by poller_wait().
 * @return Descriptor, or -1 if ev is NULL.
 */
int poller_event_fd(const PollerEvent* ev);

/**
 * @brief The opaque pointer registered with this descriptor.
 * @return Registered pointer, or NULL if none/ev is NULL.
 */
void* poller_event_data(const PollerEvent* ev);

/** @brief True if the event reports read-readiness. */
bool poller_event_is_read(const PollerEvent* ev);

/** @brief True if the event reports write-readiness. */
bool poller_event_is_write(const PollerEvent* ev);

/** @brief True if the event reports an error condition. */
bool poller_event_is_error(const PollerEvent* ev);

/** @brief True if the peer closed / hung up (read side will hit EOF). */
bool poller_event_is_hup(const PollerEvent* ev);

#ifdef __cplusplus
}
#endif

#endif /* SOLIDC_POLLER_H */
