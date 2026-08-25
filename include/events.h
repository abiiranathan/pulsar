/**
 * @file events.h
 * @brief Event-loop primitives, backed by solidc's cross-platform poller.
 *
 * This is now a thin compatibility layer over <poller.h> from libsolidc,
 * which provides epoll (Linux), kqueue (macOS/BSD), and WSAPoll (Windows)
 * behind a single API. The pulsar-facing names are preserved so the rest
 * of the codebase reads naturally, but the underlying implementation is
 * solidc's — no per-platform event files are needed anymore.
 *
 * Type mapping:
 *   event_queue_t  -> Poller*  (was: int epoll/kqueue fd)
 *   event_t        -> PollerEvent
 */

#ifndef PULSAR_EVENTS_H
#define PULSAR_EVENTS_H

#include <solidc/poller.h>

/* ----------------------------------------------------------------
 * Opaque types (solidc poller handles).
 * ---------------------------------------------------------------- */
typedef Poller event_queue_t;
typedef PollerEvent event_t;

/* ----------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------- */

/**
 * Creates a new kernel event queue.
 * @return A valid queue on success, NULL on failure (errno set).
 */
static inline event_queue_t* event_queue_create(void) { return poller_new(); }

/**
 * Frees an event queue. Registered descriptors are NOT closed.
 */
static inline void event_queue_free(event_queue_t* q) { poller_free(q); }

/* ----------------------------------------------------------------
 * Registration
 * ---------------------------------------------------------------- */

/**
 * Registers @p fd on @p queue for edge-triggered read events.
 * @param queue Event queue.
 * @param fd    Descriptor to monitor.
 * @param data  Opaque pointer stored with the event and returned
 *              by event_get_data() when the event fires.
 * @return 0 on success, -1 on failure (errno set).
 */
static inline int event_add_read(event_queue_t* queue, int fd, void* data) {
    return poller_add(queue, fd, POLLER_READ | POLLER_EDGE, data);
}

/**
 * Registers the listening @p server_fd so only one thread is woken per
 * incoming connection where the OS supports it (Linux EPOLLEXCLUSIVE).
 * @return 0 on success, -1 on failure (errno set).
 */
static inline int event_add_server(event_queue_t* queue, int server_fd) {
    return poller_add(queue, server_fd, POLLER_READ | POLLER_EDGE | POLLER_EXCLUSIVE, NULL);
}

/**
 * Removes all registrations for @p fd from @p queue.
 * Safe to call before or after close(fd), or for fds never added.
 * @return 0 on success, -1 on failure (errno set).
 */
static inline int event_delete(event_queue_t* queue, int fd) { return poller_del(queue, fd); }

/* ----------------------------------------------------------------
 * Mode switching
 * ---------------------------------------------------------------- */

/**
 * Switches @p fd to edge-triggered write monitoring.
 * Typically called after a send() returns EAGAIN.
 * @return 0 on success, -1 on failure (errno set).
 */
static inline int event_mod_write(event_queue_t* queue, int fd, void* data) {
    return poller_mod(queue, fd, POLLER_WRITE | POLLER_EDGE, data);
}

/**
 * Switches @p fd back to edge-triggered read monitoring.
 * Call once a pending write has fully drained.
 * @return 0 on success, -1 on failure (errno set).
 */
static inline int event_mod_read(event_queue_t* queue, int fd, void* data) {
    return poller_mod(queue, fd, POLLER_READ | POLLER_EDGE, data);
}

/* ----------------------------------------------------------------
 * Waiting
 * ---------------------------------------------------------------- */

/**
 * Waits for events on @p queue.
 * @param events      Caller-allocated array of at least @p max_events
 *                    elements; populated on return.
 * @param max_events  Capacity of @p events.
 * @param timeout_ms  Milliseconds to wait; -1 blocks indefinitely.
 * @return Number of events written to @p events (>= 0), or -1 on
 *         error (errno set).
 */
static inline int event_wait(event_queue_t* queue, event_t* events, int max_events, int timeout_ms) {
    return poller_wait(queue, events, max_events, timeout_ms);
}

/* ----------------------------------------------------------------
 * Event inspection
 * ---------------------------------------------------------------- */

/** Returns the opaque data pointer registered with this event. */
static inline void* event_get_data(const event_t* event) { return poller_event_data(event); }

/**
 * Returns the file descriptor associated with this event.
 * solidc's poller guarantees this works on every backend.
 */
static inline int event_get_fd(const event_t* event) { return poller_event_fd(event); }

/** Returns true if the event indicates data available for reading. */
static inline bool event_is_read(const event_t* event) { return poller_event_is_read(event); }

/** Returns true if the event indicates the socket is ready for writing. */
static inline bool event_is_write(const event_t* event) { return poller_event_is_write(event); }

/** Returns true if the event indicates an error or peer disconnection. */
static inline bool event_is_error(const event_t* event) { return poller_event_is_error(event); }

#endif /* PULSAR_EVENTS_H */
