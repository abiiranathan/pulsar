#ifndef EVENTS_H
#define EVENTS_H

#include "common.h"

/* ----------------------------------------------------------------
 * Opaque event type.
 *
 * Consumers work exclusively through the accessors below and must
 * never inspect the underlying struct directly.  The concrete type
 * is defined in the platform implementation file that is compiled.
 * ---------------------------------------------------------------- */
#if defined(__linux__)
typedef struct epoll_event event_t;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(__DragonFly__)
typedef struct kevent event_t;
#else
#error "Unsupported platform. Pulsar currently supports Linux, macOS, and BSD."
#endif

/* ----------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------- */

/**
 * Creates a new kernel event queue.
 * @return A valid file descriptor on success, -1 on failure (errno set).
 */
int event_queue_create(void);

/* ----------------------------------------------------------------
 * Registration
 * ---------------------------------------------------------------- */

/**
 * Registers @p fd on @p queue_fd for edge-triggered read events.
 * @param queue_fd  Event queue returned by event_queue_create().
 * @param fd        File descriptor to monitor.
 * @param data      Opaque pointer stored with the event and returned
 *                  by event_get_data() when the event fires.
 * @return 0 on success, -1 on failure (errno set).
 */
int event_add_read(int queue_fd, int fd, void* data);

/**
 * Registers the listening @p server_fd so that only one thread is
 * woken per incoming connection (thundering-herd prevention).
 * @return 0 on success, -1 on failure (errno set).
 */
int event_add_server(int queue_fd, int server_fd);

/**
 * Removes all registrations for @p fd from @p queue_fd.
 * Safe to call before or after close(fd).
 * @return 0 on success, -1 on failure (errno set).
 */
int event_delete(int queue_fd, int fd);

/* ----------------------------------------------------------------
 * Mode switching
 * ---------------------------------------------------------------- */

/**
 * Switches @p fd to edge-triggered write monitoring.
 * Typically called after a send() returns EAGAIN.
 * @return 0 on success, -1 on failure (errno set).
 */
int event_mod_write(int queue_fd, int fd, void* data);

/**
 * Switches @p fd back to edge-triggered read monitoring.
 * Call once a pending write has fully drained.
 * @return 0 on success, -1 on failure (errno set).
 */
int event_mod_read(int queue_fd, int fd, void* data);

/* ----------------------------------------------------------------
 * Waiting
 * ---------------------------------------------------------------- */

/**
 * Waits for events on @p queue_fd.
 * @param events      Caller-allocated array of at least @p max_events
 *                    elements; populated on return.
 * @param max_events  Capacity of @p events.
 * @param timeout_ms  Milliseconds to wait; -1 blocks indefinitely.
 * @return Number of events written to @p events (>= 0), or -1 on
 *         error (errno set).
 */
int event_wait(int queue_fd, event_t* events, int max_events, int timeout_ms);

/* ----------------------------------------------------------------
 * Event inspection
 * ---------------------------------------------------------------- */

/**
 * Returns the opaque data pointer registered with this event.
 * Returns NULL if no pointer was registered (e.g. server accept events).
 */
void* event_get_data(const event_t* event);

/** Returns the file descriptor associated with this event. */
int event_get_fd(const event_t* event);

/** Returns true if the event indicates data available for reading. */
bool event_is_read(const event_t* event);

/** Returns true if the event indicates the socket is ready for writing. */
bool event_is_write(const event_t* event);

/** Returns true if the event indicates an error or peer disconnection. */
bool event_is_error(const event_t* event);

#endif /* EVENTS_H */
