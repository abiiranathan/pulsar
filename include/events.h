#ifndef EVENTS_H
#define EVENTS_H

#include "common.h"

// Platform abstraction macros
#if defined(__linux__)
#define USE_EPOLL  1
#define USE_KQUEUE 0
#elif defined(__APPLE__) || defined(__FreeBSD__)
#define USE_EPOLL  0
#define USE_KQUEUE 1
#else
#error "Unsupported platform"
#endif

// Event system abstraction
#if USE_EPOLL
typedef struct epoll_event event_t;
#define EVENT_READ           EPOLLIN
#define EVENT_WRITE          EPOLLOUT
#define EVENT_ERROR          (EPOLLERR | EPOLLHUP | EPOLLRDHUP)
#define EVENT_EDGE_TRIGGERED EPOLLET
#elif USE_KQUEUE
typedef struct kevent event_t;
#define EVENT_READ           EVFILT_READ
#define EVENT_WRITE          EVFILT_WRITE
#define EVENT_ERROR          0  // kqueue handles errors differently
#define EVENT_EDGE_TRIGGERED EV_CLEAR
#endif

/* ================================================================
 * Event System Abstraction Functions
 * ================================================================ */

// Create event queue (epoll_fd or kqueue)
INLINE int event_queue_create() {
#if USE_EPOLL
    return epoll_create1(0);
#elif USE_KQUEUE
    return kqueue();
#endif
}

// Add file descriptor to event queue for reading
INLINE int event_add_read(int queue_fd, int fd, void* data) {
#if USE_EPOLL
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    if (data != NULL) {
        event.data.ptr = data;
    } else {
        event.data.fd = fd;  // Store fd when no user data
    }
    return epoll_ctl(queue_fd, EPOLL_CTL_ADD, fd, &event);
#elif USE_KQUEUE
    struct kevent event;
    EV_SET(&event, fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, data);
    return kevent(queue_fd, &event, 1, NULL, 0, NULL);
#endif
}

// Modify file descriptor to write mode
INLINE int event_mod_write(int queue_fd, int fd, void* data) {
#if USE_EPOLL
    struct epoll_event event;
    event.events   = EPOLLOUT | EPOLLET;
    event.data.ptr = data;
    return epoll_ctl(queue_fd, EPOLL_CTL_MOD, fd, &event);
#elif USE_KQUEUE
    struct kevent events[2];
    // Disable read events and enable write events
    EV_SET(&events[0], fd, EVFILT_READ, EV_DISABLE, 0, 0, data);
    EV_SET(&events[1], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, data);
    return kevent(queue_fd, events, 2, NULL, 0, NULL);
#endif
}

// Modify file descriptor back to read mode
INLINE int event_mod_read(int queue_fd, int fd, void* data) {
#if USE_EPOLL
    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
    event.data.ptr = data;
    return epoll_ctl(queue_fd, EPOLL_CTL_MOD, fd, &event);
#elif USE_KQUEUE
    struct kevent events[2];
    // Disable write events and enable read events
    EV_SET(&events[0], fd, EVFILT_WRITE, EV_DISABLE, 0, 0, data);
    EV_SET(&events[1], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, data);
    return kevent(queue_fd, events, 2, NULL, 0, NULL);
#endif
}

// Remove file descriptor from event queue
INLINE int event_delete(int queue_fd, int fd) {
#if USE_EPOLL
    return epoll_ctl(queue_fd, EPOLL_CTL_DEL, fd, NULL);
#elif USE_KQUEUE
    struct kevent events[2];
    EV_SET(&events[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    EV_SET(&events[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    // Note: kqueue automatically removes events when fd is closed,
    // but we'll try to remove them explicitly anyway
    kevent(queue_fd, events, 2, NULL, 0, NULL);
    return 0;  // kqueue delete doesn't fail the same way epoll does
#endif
}

// Add server socket with EPOLLEXCLUSIVE-like behavior
INLINE int event_add_server(int queue_fd, int server_fd) {
#if USE_EPOLL
    struct epoll_event event;
    event.events  = EPOLLIN | EPOLLEXCLUSIVE;
    event.data.fd = server_fd;
    return epoll_ctl(queue_fd, EPOLL_CTL_ADD, server_fd, &event);
#elif USE_KQUEUE
    struct kevent event;
    EV_SET(&event, server_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
    return kevent(queue_fd, &event, 1, NULL, 0, NULL);
#endif
}

// Wait for events
INLINE int event_wait(int queue_fd, event_t* events, int max_events, int timeout_ms) {
#if USE_EPOLL
    return epoll_wait(queue_fd, events, max_events, timeout_ms);
#elif USE_KQUEUE
    struct timespec timeout;
    struct timespec* timeout_ptr = NULL;

    if (timeout_ms >= 0) {
        timeout.tv_sec  = timeout_ms / 1000;
        timeout.tv_nsec = (timeout_ms % 1000) * 1000000;
        timeout_ptr     = &timeout;
    }
    return kevent(queue_fd, NULL, 0, events, max_events, timeout_ptr);
#endif
}

// Get event data pointer
INLINE void* event_get_data(const event_t* event) {
#if USE_EPOLL
    return event->data.ptr;
#elif USE_KQUEUE
    return event->udata;
#endif
}

// Get event file descriptor
INLINE int event_get_fd(const event_t* event) {
#if USE_EPOLL
    return event->data.fd;
#elif USE_KQUEUE
    return (int)event->ident;
#endif
}

// Check if event is for reading
INLINE bool event_is_read(const event_t* event) {
#if USE_EPOLL
    return (event->events & EPOLLIN) != 0;
#elif USE_KQUEUE
    return event->filter == EVFILT_READ;
#endif
}

// Check if event is for writing
INLINE bool event_is_write(const event_t* event) {
#if USE_EPOLL
    return (event->events & EPOLLOUT) != 0;
#elif USE_KQUEUE
    return event->filter == EVFILT_WRITE;
#endif
}

// Check if event indicates error/hangup
INLINE bool event_is_error(const event_t* event) {
#if USE_EPOLL
    return (event->events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) != 0;
#elif USE_KQUEUE
    return (event->flags & EV_EOF) != 0 || (event->flags & EV_ERROR) != 0;
#endif
}

#endif /* EVENTS_H */
