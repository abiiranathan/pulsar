#include <sys/time.h> /* struct timespec */
#include "../include/events.h"

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(__DragonFly__)

int event_queue_create(void) {
    return kqueue();
}

int event_add_read(int queue_fd, int fd, void* data) {
    struct kevent ev;
    EV_SET(&ev, (uintptr_t)fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, data);
    return kevent(queue_fd, &ev, 1, NULL, 0, NULL);
}

int event_add_server(int queue_fd, int server_fd) {
    /* kqueue has no EPOLLEXCLUSIVE equivalent; the accept(2) call itself
     * is serialised per-process, so edge-triggered read is sufficient. */
    struct kevent ev;
    EV_SET(&ev, (uintptr_t)server_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
    return kevent(queue_fd, &ev, 1, NULL, 0, NULL);
}

int event_delete(int queue_fd, int fd) {
    /* Attempt to remove both filters; ignore ENOENT — a filter that was
     * never registered is not an error from the caller's perspective.
     * kqueue also removes all filters automatically on close(fd). */
    struct kevent evs[2];
    EV_SET(&evs[0], (uintptr_t)fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    EV_SET(&evs[1], (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    kevent(queue_fd, evs, 2, NULL, 0, NULL);
    return 0;
}

int event_mod_write(int queue_fd, int fd, void* data) {
    struct kevent evs[2];
    EV_SET(&evs[0], (uintptr_t)fd, EVFILT_READ, EV_DISABLE, 0, 0, data);
    EV_SET(&evs[1], (uintptr_t)fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, data);
    return kevent(queue_fd, evs, 2, NULL, 0, NULL);
}

int event_mod_read(int queue_fd, int fd, void* data) {
    struct kevent evs[2];
    EV_SET(&evs[0], (uintptr_t)fd, EVFILT_WRITE, EV_DISABLE, 0, 0, data);
    EV_SET(&evs[1], (uintptr_t)fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, data);
    return kevent(queue_fd, evs, 2, NULL, 0, NULL);
}

int event_wait(int queue_fd, event_t* events, int max_events, int timeout_ms) {
    struct timespec ts;
    struct timespec* ts_ptr = NULL;

    if (timeout_ms >= 0) {
        ts.tv_sec  = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        ts_ptr     = &ts;
    }
    return kevent(queue_fd, NULL, 0, &events[0], max_events, ts_ptr);
}

void* event_get_data(const event_t* event) {
    return event->udata;
}

int event_get_fd(const event_t* event) {
    return (int)event->ident;
}

bool event_is_read(const event_t* event) {
    return event->filter == EVFILT_READ;
}

bool event_is_write(const event_t* event) {
    return event->filter == EVFILT_WRITE;
}

bool event_is_error(const event_t* event) {
    return (event->flags & (EV_EOF | EV_ERROR)) != 0;
}
#else
#error "Unsupported platform: kqueue is only supported on BSD-like systems."
#endif