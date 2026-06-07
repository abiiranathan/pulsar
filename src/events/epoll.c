#include "../include/events.h"

#if defined(__linux__)

int event_queue_create(void) {
    return epoll_create1(0);
}

int event_add_read(int queue_fd, int fd, void* data) {
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
        .data.ptr = data,
    };
    return epoll_ctl(queue_fd, EPOLL_CTL_ADD, fd, &ev);
}

int event_add_server(int queue_fd, int server_fd) {
    /* EPOLLEXCLUSIVE ensures only one thread is woken per accept()
     * opportunity, avoiding the thundering-herd problem on Linux 4.5+. */
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLEXCLUSIVE,
        .data.fd = server_fd,
    };
    return epoll_ctl(queue_fd, EPOLL_CTL_ADD, server_fd, &ev);
}

int event_delete(int queue_fd, int fd) {
    /* Passing NULL is valid on Linux kernel >= 2.6.9. */
    return epoll_ctl(queue_fd, EPOLL_CTL_DEL, fd, NULL);
}

int event_mod_write(int queue_fd, int fd, void* data) {
    struct epoll_event ev = {
        .events = EPOLLOUT | EPOLLET,
        .data.ptr = data,
    };
    return epoll_ctl(queue_fd, EPOLL_CTL_MOD, fd, &ev);
}

int event_mod_read(int queue_fd, int fd, void* data) {
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
        .data.ptr = data,
    };
    return epoll_ctl(queue_fd, EPOLL_CTL_MOD, fd, &ev);
}

int event_wait(int queue_fd, event_t* events, int max_events, int timeout_ms) {
    return epoll_wait(queue_fd, events, max_events, timeout_ms);
}

void* event_get_data(const event_t* event) {
    return event->data.ptr;
}

int event_get_fd(const event_t* event) {
    return event->data.fd;
}

bool event_is_read(const event_t* event) {
    return (event->events & EPOLLIN) != 0;
}

bool event_is_write(const event_t* event) {
    return (event->events & EPOLLOUT) != 0;
}

bool event_is_error(const event_t* event) {
    return (event->events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) != 0;
}

#else
#error "Unsupported platform: this events implementation is only supported on Linux."
#endif
