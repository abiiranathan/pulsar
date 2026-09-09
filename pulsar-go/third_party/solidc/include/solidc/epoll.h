#ifndef SOLIDC_EPOLL_H
#define SOLIDC_EPOLL_H

/**
 * @file solidc_epoll.h
 * @brief Cross-platform Epoll abstraction.
 *
 * On Linux: Includes <sys/epoll.h> directly.
 * On BSD/macOS: Polyfills struct epoll_event, flags, and functions using kqueue.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* =========================================================================
 * LINUX IMPLEMENTATION (Native)
 * ========================================================================= */
#if defined(__linux__)

    #include <sys/epoll.h>

/* =========================================================================
 * BSD / MACOS IMPLEMENTATION (Kqueue Wrapper)
 * ========================================================================= */
#elif defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__)

    #include <string.h>
    #include <sys/event.h>
    #include <sys/time.h>
    #include <sys/types.h>
    #include <unistd.h>

/* -------------------------------------------------------------------------
 * Data Types and Structs (Matching Linux ABI)
 * ------------------------------------------------------------------------- */

typedef union epoll_data {
    void* ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t events;   /* Epoll events */
    epoll_data_t data; /* User data variable */
} __attribute__((packed));

    /* -------------------------------------------------------------------------
     * Flags (Mimicking Linux constants)
     * ------------------------------------------------------------------------- */

    #define EPOLLIN        0x001
    #define EPOLLPRI       0x002
    #define EPOLLOUT       0x004
    #define EPOLLERR       0x008
    #define EPOLLHUP       0x010
    #define EPOLLRDHUP     0x2000
    #define EPOLLEXCLUSIVE 0x10000000 /* Use proper flag for kqueue */
    #define EPOLLET        (1U << 31) /* Using high bit for Edge Triggered */
    #define EPOLLONESHOT   (1U << 30)

    /* Op codes for epoll_ctl */
    #define EPOLL_CTL_ADD  1
    #define EPOLL_CTL_DEL  2
    #define EPOLL_CTL_MOD  3

/* -------------------------------------------------------------------------
 * Polyfill Functions
 * ------------------------------------------------------------------------- */

/**
 * @brief Mimics epoll_create1.
 * Ignores flags as kqueue doesn't have direct equivalents for CLOEXEC in create.
 */
static inline int epoll_create1(int flags) {
    (void)flags;
    return kqueue();
}

/**
 * @brief Mimics epoll_create (legacy support).
 */
static inline int epoll_create(int size) {
    (void)size;
    return kqueue();
}

/**
 * @brief Mimics epoll_ctl.
 * Translates epoll commands to kevent updates.
 */
static inline int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event) {
    struct kevent kev[2];
    int nchanges = 0;
    int flags_read = 0;
    int flags_write = 0;

    /* Default kqueue flags */
    uint16_t k_flags = 0;

    if (op == EPOLL_CTL_ADD) {
        k_flags = EV_ADD | EV_ENABLE;
    } else if (op == EPOLL_CTL_MOD) {
        k_flags = EV_ADD | EV_ENABLE;
        /* In kqueue, re-adding with EV_ADD overwrites/modifies the existing filter */
    } else if (op == EPOLL_CTL_DEL) {
        k_flags = EV_DELETE;
    } else {
        errno = EINVAL;
        return -1;
    }

    /* Handle Edge Triggering */
    if (event && (event->events & EPOLLET)) {
        k_flags |= EV_CLEAR;
    }
    /* Handle One Shot */
    if (event && (event->events & EPOLLONESHOT)) {
        k_flags |= EV_ONESHOT;
    }

    /* Prepare READ filter */
    if (op == EPOLL_CTL_DEL || (event && (event->events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP)))) {
        /* Note: kqueue doesn't distinguish PRI/RDHUP exactly like epoll,
           mapped to standard READ */
        EV_SET(&kev[nchanges++], fd, EVFILT_READ, k_flags, 0, 0, event ? event->data.ptr : NULL);
    }

    /* Prepare WRITE filter */
    if (op == EPOLL_CTL_DEL || (event && (event->events & EPOLLOUT))) {
        EV_SET(&kev[nchanges++], fd, EVFILT_WRITE, k_flags, 0, 0, event ? event->data.ptr : NULL);
    }

    /*
     * Special Case for MOD:
     * If modifying, we might be removing a flag (e.g. IN|OUT -> IN).
     * kqueue EV_ADD will update settings but won't remove a filter if we simply don't set it.
     * To strictly emulate epoll_ctl MOD, we should delete the filter we aren't setting.
     * However, for performance in this shim, we assume strict Add/Delete usage or
     * that the user understands kqueue semantics.
     *
     * Robust MOD implementation:
     */
    if (op == EPOLL_CTL_MOD && event) {
        /* If we want only IN, but previously had OUT, we must delete OUT. */
        if (!(event->events & EPOLLOUT)) {
            struct kevent del_ev;
            EV_SET(&del_ev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
            kevent(epfd, &del_ev, 1, NULL, 0, NULL); /* Ignore error if it didn't exist */
        }
        if (!(event->events & (EPOLLIN | EPOLLPRI))) {
            struct kevent del_ev;
            EV_SET(&del_ev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
            kevent(epfd, &del_ev, 1, NULL, 0, NULL); /* Ignore error */
        }
    }

    if (nchanges == 0) return 0;

    return kevent(epfd, kev, nchanges, NULL, 0, NULL);
}

/**
 * @brief Mimics epoll_wait.
 * Translates kevents back to epoll_events.
 */
static inline int epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout_ms) {
    struct timespec ts;
    struct timespec* ts_ptr = NULL;

    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000;
        ts_ptr = &ts;
    }

    /*
     * We cannot cast (struct epoll_event*) to (struct kevent*) in-place
     * because the structures have different sizes (kevent is usually larger).
     * We must allocate a temporary buffer for kevents.
     */
    struct kevent* k_events = (struct kevent*)malloc(sizeof(struct kevent) * maxevents);
    if (!k_events) {
        errno = ENOMEM;
        return -1;
    }

    int nfds = kevent(epfd, NULL, 0, k_events, maxevents, ts_ptr);

    if (nfds > 0) {
        for (int i = 0; i < nfds; ++i) {
            uint32_t ev_flags = 0;

            if (k_events[i].filter == EVFILT_READ) {
                ev_flags |= EPOLLIN;
                if (k_events[i].flags & EV_EOF) {
                    ev_flags |= EPOLLRDHUP;  // Linux specific roughly maps here
                }
            } else if (k_events[i].filter == EVFILT_WRITE) {
                ev_flags |= EPOLLOUT;
            }

            if (k_events[i].flags & EV_ERROR) {
                ev_flags |= EPOLLERR;
            }
            if (k_events[i].flags & EV_EOF) {
                ev_flags |= EPOLLHUP;
            }

            events[i].events = ev_flags;
            events[i].data.ptr = k_events[i].udata;
        }
    }

    free(k_events);
    return nfds;
}

#else
    #error "Unsupported platform: This header supports Linux (native) and BSD/macOS (kqueue shim)."
#endif

#include <arpa/inet.h>   // for socket, bind, listen, accept
#include <errno.h>       // for errno
#include <fcntl.h>       // for fcntl, F_GETFL, F_SETFL
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>  // for socket, SOL_SOCKET, SO_REUSEADDR
#include <unistd.h>      // for close, read, write

/**
 * Sets a file descriptor to non-blocking mode.
 */
static inline int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * Creates and configures the listening socket to non-blocking mode.
 * Equivalent to socket() -> bind() -> listen() -> setnonblocking.
 */
static inline int create_listen_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    //  Set SO_REUSEPORT: This is critical for load balancing
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
        perror("setsockopt SO_REUSEPORT");
        close(fd);
        return -1;
    }

    // Also set SO_REUSEADDR usually to allow restart during TIME_WAIT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        close(fd);
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, SOMAXCONN) == -1) {
        perror("listen");
        close(fd);
        return -1;
    }

    if (set_nonblocking(fd) == -1) {
        perror("set_nonblocking");
        close(fd);
        return -1;
    }

    return fd;
}

#endif /* SOLIDC_EPOLL_H */
