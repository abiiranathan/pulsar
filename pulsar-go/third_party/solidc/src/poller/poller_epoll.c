/**
 * @file poller_epoll.c
 * @brief Linux epoll backend for poller.h.
 *
 * The kernel stores only the raw fd (ev.data.fd); the user pointer lives in
 * the registration table and is resolved at wait time. This keeps internal
 * table memory invisible to epoll, so growing or rehashing the table can
 * never invalidate pointers the kernel holds.
 */

#include "poller_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

struct Poller {
    PollerBase base;
    int epfd;
    struct epoll_event* evs; /**< Growable scratch buffer for poller_wait(). */
    int evs_cap;             /* Capacity of evs (events, not bytes). */
};

Poller* poller_new(void) {
    Poller* p = (Poller*)calloc(1, sizeof(Poller));
    if (!p) return NULL;

    if (!poller_regs_init(&p->base)) {
        free(p);
        return NULL;
    }

    p->epfd = epoll_create1(0);
    if (p->epfd < 0) {
        poller_regs_free(&p->base);
        free(p);
        return NULL;
    }
    return p;
}

void poller_free(Poller* p) {
    if (!p) return;
    close(p->epfd);
    free(p->evs);
    poller_regs_free(&p->base);
    free(p);
}

/** Maps solidc interest flags to an epoll event mask. */
static uint32_t poller_to_epoll_events(int events) {
    uint32_t out = 0;
    if (events & POLLER_READ) out |= EPOLLIN;
    if (events & POLLER_WRITE) out |= EPOLLOUT;
    if (events & POLLER_EDGE) out |= EPOLLET;
    /* Always track peer shutdown so servers can reap half-open sockets. */
    out |= EPOLLRDHUP;
    return out;
}

int poller_add(Poller* p, int fd, int events, void* data) {
    if (!p || fd < 0) {
        errno = EINVAL;
        return -1;
    }

    /* Insert first: if the table grows and OOMs, we fail before touching
     * the kernel set. */
    PollerReg* reg = poller_regs_put(&p->base, fd, data);
    if (!reg) {
        errno = ENOMEM;
        return -1;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = poller_to_epoll_events(events);
    ev.data.fd = fd;

    int op = epoll_ctl(p->epfd, EPOLL_CTL_MOD, fd, &ev) == 0
                 ? 0
                 : (errno == ENOENT ? epoll_ctl(p->epfd, EPOLL_CTL_ADD, fd, &ev) : -1);
    if (op != 0) {
        poller_regs_remove(&p->base, fd);
    }
    return op;
}

int poller_mod(Poller* p, int fd, int events, void* data) {
    if (!p || fd < 0) {
        errno = EINVAL;
        return -1;
    }

    PollerReg* reg = poller_regs_get(&p->base, fd);
    if (!reg) {
        errno = ENOENT;
        return -1;
    }
    reg->data = data;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = poller_to_epoll_events(events);
    ev.data.fd = fd;
    return epoll_ctl(p->epfd, EPOLL_CTL_MOD, fd, &ev);
}

int poller_del(Poller* p, int fd) {
    if (!p || fd < 0) {
        errno = EINVAL;
        return -1;
    }
    poller_regs_remove(&p->base, fd);
    /* NULL event is valid for EPOLL_CTL_DEL since kernel 2.6.9. */
    int r = epoll_ctl(p->epfd, EPOLL_CTL_DEL, fd, NULL);
    if (r != 0 && errno == ENOENT) return 0; /* never added / already gone */
    return r;
}

int poller_wait(Poller* p, PollerEvent* events, int max, int timeout_ms) {
    if (!p || !events || max <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Grow the scratch buffer to the caller's batch size (never shrinks,
     * so steady-state waits allocate nothing). */
    if (max > p->evs_cap) {
        int cap = p->evs_cap ? p->evs_cap : 128;
        while (cap < max) cap *= 2;
        struct epoll_event* nevs = (struct epoll_event*)realloc(p->evs, (size_t)cap * sizeof(*nevs));
        if (!nevs) {
            errno = ENOMEM;
            return -1;
        }
        p->evs = nevs;
        p->evs_cap = cap;
    }

    int n = epoll_wait(p->epfd, p->evs, max, timeout_ms);
    if (n <= 0) return n;

    for (int i = 0; i < n; i++) {
        int fd = p->evs[i].data.fd;
        PollerReg* reg = poller_regs_get(&p->base, fd);
        events[i].fd = fd;
        events[i].data = reg ? reg->data : NULL;
        events[i].readable = (p->evs[i].events & EPOLLIN) != 0;
        events[i].writable = (p->evs[i].events & EPOLLOUT) != 0;
        events[i].error = (p->evs[i].events & EPOLLERR) != 0;
        events[i].hup = (p->evs[i].events & (EPOLLRDHUP | EPOLLHUP)) != 0;
    }
    return n;
}

int poller_event_fd(const PollerEvent* ev) { return ev ? ev->fd : -1; }

void* poller_event_data(const PollerEvent* ev) { return ev ? ev->data : NULL; }

bool poller_event_is_read(const PollerEvent* ev) { return ev && ev->readable; }

bool poller_event_is_write(const PollerEvent* ev) { return ev && ev->writable; }

bool poller_event_is_error(const PollerEvent* ev) { return ev && ev->error; }

bool poller_event_is_hup(const PollerEvent* ev) { return ev && ev->hup; }
