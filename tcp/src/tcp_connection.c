#include "tcp_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>

#include "tcp/tcp_socket.h"
#include "tcp/tcp_syscall.h"

/* ----------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------- */

tcp_conn_t* tcp_conn_alloc(tcp_client_t* cli, int fd, void* userdata, const tcp_conn_cbs_t* cbs) {
    tcp_conn_t* c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    c->fd = fd;
    c->state = TCP_CONN_CONNECTING;
    c->read_chunk = cli->cfg.read_chunk;
    c->userdata = userdata;
    c->owner = cli;
    tcp_buffer_init(&c->out);
    if (cbs) c->cbs = *cbs;

    /* Intrusive append at head: O(1), and connections are independent so
     * order does not matter. */
    c->next = cli->head;
    c->prev = NULL;
    if (cli->head) cli->head->prev = c;
    cli->head = c;
    cli->count++;
    if (c->state == TCP_CONN_CONNECTING) cli->connecting++;
    return c;
}

void tcp_conn_free(tcp_conn_t* c) {
    if (!c) return;
    tcp_buffer_free(&c->out);
    free(c);
}

void tcp_conn_unlink(tcp_conn_t* c) {
    tcp_client_t* cli = c->owner;
    if (c->prev)
        c->prev->next = c->next;
    else if (cli->head == c)
        cli->head = c->next;

    if (c->next) c->next->prev = c->prev;

    if (c->state == TCP_CONN_CONNECTING && cli->connecting > 0) cli->connecting--;
    if (c->notify_connected) {
        if (cli->pending_notify > 0) cli->pending_notify--;
        c->notify_connected = false;
    }
    if (cli->count > 0) cli->count--;

    c->next = NULL;
    c->prev = NULL;
}

void tcp_conn_finalize(tcp_conn_t* c, int err) {
    if (!c || c->state == TCP_CONN_CLOSED) return;

    tcp_client_t* cli = c->owner;
    c->state = TCP_CONN_CLOSED;
    tcp_conn_unlink(c);

    if (c->fd >= 0) {
        event_delete(&cli->queue, c->fd);
        sys_close_direct(c->fd);
        c->fd = -1;
    }

    if (c->cbs.on_closed) {
        c->in_callback = true;
        c->cbs.on_closed(c, err);
        c->in_callback = false;
    }

    tcp_conn_free(c);
}

/* ----------------------------------------------------------------
 * Accessors
 * ---------------------------------------------------------------- */

int tcp_conn_fd(const tcp_conn_t* c) { return c ? c->fd : -1; }
void* tcp_conn_userdata(const tcp_conn_t* c) { return c ? c->userdata : NULL; }
tcp_conn_state_t tcp_conn_state(const tcp_conn_t* c) {
    return c ? c->state : TCP_CONN_CLOSED;
}
int tcp_conn_is_closing(const tcp_conn_t* c) { return c ? c->closing : 1; }
size_t tcp_conn_pending(const tcp_conn_t* c) { return c ? tcp_buffer_size(&c->out) : 0; }

size_t tcp_conn_set_read_chunk(tcp_conn_t* c, size_t bytes) {
    if (!c) return 0;
    size_t max = c->owner->cfg.read_chunk;
    if (bytes < 256) bytes = 256;
    if (bytes > max) bytes = max;
    c->read_chunk = bytes;
    return c->read_chunk;
}

/* ----------------------------------------------------------------
 * Writing
 * ---------------------------------------------------------------- */

int tcp_conn_flush(tcp_conn_t* c) {
    if (tcp_buffer_empty(&c->out)) {
        tcp_client_arm_read(c);
        return 0;
    }

    while (!tcp_buffer_empty(&c->out)) {
        uint8_t* p = tcp_buffer_data(&c->out);
        size_t n = tcp_buffer_size(&c->out);
        ssize_t w = sys_write_direct(c->fd, p, n);

        if (w > 0) {
            tcp_buffer_consume(&c->out, (size_t)w);
            continue;
        }
        if (w == 0) break;
        if (w == -EINTR) continue;
        if (w == -EAGAIN || w == -EWOULDBLOCK) {
            tcp_client_arm_write(c);
            return 1;
        }

        errno = (int)(-w);
        return -1;
    }

    tcp_client_arm_read(c);
    if (c->cbs.on_writable) {
        c->in_callback = true;
        c->cbs.on_writable(c);
        c->in_callback = false;
    }
    return 0;
}

static int write_max_exceeded(const tcp_conn_t* c, size_t extra) {
    size_t max = c->owner->cfg.write_max;
    if (max == 0) return 0;
    return tcp_buffer_size(&c->out) + extra > max;
}

ssize_t tcp_conn_write(tcp_conn_t* c, const void* data, size_t len) {
    if (!c || c->state == TCP_CONN_CLOSED || c->closing || c->fd < 0) {
        errno = EPIPE;
        return -1;
    }
    if (len == 0) return 0;

    /* While connecting, queue everything: the kernel socket is not usable. */
    if (c->state == TCP_CONN_CONNECTING) {
        if (write_max_exceeded(c, len)) {
            errno = ENOBUFS;
            return -1;
        }
        if (tcp_buffer_append(&c->out, data, len) < 0) return -1;
        return (ssize_t)len;
    }

    /* Fast path: nothing queued -> write straight to the socket. */
    if (tcp_buffer_empty(&c->out)) {
        ssize_t w = sys_write_direct(c->fd, data, len);
        if (w == (ssize_t)len) return (ssize_t)len;

        if (w >= 0) {
            size_t rem = len - (size_t)w;
            if (write_max_exceeded(c, rem)) {
                errno = ENOBUFS;
                return -1;
            }
            if (tcp_buffer_append(&c->out, (const uint8_t*)data + w, rem) < 0) return -1;
            tcp_client_arm_write(c);
            return (ssize_t)len;
        }

        if (w == -EINTR) return tcp_conn_write(c, data, len);

        if (w == -EAGAIN || w == -EWOULDBLOCK) {
            if (write_max_exceeded(c, len)) {
                errno = ENOBUFS;
                return -1;
            }
            if (tcp_buffer_append(&c->out, data, len) < 0) return -1;
            tcp_client_arm_write(c);
            return (ssize_t)len;
        }

        errno = (int)(-w);
        return -1;
    }

    /* Queue non-empty: append behind it. */
    if (write_max_exceeded(c, len)) {
        errno = ENOBUFS;
        return -1;
    }
    if (tcp_buffer_append(&c->out, data, len) < 0) return -1;
    return (ssize_t)len;
}

ssize_t tcp_conn_writev(tcp_conn_t* c, const struct iovec* iov, int iovcnt) {
    if (!c || !iov || iovcnt <= 0) {
        errno = EINVAL;
        return -1;
    }

    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) total += iov[i].iov_len;

    if (c->state == TCP_CONN_ESTABLISHED && tcp_buffer_empty(&c->out)) {
        ssize_t w = sys_writev_direct(c->fd, iov, iovcnt);
        if (w == (ssize_t)total) return (ssize_t)total;
        if (w > 0) {
            /* Re-queue the unsent tail [w, total) by linearizing it. */
            if (write_max_exceeded(c, total - (size_t)w)) {
                errno = ENOBUFS;
                return -1;
            }
            size_t skip = (size_t)w;
            int i = 0;
            while (i < iovcnt && skip >= iov[i].iov_len) {
                skip -= iov[i].iov_len;
                i++;
            }
            if (i < iovcnt) {
                if (skip > 0) {
                    struct iovec tail = {.iov_base = (uint8_t*)iov[i].iov_base + skip,
                                         .iov_len = iov[i].iov_len - skip};
                    if (tcp_buffer_appendv(&c->out, &tail, 1) < 0) return -1;
                    i++;
                }
                if (i < iovcnt && tcp_buffer_appendv(&c->out, &iov[i], iovcnt - i) < 0) {
                    return -1;
                }
            }
            tcp_client_arm_write(c);
            return (ssize_t)total;
        }
        if (w == -EINTR) return tcp_conn_writev(c, iov, iovcnt);
        if (w < 0 && w != -EAGAIN && w != -EWOULDBLOCK) {
            errno = (int)(-w);
            return -1;
        }
    }

    if (write_max_exceeded(c, total)) {
        errno = ENOBUFS;
        return -1;
    }
    if (tcp_buffer_appendv(&c->out, iov, iovcnt) < 0) return -1;
    if (c->state == TCP_CONN_ESTABLISHED) tcp_client_arm_write(c);
    return (ssize_t)total;
}

void tcp_conn_close(tcp_conn_t* c) {
    if (!c || c->state == TCP_CONN_CLOSED) return;
    if (c->closing) return;

    c->closing = true;

    if (c->fd < 0 || c->state != TCP_CONN_ESTABLISHED) return;

    if (tcp_buffer_empty(&c->out)) {
        /* Nothing queued: signal EOF and let the loop tear down. */
        shutdown(c->fd, SHUT_WR);
    } else {
        /* Finish sending queued bytes before the loop closes the fd. */
        c->close_after_flush = true;
        tcp_client_arm_write(c);
    }
}

/* ----------------------------------------------------------------
 * Event handlers (called by the loop)
 * ---------------------------------------------------------------- */

void tcp_conn_on_connect(tcp_conn_t* c) {
    int st = tcp_connect_check(c->fd);
    if (st < 0) {
        c->close_err = errno;
        c->closing = true;
        return;
    }
    if (st == 1) return; /* still in flight */

    c->state = TCP_CONN_ESTABLISHED;
    if (c->owner->connecting > 0) c->owner->connecting--;

    /* Read interest is always on once established. */
    if (tcp_buffer_empty(&c->out))
        tcp_client_arm_read(c);
    else
        tcp_client_arm_write(c); /* keeps read armed too */

    if (c->cbs.on_connected) {
        c->in_callback = true;
        c->cbs.on_connected(c);
        c->in_callback = false;
    }
    if (c->closing) return;

    if (!tcp_buffer_empty(&c->out)) {
        if (tcp_conn_flush(c) < 0) {
            c->close_err = errno;
            c->closing = true;
        }
    }
}

void tcp_conn_on_read(tcp_conn_t* c) {
    tcp_client_t* cli = c->owner;
    size_t chunk = c->read_chunk ? c->read_chunk : cli->cfg.read_chunk;

    for (;;) {
        ssize_t n = sys_read_direct(c->fd, cli->rbuf, chunk);
        if (n > 0) {
            if (c->cbs.on_data) {
                c->in_callback = true;
                c->cbs.on_data(c, cli->rbuf, (size_t)n);
                c->in_callback = false;
            }
            if (c->closing) return;
            continue;
        }
        if (n == 0) {
            c->close_err = 0; /* orderly EOF */
            c->closing = true;
            return;
        }
        if (n == -EINTR) continue;
        if (n == -EAGAIN || n == -EWOULDBLOCK) return;

        c->close_err = (int)(-n);
        c->closing = true;
        return;
    }
}

void tcp_conn_on_write(tcp_conn_t* c) {
    if (tcp_conn_flush(c) < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        c->close_err = errno;
        c->closing = true;
    }
}
