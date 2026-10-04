#include "tcp_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#include "tcp/tcp_socket.h"
#include "tcp/tcp_syscall.h"

/* ----------------------------------------------------------------
 * Time
 * ---------------------------------------------------------------- */

uint64_t tcp_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

/* ----------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------- */

tcp_client_config_t tcp_client_config_default(void) {
    tcp_client_config_t c;
    c.read_chunk = 64u * 1024u;
    c.write_max = 4u * 1024u * 1024u;
    c.max_events = 1024;
    c.poll_timeout_ms = 1000;
    c.connect_timeout_ms = 0;
    c.exit_when_idle = 1;
    return c;
}

static void normalize_config(tcp_client_config_t* c) {
    if (c->read_chunk < 256) c->read_chunk = 256;
    if (c->read_chunk > (size_t)1 << 30) c->read_chunk = (size_t)1 << 30;
    if (c->max_events < 1) c->max_events = 1;
    if (c->max_events > 65536) c->max_events = 65536;
    if (c->poll_timeout_ms < 0) c->poll_timeout_ms = 1000;
    if (c->connect_timeout_ms < 0) c->connect_timeout_ms = 0;
}

/* ----------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------- */

tcp_client_t* tcp_client_create(const tcp_client_config_t* cfg) {
    tcp_client_t* cli = calloc(1, sizeof(*cli));
    if (!cli) return NULL;

    cli->cfg = cfg ? *cfg : tcp_client_config_default();
    normalize_config(&cli->cfg);
    cli->wake_fd = -1;

    if (event_queue_create(&cli->queue) != 0) {
        free(cli);
        return NULL;
    }

    cli->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    cli->rbuf = malloc(cli->cfg.read_chunk);
    cli->raw_events = malloc(sizeof(struct epoll_event) * (size_t)cli->cfg.max_events);
    cli->events = malloc(sizeof(event_t) * (size_t)cli->cfg.max_events);

    if (cli->wake_fd < 0 || !cli->rbuf || !cli->raw_events || !cli->events) {
        free(cli->rbuf);
        free(cli->raw_events);
        free(cli->events);
        if (cli->wake_fd >= 0) sys_close_direct(cli->wake_fd);
        event_queue_close(&cli->queue);
        free(cli);
        return NULL;
    }

    if (event_add_read(&cli->queue, cli->wake_fd, cli) < 0) {
        sys_close_direct(cli->wake_fd);
        event_queue_close(&cli->queue);
        free(cli->rbuf);
        free(cli->raw_events);
        free(cli->events);
        free(cli);
        return NULL;
    }

    atomic_init(&cli->running, 1);
    return cli;
}

void tcp_client_destroy(tcp_client_t* cli) {
    if (!cli) return;

    tcp_conn_t* c = cli->head;
    while (c) {
        tcp_conn_t* next = c->next;
        if (c->fd >= 0) {
            event_delete(&cli->queue, c->fd);
            sys_close_direct(c->fd);
            c->fd = -1;
        }
        tcp_conn_free(c);
        c = next;
    }

    if (cli->wake_fd >= 0) sys_close_direct(cli->wake_fd);
    event_queue_close(&cli->queue);
    free(cli->rbuf);
    free(cli->raw_events);
    free(cli->events);
    free(cli);
}

/* ----------------------------------------------------------------
 * Interest arming
 * ---------------------------------------------------------------- */

void tcp_client_arm_write(tcp_conn_t* c) {
    if (!c || c->state == TCP_CONN_CLOSED || c->want_write) return;
    c->want_write = true;

    /* Once established, read interest stays on so backpressure never stalls
     * the inbound direction. */
    if (c->state == TCP_CONN_ESTABLISHED)
        event_mod_readwrite(&c->owner->queue, c->fd, c);
    else
        event_mod_write(&c->owner->queue, c->fd, c);
}

void tcp_client_arm_read(tcp_conn_t* c) {
    if (!c || c->state == TCP_CONN_CLOSED || !c->want_write) return;
    c->want_write = false;
    event_mod_read(&c->owner->queue, c->fd, c);
}

/* ----------------------------------------------------------------
 * Connect / adopt
 * ---------------------------------------------------------------- */

tcp_conn_t* tcp_client_connect(tcp_client_t* cli, const char* host, int port, void* userdata,
                               const tcp_conn_cbs_t* cbs) {
    if (!cli || !host) {
        errno = EINVAL;
        return NULL;
    }

    int fd = tcp_connect_start(host, port, NULL);
    if (fd < 0) return NULL;

    tcp_conn_t* c = tcp_conn_alloc(cli, fd, userdata, cbs);
    if (!c) {
        sys_close_direct(fd);
        return NULL;
    }

    if (cli->cfg.connect_timeout_ms > 0)
        c->connect_deadline_ms = tcp_now_ms() + (uint64_t)cli->cfg.connect_timeout_ms;

    if (event_add_read(&cli->queue, fd, c) < 0) {
        tcp_conn_unlink(c);
        sys_close_direct(fd);
        tcp_conn_free(c);
        return NULL;
    }

    tcp_client_arm_write(c); /* arm EPOLLOUT for connect completion */
    return c;
}

tcp_conn_t* tcp_client_add(tcp_client_t* cli, int fd, void* userdata, const tcp_conn_cbs_t* cbs) {
    if (!cli || fd < 0) {
        errno = EINVAL;
        return NULL;
    }
    if (tcp_set_nonblock(fd) < 0) return NULL;

    tcp_conn_t* c = tcp_conn_alloc(cli, fd, userdata, cbs);
    if (!c) return NULL;

    /* tcp_conn_alloc counted it as connecting; it is already connected. */
    if (cli->connecting > 0) cli->connecting--;
    c->state = TCP_CONN_ESTABLISHED;

    if (event_add_read(&cli->queue, fd, c) < 0) {
        tcp_conn_unlink(c);
        tcp_conn_free(c);
        return NULL;
    }

    /* Fire on_connected on the next loop turn, once the caller has received
     * the handle and finished its own setup. */
    c->notify_connected = true;
    cli->pending_notify++;
    return c;
}

size_t tcp_client_connection_count(const tcp_client_t* cli) { return cli ? cli->count : 0; }

/* ----------------------------------------------------------------
 * Loop
 * ---------------------------------------------------------------- */

static void drain_wake(tcp_client_t* cli) {
    uint64_t v;
    while (sys_read_direct(cli->wake_fd, &v, sizeof(v)) > 0) {
        /* Drain all pending stop notifications. */
    }
}

static void check_connect_timeouts(tcp_client_t* cli) {
    uint64_t now = tcp_now_ms();
    tcp_conn_t* c = cli->head;
    while (c) {
        tcp_conn_t* next = c->next;
        if (c->state == TCP_CONN_CONNECTING && c->connect_deadline_ms != 0 &&
            now >= c->connect_deadline_ms) {
            tcp_conn_finalize(c, ETIMEDOUT);
        }
        c = next;
    }
}

static void dispatch_event(tcp_client_t* cli, tcp_conn_t* c, const event_t* ev) {
    (void)cli;

    if (ev->error) {
        c->close_err = ECONNRESET;
        c->closing = true;
    } else {
        if (c->state == TCP_CONN_CONNECTING && ev->writable) tcp_conn_on_connect(c);

        if (!c->closing && ev->readable && c->state == TCP_CONN_ESTABLISHED)
            tcp_conn_on_read(c);

        if (!c->closing && ev->writable && c->state == TCP_CONN_ESTABLISHED)
            tcp_conn_on_write(c);
    }

    if (c->closing) {
        /* A graceful close waits for already-queued output to drain, but a
         * fatal write error must not spin on a permanently-writable socket. */
        if (c->close_after_flush && c->close_err == 0 && !tcp_buffer_empty(&c->out)) {
            tcp_client_arm_write(c);
        } else {
            tcp_conn_finalize(c, c->close_err);
        }
    }
}

static void fire_pending_connects(tcp_client_t* cli) {
    tcp_conn_t* c = cli->head;
    while (c) {
        tcp_conn_t* next = c->next;
        if (c->notify_connected) {
            c->notify_connected = false;
            if (cli->pending_notify > 0) cli->pending_notify--;

            if (c->cbs.on_connected) {
                c->in_callback = true;
                c->cbs.on_connected(c);
                c->in_callback = false;
            }
            if (c->closing) tcp_conn_finalize(c, c->close_err);
        }
        c = next;
    }
}

int tcp_client_run(tcp_client_t* cli) {
    if (!cli) {
        errno = EINVAL;
        return -1;
    }

    int rc = 0;
    while (atomic_load_explicit(&cli->running, memory_order_relaxed)) {
        if (cli->pending_notify > 0) fire_pending_connects(cli);

        int n = event_wait(&cli->queue, cli->raw_events, cli->events, cli->cfg.max_events,
                           cli->cfg.poll_timeout_ms);
        if (n < 0) {
            if (errno == EINTR) continue;
            rc = -1;
            break;
        }

        if (cli->connecting > 0 && cli->cfg.connect_timeout_ms > 0) check_connect_timeouts(cli);

        for (int i = 0; i < n; i++) {
            event_t* ev = &cli->events[i];
            void* d = ev->data;
            if (d == cli) {
                drain_wake(cli);
                continue;
            }
            tcp_conn_t* c = d;
            if (!c) continue;
            dispatch_event(cli, c, ev);
        }

        if (cli->cfg.exit_when_idle && cli->count == 0) break;
    }
    return rc;
}

void tcp_client_stop(tcp_client_t* cli) {
    if (!cli) return;
    atomic_store_explicit(&cli->running, 0, memory_order_relaxed);
    uint64_t one = 1;
    (void)sys_write_direct(cli->wake_fd, &one, sizeof(one));
}
