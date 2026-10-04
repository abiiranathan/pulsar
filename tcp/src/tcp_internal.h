#ifndef TCP_INTERNAL_H
#define TCP_INTERNAL_H

/*
 * Shared internal state and entry points for the tcp package. Not installed;
 * only tcp_connection.c and tcp_client.c include it.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "tcp/tcp_buffer.h"
#include "tcp/tcp_client.h"
#include "tcp/tcp_connection.h"
#include "tcp/tcp_events.h"

struct tcp_conn {
    int fd;
    tcp_conn_state_t state;
    bool closing;
    bool want_write;   /* EPOLLOUT currently armed */
    bool in_callback;  /* guards reentrant close/stop */
    bool notify_connected; /* on_connected deferred to the next loop turn */
    bool close_after_flush; /* close() waits for queued output to drain */
    int close_err;     /* errno to report to on_closed */
    size_t read_chunk; /* per-read size, <= client cfg.read_chunk */
    uint64_t connect_deadline_ms; /* 0 = no timeout */
    void* userdata;
    tcp_buffer_t out;
    struct tcp_client* owner;
    struct tcp_conn* next;
    struct tcp_conn* prev;
    tcp_conn_cbs_t cbs;
};

struct tcp_client {
    event_queue_t queue;
    int wake_fd;
    atomic_int running;
    size_t count;
    size_t connecting;
    size_t pending_notify;
    struct tcp_conn* head;
    tcp_client_config_t cfg;
    char* rbuf;
    struct epoll_event* raw_events;
    event_t* events;
};

/* tcp_connection.c */
tcp_conn_t* tcp_conn_alloc(tcp_client_t* cli, int fd, void* userdata, const tcp_conn_cbs_t* cbs);
void tcp_conn_free(tcp_conn_t* c);
void tcp_conn_unlink(tcp_conn_t* c);
void tcp_conn_finalize(tcp_conn_t* c, int err);

/* Event handlers driven by the loop (tcp_client.c). Each may mark the
 * connection closing but never frees it. */
void tcp_conn_on_connect(tcp_conn_t* c);
void tcp_conn_on_read(tcp_conn_t* c);
void tcp_conn_on_write(tcp_conn_t* c);

/* tcp_client.c helpers used by tcp_connection.c */
void tcp_client_arm_write(tcp_conn_t* c);
void tcp_client_arm_read(tcp_conn_t* c);

/* Monotonic milliseconds. */
uint64_t tcp_now_ms(void);

#endif /* TCP_INTERNAL_H */
