#include "internal.h"

#if ENABLE_SLOW_WORKERS

#define SLOW_KEEPALIVE_CHECK_S 5

/* ================================================================
 * Slow Worker Pool
 *
 * Background threads that take over long-lived / offloaded connections
 * (SSE, websockets, slow handlers) so the main workers keep spinning on
 * the request hot path.
 * ================================================================ */

ALIGN(64) SlowWorker slow_workers[NUM_SLOW_WORKERS];
ALIGN(64) _Atomic int next_slow_worker = 0;

static void slow_close_offloaded(event_queue_t* queue, PulsarConn* conn) {
    if (conn->offload_hooks.on_close) {
        conn->offload_hooks.on_close(conn);
    }
    event_delete(queue, conn->client_fd);
    sys_close_direct(conn->client_fd);
    conn->client_fd = -1;

    free_response_body(&conn->response);
    locals_destroy(&conn->locals);
    arena_destroy(conn->arena);
    free(conn);
}

void* slow_worker_thread(void* arg) {
    SlowWorker* worker = (SlowWorker*)arg;
    event_queue_t* queue = &worker->queue;
    KeepAliveState* ka = &worker->ka_state;
    event_t events[MAX_EVENTS] = {0};
    struct epoll_event raw_events[MAX_EVENTS] = {0};
    time_t last_timeout_check = 0;

    while (server_running) {
        int n = event_wait(queue, raw_events, events, MAX_EVENTS, 500);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("slow_worker event_wait");
            continue;
        }

        time_t mono_now = pulsar_mono_sec();
        if (mono_now - last_timeout_check >= SLOW_KEEPALIVE_CHECK_S) {
            PulsarConn* cur = ka->head;
            while (cur) {
                PulsarConn* nxt = cur->next;
                if (conn_timedout(mono_now, cur->last_activity)) {
                    remove_keepalive_connection(cur, ka);
                    slow_close_offloaded(queue, cur);
                }
                cur = nxt;
            }
            last_timeout_check = mono_now;
        }

        for (int i = 0; i < n; i++) {
            event_t* ev = &events[i];
            PulsarConn* conn = (PulsarConn*)ev->data;
            if (!conn) continue;

            conn->last_activity = pulsar_mono_sec();

            if (ev->error) {
                conn->closing = true;
                goto maybe_close;
            }

            if (ev->readable) {
                char peek_buf[1];
                ssize_t r = sys_recv_direct(conn->client_fd, peek_buf, sizeof(peek_buf),
                                            MSG_PEEK | MSG_DONTWAIT);
                if (r == 0) {
                    conn->closing = true;
                } else if (r < 0 && r != -EAGAIN && r != -EWOULDBLOCK) {
                    conn->closing = true;
                } else if (r > 0 && conn->offload_hooks.on_read) {
                    conn->offload_hooks.on_read(conn);
                }
            }

            if (ev->writable && !conn->closing) {
                if (conn->offload_hooks.on_write) {
                    conn->offload_hooks.on_write(conn);
                }
            }

        maybe_close:
            if (conn->closing) {
                if (conn->in_keep_alive) {
                    remove_keepalive_connection(conn, ka);
                }
                slow_close_offloaded(queue, conn);
            }
        }
    }

    event_queue_close(queue);
    return NULL;
}

bool pulsar_handoff(PulsarConn* conn, PulsarOffloadHandler handlers) {
    /* Offloaded handlers may run long after the worker read buffer is
     * reused: materialize the header table now, while the raw span is
     * guaranteed valid (handoff is always called synchronously from a
     * route handler). Cold path, correctness only. */
    ensure_headers_parsed(conn);

    if (event_delete(conn->owner_queue, conn->client_fd) < 0) return false;

    if (conn->in_keep_alive && conn->owner_ka_state) {
        remove_keepalive_connection(conn, (KeepAliveState*)conn->owner_ka_state);
    }

    conn->offloaded = true;
    conn->offload_hooks = handlers;

    int idx =
        atomic_fetch_add_explicit(&next_slow_worker, 1, memory_order_relaxed) % NUM_SLOW_WORKERS;
    SlowWorker* target = &slow_workers[idx];

    conn->owner_queue = &target->queue;
    conn->owner_ka_state = &target->ka_state;

    int ret = event_add_read(&target->queue, conn->client_fd, conn);
    if (ret >= 0 && handlers.on_write) {
        ret = event_mod_write(&target->queue, conn->client_fd, conn);
    }

    if (ret < 0) {
        if (handlers.on_close) handlers.on_close(conn);
        sys_close_direct(conn->client_fd);
        conn->client_fd = -1;
        free_response_body(&conn->response);
        locals_destroy(&conn->locals);
        arena_destroy(conn->arena);
        free(conn);
        return false;
    }

    return true;
}

#endif /* ENABLE_SLOW_WORKERS */
