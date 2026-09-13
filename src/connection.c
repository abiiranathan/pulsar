#include "internal.h"
#include "workerpool.h"

/* ================================================================
 * Connection Lifecycle
 *
 * init/reset/close plus the two read-only connection predicates. The
 * request/response buffers themselves are owned by request.c/response.c.
 * ================================================================ */

void free_response_body(response_t* resp) {
    if (HAS_HEAP_ALLOCATED(resp->flags) && resp->body.heap) {
        free(resp->body.heap);
        resp->body.heap = NULL;
        CLR_HEAP_ALLOCATED(resp->flags);
    }
}

bool init_connection(PulsarConn* conn, Arena* arena, int client_fd, int worker_id) {
    request_t* req = &conn->request;
    response_t* res = &conn->response;
    conn->closing = false;
    conn->client_fd = client_fd;
    conn->worker_id = worker_id;
    conn->keep_alive = true;
    conn->in_keep_alive = false;
    conn->abort = false;
    conn->arena = arena;
    conn->last_activity = pulsar_mono_sec();
    conn->pending_len = 0;
    conn->next = NULL;
    conn->prev = NULL;

    locals_init(&conn->locals, 64);
    headers_init(&req->headers);
    headers_init(&req->query_params);
    req->hdr_data = NULL;
    req->hdr_len_raw = 0;
    req->headers_parsed = true; /* nothing pending; process_request sets it per request */

    res->file_fd = -1;
    res->status_code = StatusOK;
    res->status_len = 0;
    res->headers_len = 0;
    res->body_len = 0;
    res->out_len = 0;
    res->out_sent = 0;
    res->flags = 0;
    res->body_capacity = 0;
    res->body_sent = 0;
    res->body.heap = NULL;
    /* Force the first request on a (new or pooled) connection to stage the
     * Date prefix: buf contents are garbage or belong to an older Date. */
    res->date_gen = 0;

    return true;
}

bool reset_connection(PulsarConn* conn) {
    conn->closing = false;
    conn->keep_alive = true;
    conn->abort = false;
    response_t* res = &conn->response;

    if (HAS_HEAP_ALLOCATED(res->flags)) {
        free_response_body(res);
    }

    conn->request.content_length = 0;
    conn->request.body = NULL;
    conn->request.range_hdr = (StrSlice){.data = NULL, .len = 0};
    conn->request.hdr_data = NULL;
    conn->request.hdr_len_raw = 0;
    conn->request.headers_parsed = true;
    arena_reset(conn->arena);
    headers_init(&conn->request.headers);
    headers_init(&conn->request.query_params);

    res->status_code = StatusOK;
    res->status_len = 0;
    res->headers_len = 0;
    res->body_len = 0;
    res->body_sent = 0;
    res->out_len = 0;
    res->out_sent = 0;
    res->flags = 0;
    res->file_fd = -1;
    res->file_size = 0;
    res->file_offset = 0;
    res->range_end = 0;
    /* Deliberately preserve res->date_gen + buf[0..prefix): when the Date
     * second hasn't rolled over the next request reuses the staged prefix
     * with zero copies. finalize_response() already invalidated it (0) if
     * the previous response overwrote the 200 OK prefix. */

    if (!conn->in_keep_alive) {
        conn->next = NULL;
        conn->prev = NULL;
    }
    return true;
}

void close_connection(event_queue_t* queue, PulsarConn* conn, KeepAliveState* ka_state,
                      int worker_id) {
    if (!conn || conn->client_fd == -1) return;

    event_delete(queue, conn->client_fd);
    sys_close_direct(conn->client_fd);
    conn->client_fd = -1;

    if (conn->in_keep_alive) {
        remove_keepalive_connection(conn, ka_state);
    }

    free_response_body(&conn->response);
    locals_destroy(&conn->locals);
    worker_pool_release(worker_id, conn, conn->arena);
}

bool conn_is_open(PulsarConn* conn) { return conn && conn->client_fd != -1 && !conn->closing; }

int conn_worker_id(PulsarConn* conn) { return conn ? conn->worker_id : 0; }
