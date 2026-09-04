#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <solidc/file.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <sys/uio.h>
#include <unistd.h>
#include "../include/pulsar_itoa.h"

#if defined(__AVX2__)
#include <immintrin.h>
#endif

#include "../include/events.h"
#include "../include/mimetypes.h"
#include "../include/plog.h"
#include "../include/pulsar.h"
#include "../include/pulsar_syscall.h"

static int worker_listen_fds[NUM_WORKERS]; /**< Per-worker SO_REUSEPORT listeners. */
volatile sig_atomic_t server_running = 1;
static HttpHandler global_middleware[MAX_GLOBAL_MIDDLEWARE] = {0};
static size_t global_mw_count = 0;
static void* GLOBAL_HANDLER_USERDATA = NULL;

#define SERVER_NAME "PULSAR/1.0 (Unix)"

#define conn_timedout(now, last_activity) ((now) - (last_activity) > CONNECTION_TIMEOUT)

// Keep-Alive state is a linked list of connections.
typedef struct KeepAliveState {
    PulsarConn* head;
    PulsarConn* tail;
    size_t count;
} KeepAliveState;

/* ================================================================
 * Forward Declarations
 * ================================================================ */
static void finalize_response(PulsarConn* conn, HttpMethod method);
static void handle_write(event_queue_t* queue, PulsarConn* conn, KeepAliveState* state);
INLINE void free_response_body(response_t* resp);
INLINE void remove_keepalive_connection(PulsarConn* conn, KeepAliveState* state);
INLINE void close_connection(event_queue_t* queue, PulsarConn* conn, KeepAliveState* ka_state);

/* ================================================================
 * Slow Worker Pool
 * ================================================================ */
typedef struct SlowWorker {
    pthread_t thread;                /**< OS thread handle. */
    event_queue_t* queue;            /**< Event queue (solidc poller). */
    int id;                          /**< Zero-based worker index, useful for debugging. */
    KeepAliveState keep_alive_state; /**< Idle-connection timeout list. */
} SlowWorker;

static SlowWorker slow_workers[NUM_SLOW_WORKERS];
static _Atomic int next_slow_worker = 0;

/* ----------------------------------------------------------------
 * slow_close_offloaded
 *
 * Common teardown path for a connection that has been handed off to a slow
 * worker.  Runs the user's on_close hook (if registered), removes the fd from
 * the event queue, and frees all resources associated with the connection.
 *
 * @param queue     The slow worker's event queue.
 * @param conn      The connection to tear down.  Must not be NULL.
 * ---------------------------------------------------------------- */
static void slow_close_offloaded(event_queue_t* queue, PulsarConn* conn) {
    /* Notify user code first so it can clean up its own state (e.g. remove
     * the connection from a subscribers list) before the fd is closed. */
    if (conn->offload_hooks.on_close) {
        conn->offload_hooks.on_close(conn);
    }

    event_delete(queue, conn->client_fd);
    sys_close_direct(conn->client_fd);
    conn->client_fd = -1;

    free_response_body(&conn->response);
    LocalsClear(&conn->locals);
    arena_destroy(conn->arena);
    free(conn);
}

/* ----------------------------------------------------------------
 * slow_worker_thread
 *
 * Event loop for one slow-worker thread.  Handles an unbounded number of
 * offloaded connections by multiplexing them through a single kernel event
 * queue.  The thread exits when server_running is cleared.
 *
 * Timeout handling: idle connections are scanned every SLOW_KEEPALIVE_CHECK_S
 * seconds (default 5 s) and closed if they exceed CONNECTION_TIMEOUT.
 * ---------------------------------------------------------------- */
#ifndef SLOW_KEEPALIVE_CHECK_S
#define SLOW_KEEPALIVE_CHECK_S 5
#endif

static void* slow_worker_thread(void* arg) {
    SlowWorker* worker = (SlowWorker*)arg;
    event_queue_t* queue = worker->queue;
    KeepAliveState* ka = &worker->keep_alive_state;
    event_t events[MAX_EVENTS] = {0};

    long last_timeout_check = 0;

    while (server_running) {
        int n = event_wait(queue, events, MAX_EVENTS, 2000);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("slow_worker event_wait");
            continue;
        }

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if (ts.tv_sec - last_timeout_check >= SLOW_KEEPALIVE_CHECK_S) {
            PulsarConn* cur = ka->head;
            time_t now = time(NULL);
            while (cur) {
                PulsarConn* nxt = cur->next;
                if (conn_timedout(now, cur->last_activity)) {
                    remove_keepalive_connection(cur, ka);
                    slow_close_offloaded(queue, cur);
                }
                cur = nxt;
            }
            last_timeout_check = ts.tv_sec;
        }

        for (int i = 0; i < n; i++) {
            const event_t* ev = &events[i];
            PulsarConn* conn = (PulsarConn*)event_get_data(ev);
            if (!conn) continue;

            conn->last_activity = time(NULL);

            if (event_is_error(ev)) {
                conn->closing = true;
                goto maybe_close;
            }

            if (event_is_read(ev)) {
                char peek_buf[1];
                ssize_t r = sys_recv_direct(conn->client_fd, peek_buf, sizeof(peek_buf), MSG_PEEK | MSG_DONTWAIT);
                if (r == 0) {
                    conn->closing = true;
                } else if (r < 0 && r != -EAGAIN && r != -EWOULDBLOCK) {
                    conn->closing = true;
                } else if (r > 0 && conn->offload_hooks.on_read) {
                    conn->offload_hooks.on_read(conn);
                }
            }

            if (event_is_write(ev) && !conn->closing) {
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

    event_queue_free(queue);
    return NULL;
}

bool pulsar_handoff(PulsarConn* conn, PulsarOffloadHandler handlers) {
    if (event_delete(conn->owner_queue, conn->client_fd) < 0) return false;

    if (conn->in_keep_alive && conn->owner_ka_state) {
        remove_keepalive_connection(conn, (KeepAliveState*)conn->owner_ka_state);
    }

    conn->offloaded = true;
    conn->offload_hooks = handlers;

    int idx = atomic_fetch_add_explicit(&next_slow_worker, 1, memory_order_relaxed) % NUM_SLOW_WORKERS;
    SlowWorker* target = &slow_workers[idx];

    conn->owner_queue = target->queue;
    conn->owner_ka_state = &target->keep_alive_state;

    int ret = event_add_read(target->queue, conn->client_fd, conn);
    if (ret >= 0 && handlers.on_write) {
        ret = event_mod_write(target->queue, conn->client_fd, conn);
    }

    if (ret < 0) {
        if (handlers.on_close) handlers.on_close(conn);
        sys_close_direct(conn->client_fd);
        conn->client_fd = -1;
        free_response_body(&conn->response);
        LocalsClear(&conn->locals);
        arena_destroy(conn->arena);
        free(conn);
        return false;
    }

    return true;
}

static void remove_keepalive_connection(PulsarConn* conn, KeepAliveState* state) {
    if (!conn->in_keep_alive) return;

    if (conn->prev)
        conn->prev->next = conn->next;
    else
        state->head = conn->next;

    if (conn->next)
        conn->next->prev = conn->prev;
    else
        state->tail = conn->prev;

    conn->prev = NULL;
    conn->next = NULL;
    state->count--;
    conn->in_keep_alive = false;
}

static void AddKeepAliveConnection(PulsarConn* conn, KeepAliveState* state) {
    if (conn->in_keep_alive) return;

    conn->next = state->head;
    conn->prev = NULL;

    if (state->head)
        state->head->prev = conn;
    else
        state->tail = conn;

    state->head = conn;
    state->count++;
    conn->in_keep_alive = true;
}

static void CheckKeepAliveTimeouts(KeepAliveState* state, event_queue_t* queue) {
    PulsarConn* current = state->head;
    time_t now = time(NULL);
    while (current) {
        PulsarConn* next = current->next;
        if (conn_timedout(now, current->last_activity)) {
            close_connection(queue, current, state);
        }
        current = next;
    }
}

/* ================================================================
 * Signal Handler
 * ================================================================ */
void handle_sigint(int sig) {
    if (sig == SIGINT || sig == SIGTERM) server_running = 0;
}

static void install_signal_handler(void) {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

INLINE void ensure_headers_capacity(Arena* arena, response_t* res, size_t required) {
    if (LIKELY((size_t)res->headers_len + required < (size_t)res->headers_cap)) {
        return;
    }
    size_t new_cap = (size_t)res->headers_cap * 2;
    res->headers_buf = arena_realloc(arena, res->headers_buf, res->headers_cap, new_cap, ARENA_DEFAULT_ALIGN);
    ASSERT(res->headers_buf);
    res->headers_cap = (uint32_t)new_cap;
}

INLINE void free_response_body(response_t* resp) {
    if (HAS_HEAP_ALLOCATED(resp->flags) && resp->body.heap) {
        free(resp->body.heap);
        resp->body.heap = NULL;
        CLR_HEAP_ALLOCATED(resp->flags);
    }
}

static bool init_connection(PulsarConn* conn, Arena* arena, int client_fd, int worker_id) {
    request_t* req = &conn->request;
    response_t* res = &conn->response;
    conn->closing = false;
    conn->client_fd = client_fd;
    conn->worker_id = worker_id;
    conn->keep_alive = true;
    conn->in_keep_alive = false;
    conn->abort = false;
    conn->arena = arena;
    conn->last_activity = time(NULL);
    conn->pending_len = 0;
    conn->next = NULL;
    conn->prev = NULL;

    LocalsInit(&conn->locals);

    if (req->headers) headers_init(req->headers);

    res->body_capacity = WRITE_BUFFER_SIZE;
    res->file_fd = -1;
    res->headers_cap = HEADERS_DEFAULT_CAPACITY;

    return (conn->read_buf && req->path && req->headers && res->status_buf && res->headers_buf && res->out_buf);
}

INLINE bool reset_connection(PulsarConn* conn) {
    conn->closing = false;
    conn->keep_alive = true;
    conn->abort = false;
    response_t* res = &conn->response;

    if (unlikely(HAS_HEAP_ALLOCATED(res->flags))) {
        free_response_body(res);
    }

    conn->request.query_params = NULL;
    /* Per-request state must not leak across keep-alive reuse: a stale
     * content_length corrupts pipelining offsets (consumed) and serves the
     * previous request's body to the next handler. */
    conn->request.content_length = 0;
    conn->request.body = NULL;
    conn->request.range_hdr = (StrSlice){.data = NULL, .len = 0};
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

    if (unlikely(conn->locals.size > 0)) {
        LocalsClear(&conn->locals);
    }

    arena_reset(conn->arena);

    if (!conn->in_keep_alive) {
        conn->next = NULL;
        conn->prev = NULL;
    }
    return true;
}

static void close_connection(event_queue_t* queue, PulsarConn* conn, KeepAliveState* ka_state) {
    if (!conn || conn->client_fd == -1) return;

    event_delete(queue, conn->client_fd);
    sys_close_direct(conn->client_fd);
    conn->client_fd = -1;

    remove_keepalive_connection(conn, ka_state);
    free_response_body(&conn->response);
    LocalsClear(&conn->locals);
    arena_destroy(conn->arena);
    free(conn);
}

/* ================================================================
 * Error Response Helper
 * ================================================================ */
INLINE void write_error(PulsarConn* conn, http_status status) {
    conn_set_status(conn, status);
    conn_set_content_type(conn, SS_LIT(PLAINTEXT_TYPE));
    conn_write_string(conn, "Something went wrong");
    finalize_response(conn, conn->request.method_type);
}

/* ================================================================
 * Zero-Branch AVX2 Header End Search
 * ================================================================ */
#if defined(__AVX2__)
/* Hoisted broadcast patterns: building these vectors per request costs ~2
 * extra uops on every call. A 32-byte load of a compile-time pattern is
 * cheaper and keeps the per-request path to pure scan work. */
alignas(32) static const uint8_t HDR_CR_PAT[32] = {'\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r',
                                                   '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r',
                                                   '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r'};
alignas(32) static const uint8_t HDR_LF_PAT[32] = {'\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n',
                                                   '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n',
                                                   '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n'};
#endif

INLINE const char* find_headers_end(const char* buf, size_t len) {
    if (unlikely(len < 4)) return NULL;

    const char* p = buf;
    const char* end = buf + len;

#if defined(__AVX2__)
    const __m256i r_vec = _mm256_load_si256((const __m256i*)HDR_CR_PAT);
    const __m256i n_vec = _mm256_load_si256((const __m256i*)HDR_LF_PAT);

    uint32_t prev_r = 0;
    uint32_t prev_n = 0;

    while (p + 32 <= end) {
        __m256i v = _mm256_loadu_si256((const __m256i*)p);
        uint32_t mask_r = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, r_vec));
        uint32_t mask_n = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, n_vec));

        uint64_t full_r = ((uint64_t)mask_r << 3) | prev_r;
        uint64_t full_n = ((uint64_t)mask_n << 3) | prev_n;

        uint64_t match = full_r & (full_n >> 1) & (full_r >> 2) & (full_n >> 3);
        uint32_t match32 = (uint32_t)(match >> 3);

        if (match32) {
            int idx = __builtin_ctz(match32);
            return p + idx;
        }

        prev_r = mask_r >> 29;
        prev_n = mask_n >> 29;
        p += 32;
    }
#endif

    /* The AVX2 loop can advance p past scalar_end (end-3): a \r\n\r\n
     * starting up to 3 bytes before p overlaps the last scanned block but was
     * never fully visible to either path (the carry only covers interior
     * block boundaries). Rewind the tail scan by 3 so every 4-byte window in
     * [buf, end) is examined exactly once. Without this, requests whose
     * terminator straddles the boundary return NULL and hang forever. */
    const char* scalar_end = end - 3;
    const char* sp = (p > buf + 3) ? p - 3 : buf;
    while (sp < scalar_end) {
        uint32_t v;
        memcpy(&v, sp, 4);
        if (v == UINT32_C(0x0a0d0a0d)) return sp;
        sp++;
    }
    return NULL;
}

INLINE uint64_t fast_atou64(const char* str, size_t len) {
    uint64_t val = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)(str[i] - '0');
        if (c > 9) break;
        val = val * 10 + c;
    }
    return val;
}

/* Branchless ASCII case-insensitive header-name match via SWAR word compares.
 * Replaces strncasecmp() (locale-aware libc call behind a PLT on the hot path)
 * for the only two headers the parser cares about. Lowercasing is a single
 * OR per word; the precomputed targets were verified against the literals.
 * Note: |0x20 also folds 0x40-0x5F bytes (e.g. '@') onto lowercase, but those
 * bytes are illegal in HTTP token names, so a match there only affects
 * already-malformed input (and the value checks still validate). */
INLINE bool match_connection(const char* s) {
    uint64_t a;
    uint16_t b;
    __builtin_memcpy(&a, s, 8);
    __builtin_memcpy(&b, s + 8, 2);
    return ((a | UINT64_C(0x2020202020202020)) == UINT64_C(0x697463656e6e6f63)) && /* "connecti" */
           ((uint16_t)(b | UINT16_C(0x2020)) == UINT16_C(0x6e6f));                 /* "on" */
}

INLINE bool match_content_length(const char* s) {
    uint64_t a, b;
    __builtin_memcpy(&a, s, 8);
    __builtin_memcpy(&b, s + 8, 6); /* exactly the 6 remaining bytes: no overread */
    return ((a | UINT64_C(0x2020202020202020)) == UINT64_C(0x2d746e65746e6f63)) && /* "content-" */
           (((b | UINT64_C(0x2020202020202020)) & UINT64_C(0x0000ffffffffffff)) == UINT64_C(0x00006874676e656c));
}

static bool parse_request_headers(PulsarConn* conn, const char* hdrs, HttpMethod method, size_t headers_len) {
    const char* ptr = hdrs;
    const char* end = ptr + headers_len;
    const bool is_safe = SAFE_METHOD(method);
    request_t* req = &conn->request;
    conn->keep_alive = true;
    uint8_t flags = 0;

    while (ptr < end) {
        const char* const colon = memchr(ptr, ':', (size_t)(end - ptr));
        if (!colon) break;

        const size_t name_len = (size_t)(colon - ptr);
        if (unlikely(name_len == 0)) return false;

        const char* value_start = colon + 1;
        while (value_start < end && (*value_start == ' ' || *value_start == '\t')) value_start++;

        const char* const eol = memchr(value_start, '\r', (size_t)(end - value_start));
        if (!eol || eol + 1 >= end || eol[1] != '\n') break;

        const char* value_end = eol;
        while (value_end > value_start && (value_end[-1] == ' ' || value_end[-1] == '\t')) value_end--;
        const size_t value_len = (size_t)(value_end - value_start);

        const char fc = (char)(ptr[0] | 0x20);
        /* Range is the only header the core needs after parsing (static file
         * serving): extract it as a view instead of storing every header into
         * request.headers (which cost ~100 cycles/req in headers_set scans).
         * Views into read_buf are valid for this request's lifetime. */
        if (fc == 'r' && name_len == 5 && req->range_hdr.data == NULL) {
            uint64_t w = 0;
            __builtin_memcpy(&w, ptr, 5);
            if (((w | UINT64_C(0x2020202020202020)) & UINT64_C(0x000000ffffffffff)) ==
                UINT64_C(0x00000065676e6172)) { /* "range" */
                req->range_hdr = (StrSlice){.data = value_start, .len = value_len};
            }
        }

        if (fc == 'c') {
            if (!is_safe && name_len == 14 && !(flags & 1)) {
                if (match_content_length(ptr)) {
                    req->content_length = (size_t)fast_atou64(value_start, value_len);
                    flags |= 1;
                }
            } else if (name_len == 10 && !(flags & 2)) {
                if (match_connection(ptr)) {
                    /* "close" is always lowercase from compliant clients; use a
                     * single integer compare instead of strncasecmp. */
                    uint64_t w = 0;
                    if (value_len == 5) __builtin_memcpy(&w, value_start, 5);
                    conn->keep_alive =
                        !((value_len == 5) && (((w | UINT64_C(0x2020202020202020)) & UINT64_C(0x000000ffffffffff)) ==
                                               UINT64_C(0x00000065736f6c63)));
                    flags |= 2;
                }
            }
        }

        ptr = eol + 2;
    }
    return true;
}

static bool parse_query_params(PulsarConn* conn, size_t* path_len) {
    char* const path = conn->request.path;
    const char* query = memchr(path, '?', *path_len);
    if (!query) return true;

    path[query - path] = '\0';
    *path_len = (size_t)(query - path);

    const char* ptr = query + 1;
    const char* end = ptr + strlen(ptr);

    conn->request.query_params = arena_alloc(conn->arena, sizeof(headers_t));
    if (!conn->request.query_params) return false;
    headers_init(conn->request.query_params);

    while (ptr < end) {
        const char* eq = memchr(ptr, '=', (size_t)(end - ptr));
        const char* amp = memchr(ptr, '&', (size_t)(end - ptr));

        const char* key_end = eq && (!amp || eq < amp) ? eq : (amp ? amp : end);
        StrSlice key = {.data = ptr, .len = (size_t)(key_end - ptr)};
        StrSlice value = {.data = key_end, .len = 0};

        if (eq && (!amp || eq < amp)) {
            const char* val_start = eq + 1;
            const char* val_end = amp ? amp : end;
            value = (StrSlice){.data = val_start, .len = (size_t)(val_end - val_start)};
            ptr = val_end;
        } else {
            ptr = key_end;
        }

        if (ptr < end && *ptr == '&') ptr++;
        if (key.len == 0) continue;

        if (!headers_set(conn->request.query_params, key, value)) {
            return false;
        }
    }
    return true;
}

static http_status parse_request_body(PulsarConn* conn, const char* buf, size_t headers_len, size_t read_bytes) {
    if (conn->request.content_length == 0) return StatusOK;

    request_t* req = &conn->request;
    size_t content_length = req->content_length;
    size_t body_available = read_bytes - headers_len;
    if (body_available > content_length) body_available = content_length;

    if (content_length > MAX_BODY_SIZE) {
        return StatusRequestEntityTooLarge;
    }

    req->body = arena_alloc(conn->arena, content_length + 1);
    if (!req->body) {
        perror("arena_alloc failed to allocated body");
        return StatusInternalServerError;
    }

    memcpy(req->body, buf + headers_len, body_available);
    req->body[body_available] = '\0';

    size_t received = body_available;
    while (received < content_length) {
        ssize_t n = sys_read_direct(conn->client_fd, req->body + received, content_length - received);
        if (n < 0) {
            if (n == -EAGAIN || n == -EWOULDBLOCK) {
                usleep(10);
                continue;
            }
            if (n == -EINTR) continue;
            perror("read body");
            return StatusInternalServerError;
        }
        if (n == 0) {
            perror("read body EOF");
            return StatusInternalServerError;
        }
        received += (size_t)n;
    }
    return StatusOK;
}

/* ================================================================
 * Request Getters
 * ================================================================ */
char* req_body(PulsarConn* conn) { return conn->request.body; }

StrSlice req_body_slice(PulsarConn* conn) {
    return (StrSlice){
        .data = conn->request.body,
        .len = conn->request.content_length,
    };
}

const char* req_method(PulsarConn* conn) { return conn->request.method; }
const char* req_path(PulsarConn* conn) { return conn->request.path; }

const char* query_get(PulsarConn* conn, const char* name) {
    if (!conn->request.query_params) return NULL;
    StrSlice h = headers_get(conn->request.query_params, name);
    return arena_strdupn(conn->arena, h.data, h.len);
}

headers_t* query_params(PulsarConn* conn) { return conn->request.query_params; }
const headers_t* req_headers(PulsarConn* conn) { return (const headers_t*)conn->request.headers; }

const char* req_header_get(PulsarConn* conn, const char* name) {
    StrSlice h = headers_get(conn->request.headers, name);
    return arena_strdupn(conn->arena, h.data, h.len);
}

void conn_set_status(PulsarConn* restrict conn, http_status code) {
    response_t* res = &conn->response;
    res->status_code = (uint16_t)code;

    // Fast SWAR 200 OK
    if (likely(code == StatusOK)) {
        *(uint64_t*)(res->status_buf + 0) = UINT64_C(0x312e312f50545448); /* "HTTP/1.1" */
        *(uint64_t*)(res->status_buf + 8) = UINT64_C(0x0d4b4f2030303220); /* " 200 OK\r" */
        res->status_buf[16] = '\n';
        res->status_len = 17;
        return;
    }

    StrSlice status = get_http_status(code);
    res->status_len = (uint8_t)status.len;
    __builtin_memcpy(res->status_buf, status.data, status.len);
}

http_status res_get_status(PulsarConn* conn) { return (http_status)conn->response.status_code; }

char* res_header_get(PulsarConn* conn, const char* name) {
    response_t* res = &conn->response;
    char* buf = res->headers_buf;
    buf[res->headers_len] = '\0';

    char* ptr = strstr(buf, name);
    if (!ptr) return NULL;
    ptr += strlen(name) + 2;

    char* end = strstr(ptr, "\r\n");
    if (!end) return NULL;

    size_t vlen = (size_t)(end - ptr);
    char* result = malloc(vlen + 1);
    if (!result) return NULL;
    memcpy(result, ptr, vlen);
    result[vlen] = '\0';
    return result;
}

bool res_header_get_buf(PulsarConn* conn, const char* __restrict__ name, char* __restrict__ dest, size_t dest_size) {
    response_t* res = &conn->response;
    char* buf = res->headers_buf;
    buf[res->headers_len] = '\0';

    char* ptr = strstr(buf, name);
    if (!ptr) return false;
    ptr += strlen(name) + 2;

    char* end = strstr(ptr, "\r\n");
    if (!end) return false;

    size_t vlen = (size_t)(end - ptr);
    if (dest_size <= vlen) return false;
    memcpy(dest, ptr, vlen);
    dest[vlen] = '\0';
    return true;
}

/* ================================================================
 * Response Header Writers
 * ================================================================ */
void conn_writeheader(PulsarConn* conn, StrSlice name, StrSlice value) {
    response_t* resp = &conn->response;
    Arena* a = conn->arena;
    size_t required = name.len + value.len + 4;
    ensure_headers_capacity(a, resp, required);

    char* dest = resp->headers_buf + resp->headers_len;
    __builtin_memcpy(dest, name.data, name.len);
    dest[name.len] = ':';
    dest[name.len + 1] = ' ';
    __builtin_memcpy(dest + name.len + 2, value.data, value.len);
    dest[name.len + 2 + value.len] = '\r';
    dest[name.len + 2 + value.len + 1] = '\n';
    resp->headers_len += (uint32_t)required;
}

void conn_writeheader_raw(PulsarConn* conn, const char* header, size_t length) {
    response_t* resp = &conn->response;
    Arena* a = conn->arena;
    ensure_headers_capacity(a, resp, length);
    __builtin_memcpy(resp->headers_buf + resp->headers_len, header, length);
    resp->headers_len += (uint32_t)length;
}

void conn_writeheaders_vec(PulsarConn* conn, const struct iovec* headers, size_t count) {
    response_t* resp = &conn->response;
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++) {
        total_len += headers[i].iov_len;
    }

    ensure_headers_capacity(conn->arena, resp, total_len);

    char* dest = resp->headers_buf + resp->headers_len;
    for (size_t i = 0; i < count; i++) {
        __builtin_memcpy(dest, headers[i].iov_base, headers[i].iov_len);
        dest += headers[i].iov_len;
    }
    resp->headers_len += (uint32_t)total_len;
}

void conn_set_content_type(PulsarConn* conn, StrSlice content_type) {
    if (HAS_CONTENT_TYPE(conn->response.flags)) return;
    conn_writeheader(conn, SS_LIT("Content-Type"), content_type);
    SET_CONTENT_TYPE(conn->response.flags);
}

/* ================================================================
 * Response Body Writers
 * ================================================================ */
int conn_write(PulsarConn* conn, const void* data, size_t len) {
    response_t* res = &conn->response;
    size_t body_len = res->body_len;
    size_t required = body_len + len;

    if (unlikely(required > UINT32_MAX)) {
        fprintf(stderr, "body too large\n");
        return -1;
    }

    if (likely(!HAS_HEAP_ALLOCATED(res->flags))) {
        if (required <= STACK_BUFFER_SIZE) {
            __builtin_memcpy(res->body.stack + body_len, data, len);
            res->body_len = (uint32_t)required;
            return (int)len;
        }

        size_t cap = WRITE_BUFFER_SIZE;
        while (cap < required) {
            if (cap > SIZE_MAX / 2) {
                cap = required;
                break;
            }
            cap *= 2;
        }
        if (unlikely(cap > UINT32_MAX)) {
            fprintf(stderr, "body too large\n");
            return -1;
        }
        uint8_t* hp = aligned_alloc(CACHE_LINE_SIZE, cap);
        if (!hp) {
            perror("aligned_alloc");
            return -1;
        }
        __builtin_memcpy(hp, res->body.stack, body_len);
        SET_HEAP_ALLOCATED(res->flags);
        res->body_capacity = (uint32_t)cap;
        res->body.heap = hp;
    }

    if (required > res->body_capacity) {
        size_t cap = res->body_capacity;
        while (cap < required) {
            if (cap > SIZE_MAX / 2) {
                fprintf(stderr, "body too large\n");
                return -1;
            }
            cap *= 2;
        }
        if (unlikely(cap > UINT32_MAX)) {
            fprintf(stderr, "body too large\n");
            return -1;
        }
        uint8_t* nb = realloc(res->body.heap, cap);
        if (!nb) {
            perror("realloc body");
            return -1;
        }
        res->body.heap = nb;
        res->body_capacity = (uint32_t)cap;
    }

    __builtin_memcpy(res->body.heap + body_len, data, len);
    res->body_len = (uint32_t)required;
    return (int)len;
}

int conn_notfound(PulsarConn* conn) {
    conn_set_status(conn, StatusNotFound);
    conn_set_content_type(conn, SS_LIT(PLAINTEXT_TYPE));
    return conn_write(conn, "404 Not Found", 13);
}

int conn_write_string(PulsarConn* conn, const char* str) { return str ? conn_write(conn, str, strlen(str)) : 0; }

int conn_writef(PulsarConn* conn, const char* restrict fmt, ...) {
    va_list args;
    char sbuf[4096];
    int len;

    va_start(args, fmt);
    len = vsnprintf(sbuf, sizeof(sbuf), fmt, args);
    va_end(args);

    if (len < 0) return 0;
    if (len < (int)sizeof(sbuf)) return conn_write(conn, sbuf, (size_t)len);
    char* hbuf = malloc((size_t)len + 1);
    if (!hbuf) {
        perror("conn_writef malloc");
        return 0;
    }

    va_start(args, fmt);
    vsnprintf(hbuf, (size_t)len + 1, fmt, args);
    va_end(args);
    int result = conn_write(conn, hbuf, (size_t)len);
    free(hbuf);

    return result;
}

void conn_abort(PulsarConn* conn) { conn->abort = true; }

void conn_send(PulsarConn* conn, http_status status, const void* data, size_t length) {
    conn_set_status(conn, status);
    conn_write(conn, data, length);
}

void conn_send_json(PulsarConn* conn, http_status status, const char* json, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: application/json\r\n", 32);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, json, length);
}

void conn_send_html(PulsarConn* conn, http_status status, const char* html, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: text/html\r\n", 25);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, html, length);
}

void conn_send_text(PulsarConn* conn, http_status status, const char* text, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: text/plain\r\n", 26);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, text, length);
}

void conn_send_xml(PulsarConn* conn, http_status status, const char* xml, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: application/xml\r\n", 31);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, xml, length);
}

void conn_send_javascript(PulsarConn* conn, http_status status, const char* javascript, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: application/javascript\r\n", 38);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, javascript, length);
}

void conn_send_css(PulsarConn* conn, http_status status, const char* css, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: text/css\r\n", 24);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, css, length);
}

void conn_send_redirect(PulsarConn* conn, const char* location, bool permanent) {
    conn_set_status(conn, permanent ? StatusMovedPermanently : StatusFound);
    response_t* resp = &conn->response;
    size_t loc_len = strlen(location);
    size_t needed = 10 + loc_len + 2;
    ensure_headers_capacity(conn->arena, resp, resp->headers_len + needed);

    char* dest = resp->headers_buf + resp->headers_len;
    memcpy(dest, "Location: ", 10);
    dest += 10;
    memcpy(dest, location, loc_len);
    dest += loc_len;
    *dest++ = '\r';
    *dest++ = '\n';
    resp->headers_len += (uint32_t)needed;
}

/* ================================================================
 * Fast 1-Second Preformatted Server + Date Header
 * ================================================================ */
static const char DAYS[7][5] = {"Sun,", "Mon,", "Tue,", "Wed,", "Fri,", "Sat,"};
static const char MONTHS[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

typedef struct __attribute__((aligned(64))) {
    char header_str[128];
    uint16_t header_len;
} PreformattedServerDate;

static PreformattedServerDate g_server_date_hdr;
static _Atomic time_t g_current_time = 0;

static void update_date_header(time_t t) {
    struct tm tm;
    gmtime_r(&t, &tm);

    char buf[128];
    int n =
        snprintf(buf, sizeof(buf),
                 "Server: " SERVER_NAME
                 "\r\n"
                 "Date: %s %02d %s %04d %02d:%02d:%02d GMT\r\n",
                 DAYS[tm.tm_wday], tm.tm_mday, MONTHS[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);

    if (n > 0) {
        memcpy(g_server_date_hdr.header_str, buf, (size_t)n);
        g_server_date_hdr.header_len = (uint16_t)n;
        atomic_store_explicit(&g_current_time, t, memory_order_relaxed);
    }
}

INLINE void write_server_headers(PulsarConn* conn) {
    conn_writeheader_raw(conn, g_server_date_hdr.header_str, g_server_date_hdr.header_len);
}

/* ================================================================
 * Streaming / Single-Write Helpers
 * ================================================================ */
INLINE ssize_t write_retry(int fd, const void* data, size_t len) {
    size_t total = 0;
    const char* ptr = (const char*)data;
    while (total < len) {
        ssize_t written = sys_write_direct(fd, ptr + total, len - total);
        if (written < 0) {
            if (written == -EAGAIN || written == -EWOULDBLOCK) {
                usleep(10);
                continue;
            }
            if (written == -EINTR) continue;
            return -1;
        }
        total += (size_t)written;
    }
    return (ssize_t)total;
}

INLINE ssize_t writev_retry(int fd, struct iovec* iov, int iovcnt) {
    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) total += iov[i].iov_len;
    size_t sent_total = 0;

    while (sent_total < total) {
        ssize_t n = sys_writev_direct(fd, iov, iovcnt);
        if (n < 0) {
            if (n == -EAGAIN || n == -EWOULDBLOCK) {
                usleep(10);
                continue;
            }
            if (n == -EINTR) continue;
            return -1;
        }
        sent_total += (size_t)n;
        if (sent_total == total) break;

        size_t rem = (size_t)n;
        while (iovcnt > 0 && rem >= iov[0].iov_len) {
            rem -= iov[0].iov_len;
            iov++;
            iovcnt--;
        }
        if (iovcnt > 0 && rem > 0) {
            iov[0].iov_base = (char*)iov[0].iov_base + rem;
            iov[0].iov_len -= rem;
        }
    }
    return (ssize_t)sent_total;
}

void conn_start_sse(PulsarConn* conn) {
    conn_set_status(conn, StatusOK);
    static const char SSE_HEADERS[] =
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n";
    conn_writeheader_raw(conn, SSE_HEADERS, sizeof(SSE_HEADERS) - 1);
    SET_CONTENT_TYPE(conn->response.flags);
    SET_CHUNKED_TRANSFER(conn->response.flags);
}

void conn_start_chunked_transfer(PulsarConn* conn, int max_age_seconds) {
    conn_set_status(conn, StatusOK);
    static const char TRANS_HEADERS[] =
        "Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n";
    conn_writef(conn, "Cache-Control: public, max-age=%d\r\n", max_age_seconds);
    conn_writeheader_raw(conn, TRANS_HEADERS, sizeof(TRANS_HEADERS) - 1);
    SET_CONTENT_TYPE(conn->response.flags);
    SET_CHUNKED_TRANSFER(conn->response.flags);
}

#define BATCH_SIZE 4096

ssize_t conn_write_chunk(PulsarConn* conn, const void* data, size_t size) {
    char chunk_buf[BATCH_SIZE] = {0};
    size_t pos = 0;

    if (!HAS_HEADERS_WRITTEN(conn->response.flags)) {
        write_server_headers(conn);
        ensure_headers_capacity(conn->arena, &conn->response, conn->response.headers_len + 2);
        memcpy(conn->response.headers_buf + conn->response.headers_len, "\r\n", 2);
        conn->response.headers_len += 2;

        struct iovec iov[2] = {
            {.iov_base = conn->response.status_buf, .iov_len = conn->response.status_len},
            {.iov_base = conn->response.headers_buf, .iov_len = conn->response.headers_len},
        };
        if (writev_retry(conn->client_fd, iov, 2) < 0) return -1;
        SET_HEADERS_WRITTEN(conn->response.flags);
    }

    if (size == 0) {
        static const char final_chunk[] = "0\r\n\r\n";
        return write_retry(conn->client_fd, final_chunk, sizeof(final_chunk) - 1);
    }

    int hlen = snprintf(chunk_buf, sizeof(chunk_buf), "%zx\r\n", size);
    if (hlen > 0) pos += (size_t)hlen;

    if (pos + size + 2 <= sizeof(chunk_buf)) {
        memcpy(chunk_buf + pos, data, size);
        pos += size;
        memcpy(chunk_buf + pos, "\r\n", 2);
        pos += 2;
        return write_retry(conn->client_fd, chunk_buf, pos);
    } else {
        struct iovec iov[3] = {
            {.iov_base = chunk_buf, .iov_len = pos},
            {.iov_base = (void*)data, .iov_len = size},
            {.iov_base = (void*)"\r\n", .iov_len = 2},
        };
        return writev_retry(conn->client_fd, iov, 3);
    }
}

void conn_send_event(PulsarConn* conn, const SSEvent* evt) {
    if (!HAS_HEADERS_WRITTEN(conn->response.flags)) {
        write_server_headers(conn);
        ensure_headers_capacity(conn->arena, &conn->response, conn->response.headers_len + 2);
        memcpy(conn->response.headers_buf + conn->response.headers_len, "\r\n", 2);
        conn->response.headers_len += 2;

        struct iovec iov[2] = {
            {.iov_base = conn->response.status_buf, .iov_len = conn->response.status_len},
            {.iov_base = conn->response.headers_buf, .iov_len = conn->response.headers_len},
        };
        writev_retry(conn->client_fd, iov, 2);
        SET_HEADERS_WRITTEN(conn->response.flags);
    }

    char batch[BATCH_SIZE] = {0};
    size_t bpos = 0;

#define FLUSH_IF_NEEDED(n)                         \
    do {                                           \
        if (bpos + (n) > BATCH_SIZE && bpos > 0) { \
            conn_write_chunk(conn, batch, bpos);   \
            bpos = 0;                              \
        }                                          \
    } while (0)

    if (ss_is_valid(evt->event)) {
        FLUSH_IF_NEEDED(evt->event.len + 8);
        bpos +=
            (size_t)snprintf(batch + bpos, BATCH_SIZE - bpos, "event: %.*s\n", (int)evt->event.len, evt->event.data);
    }

    const char* dp = evt->data.data;
    size_t drem = evt->data.len;
    while (drem > 0) {
        const char* le = memchr(dp, '\n', drem);
        size_t line_len = le ? (size_t)(le - dp) : drem;
        FLUSH_IF_NEEDED(line_len + 8);

        size_t max_line = BATCH_SIZE - bpos - 8;
        if (line_len > max_line) line_len = max_line;
        bpos += (size_t)snprintf(batch + bpos, BATCH_SIZE - bpos, "data: %.*s\n", (int)line_len, dp);
        dp += line_len;
        drem -= line_len;

        if (drem > 0 && *dp == '\n') {
            dp++;
            drem--;
        }
    }

    if (ss_is_valid(evt->id)) {
        FLUSH_IF_NEEDED(evt->id.len + 5);
        bpos += (size_t)snprintf(batch + bpos, BATCH_SIZE - bpos, "id: %.*s\n", (int)evt->id.len, evt->id.data);
    }

    FLUSH_IF_NEEDED(1);
    batch[bpos++] = '\n';
    if (bpos > 0) conn_write_chunk(conn, batch, bpos);
#undef FLUSH_IF_NEEDED
}

void conn_end_chunked_transfer(PulsarConn* conn) { conn_write_chunk(conn, NULL, 0); }
void conn_end_sse(PulsarConn* conn) { conn_write_chunk(conn, NULL, 0); }

bool conn_is_open(PulsarConn* conn) { return conn && conn->client_fd != -1 && !conn->closing; }
int conn_worker_id(PulsarConn* conn) { return conn ? conn->worker_id : 0; }

/* ================================================================
 * Range Request Helpers
 * ================================================================ */
#define MAX_RANGE_HDR 64
INLINE bool parse_range(StrSlice hdr, ssize_t* start, ssize_t* end, bool* has_end) {
    if (!ss_contains(hdr, SS_LIT("bytes="))) return false;
    if (hdr.len >= MAX_RANGE_HDR) return false;

    char buf[MAX_RANGE_HDR];
    memcpy(buf, hdr.data, hdr.len);
    buf[hdr.len] = '\0';
    if (sscanf(buf, "bytes=%ld-%ld", start, end) == 2) {
        *has_end = true;
        return true;
    }

    if (sscanf(buf, "bytes=%ld-", start) == 1) {
        *has_end = false;
        return true;
    }

    return false;
}

INLINE bool validate_range(bool has_end, ssize_t* start, ssize_t* end, off_t file_size) {
    if (!start || !end) return false;
    ssize_t sb = *start, eb = *end;
    ssize_t chunk = (4 * 1024 * 1024) - 1;

    if (!has_end && sb >= 0)
        eb = sb + chunk;
    else if (sb < 0) {
        sb = file_size + sb;
        eb = sb + chunk;
    } else if (eb < 0)
        eb = file_size + eb;

    if (eb >= file_size) eb = file_size - 1;
    /* Start past EOF (or an inverted/empty range) is unsatisfiable: without
     * this, bytes=99999999- validated true with start > end and produced a
     * 206 claiming a bogus Content-Range with zero body bytes. */
    if (sb < 0 || eb < 0 || sb >= file_size || sb > eb) return false;
    *start = sb;
    *end = eb;
    return true;
}

INLINE void send_range_headers(PulsarConn* conn, ssize_t start, ssize_t end, off_t file_size) {
    static const char hfmt[] =
        "Accept-Ranges: bytes\r\n"
        "Content-Length: %ld\r\n"
        "Content-Range: bytes %ld-%ld/%lld\r\n";
    response_t* resp = &conn->response;
    ensure_headers_capacity(conn->arena, &conn->response, sizeof(hfmt) - 1 + 32);
    size_t n = (size_t)snprintf(resp->headers_buf + resp->headers_len, sizeof(hfmt) + 31, hfmt, end - start + 1, start,
                                end, (long long)file_size);
    resp->headers_len += (uint32_t)n;
}

bool conn_servefile(PulsarConn* conn, const char* filename) {
    if (!filename) return false;
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return false;
    }

    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        perror("fstat");
        sys_close_direct(fd);
        return false;
    }

    if (sb.st_size < 0 || (uint64_t)sb.st_size > UINT32_MAX) {
        fprintf(stderr, "file too large for 32-bit file_size\n");
        sys_close_direct(fd);
        return false;
    }

    /* gmtime() is process-global state: 4 workers would race on it.
     * Use the reentrant variant with a per-call buffer. */
    char tbuf[64];
    struct tm tm_buf;
    if (gmtime_r(&sb.st_mtime, &tm_buf) != NULL) {
        strftime(tbuf, sizeof(tbuf), "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);
        conn_writeheader(conn, SS_LIT("Last-Modified"), ss_from_cstr(tbuf));
    }

    if (!HAS_CONTENT_TYPE(conn->response.flags)) {
        conn_set_content_type(conn, get_mimetype((char*)filename));
    }

    conn->response.file_fd = fd;
    conn->response.file_size = (uint32_t)sb.st_size;
    conn->response.file_offset = 0;
    conn->response.range_end = (uint32_t)sb.st_size;

    /* Range value was captured during header parsing (parse_request_headers)
     * as a view into read_buf; no headers_t lookup needed. */
    StrSlice range_hdr = conn->request.range_hdr;
    if (range_hdr.data == NULL) return true;

    ssize_t s = 0, e = 0;
    bool has_end;
    if (parse_range(range_hdr, &s, &e, &has_end)) {
        if (!validate_range(has_end, &s, &e, sb.st_size)) {
            /* 416 is a complete response (status only): clear file_fd so the
             * stale (now closed) descriptor isn't treated as a send, and
             * return true so the caller doesn't stomp 416 with its 500
             * fallback. finalize builds Content-Length: 0 + date headers. */
            sys_close_direct(fd);
            conn->response.file_fd = -1;
            conn_set_status(conn, StatusRequestedRangeNotSatisfiable);
            return true;
        }
        conn_set_status(conn, StatusPartialContent);
        send_range_headers(conn, s, e, sb.st_size);
        conn->response.file_offset = s;
        conn->response.range_end = (uint32_t)(e + 1); /* e <= size-1 so no overflow */
        SET_RANGE_REQUEST(conn->response.flags);
    }
    return true;
}

/* ================================================================
 * Highly Optimized Finalize Response
 * ================================================================ */
#define CRLF_WORD 0x0A0D /* "\r\n" in little-endian (uint16_t) */

__attribute__((no_stack_protector)) static void finalize_response(PulsarConn* conn, HttpMethod method) {
    response_t* resp = &conn->response;

    if (unlikely(resp->status_len == 0)) {
        /* Default 200 OK. Must populate status_buf as well: the file-serve
         * path in handle_write copies status_buf verbatim, and handlers such
         * as static_file_handler never call conn_set_status. Without this the
         * server shipped status_len NUL bytes as the status line. */
        resp->status_code = StatusOK;
        *(uint64_t*)(resp->status_buf + 0) = UINT64_C(0x312e312f50545448); /* "HTTP/1.1" */
        *(uint64_t*)(resp->status_buf + 8) = UINT64_C(0x0d4b4f2030303220); /* " 200 OK\r" */
        resp->status_buf[16] = '\n';
        resp->status_len = 17;
    }

    if (likely(resp->file_fd < 0 && !HAS_HEAP_ALLOCATED(resp->flags))) {
        size_t s_len = resp->status_len;
        size_t user_h_len = resp->headers_len;
        size_t b_len = resp->body_len;
        size_t date_len = g_server_date_hdr.header_len;

        /* Single safe upper-bound capacity check: avoid precomputing count_digits */
        if (likely(s_len + user_h_len + date_len + b_len + 64 <= resp->out_cap)) {
            char* dst = resp->out_buf;

            /* 1. Fast SWAR Status Line Copy */
            if (likely(s_len == 17 && resp->status_code == StatusOK)) {
                *(uint64_t*)(dst + 0) = UINT64_C(0x312e312f50545448); /* "HTTP/1.1" */
                *(uint64_t*)(dst + 8) = UINT64_C(0x0d4b4f2030303220); /* " 200 OK\r" */
                *(dst + 16) = '\n';
                dst += 17;
            } else {
                __builtin_memcpy(dst, resp->status_buf, s_len);
                dst += s_len;
            }

            /* 2. User Headers */
            if (user_h_len > 0) {
                __builtin_memcpy(dst, resp->headers_buf, user_h_len);
                dst += user_h_len;
            }

            /* 3. Direct Content-Length formatting */
            if (!HAS_RANGE_REQUEST(resp->flags)) {
                size_t cl = (method != HTTP_OPTIONS) ? b_len : 0;
                *(uint64_t*)(dst + 0) = UINT64_C(0x2d746e65746e6f43); /* "Content-" */
                *(uint64_t*)(dst + 8) = UINT64_C(0x203a6874676e654c); /* "Length: " */
                size_t digits = pulsar_itoa((uint64_t)cl, dst + 16);
                *(uint16_t*)(dst + 16 + digits) = CRLF_WORD;
                dst += 18 + digits;
            }

            /* 4. Vectorized Server + Date Copy */
#if defined(__AVX2__)
            __m256i s0 = _mm256_load_si256((const __m256i*)(g_server_date_hdr.header_str + 0));
            __m256i s1 = _mm256_load_si256((const __m256i*)(g_server_date_hdr.header_str + 32));
            _mm256_storeu_si256((__m256i*)(dst + 0), s0);
            _mm256_storeu_si256((__m256i*)(dst + 32), s1);
            if (date_len > 64) {
                __builtin_memcpy(dst + 64, g_server_date_hdr.header_str + 64, date_len - 64);
            }
            dst += date_len;
#else
            __builtin_memcpy(dst, g_server_date_hdr.header_str, date_len);
            dst += date_len;
#endif

            /* 5. Trailing CRLF */
            *(uint16_t*)dst = CRLF_WORD;
            dst += 2;

            /* 6. Body */
            if (b_len > 0) {
                __builtin_memcpy(dst, resp->body.stack, b_len);
                dst += b_len;
            }

            resp->out_len = (uint32_t)(dst - resp->out_buf);
            resp->out_sent = 0;
            return;
        }
    }

    /* Fallback for file responses or heap-allocated bodies */
    if (!HAS_RANGE_REQUEST(resp->flags)) {
        size_t cl =
            (method != HTTP_OPTIONS) ? ((resp->file_fd >= 0) ? (size_t)resp->file_size : (size_t)resp->body_len) : 0;

        char cl_buf[38];
        *(uint64_t*)(cl_buf + 0) = UINT64_C(0x2d746e65746e6f43);
        *(uint64_t*)(cl_buf + 8) = UINT64_C(0x203a6874676e654c);
        size_t digits = pulsar_itoa((uint64_t)cl, cl_buf + 16);
        size_t cl_len = 16 + digits;
        *(uint16_t*)(cl_buf + cl_len) = CRLF_WORD;
        cl_len += 2;
        conn_writeheader_raw(conn, cl_buf, cl_len);
    }

    write_server_headers(conn);

    size_t h_len = resp->headers_len;
    ensure_headers_capacity(conn->arena, resp, h_len + 2);
    *(uint16_t*)(resp->headers_buf + h_len) = CRLF_WORD;
    resp->headers_len = (uint32_t)(h_len + 2);
}

/* ================================================================
 * Static File Handler
 * ================================================================ */
void static_file_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    route_t* route = conn->request.route;
    ASSERT(route->route_type == ROUTE_TYPE_STATIC);

    const char* path = conn->request.path;
    const char* dirname = route->state.static_.dirname;
    const char* pattern = route->pattern;
    size_t dirlen = route->state.static_.dirname_len;
    size_t pattern_len = route->pattern_len;

    if (is_malicious_path(path)) {
        conn_notfound(conn);
        return;
    }

    const char* static_ptr = path + pattern_len;
    if (strcmp(pattern, "/") != 0 && *static_ptr == '/') {
        static_ptr++;
    }
    size_t static_len = strlen(static_ptr);

    if (dirlen >= PATH_MAX || static_len >= PATH_MAX || dirlen + static_len + 2 >= PATH_MAX) {
        conn_set_status(conn, StatusRequestURITooLong);
        conn_set_content_type(conn, SS_LIT("text/html"));
        conn_write_string(conn, "<h1>Path too long</h1>");
        return;
    }

    char filepath[PATH_MAX];
    char decoded[PATH_MAX];
    char index_file[PATH_MAX];

    bool needs_slash = dirlen > 0 && dirname[dirlen - 1] != '/';
    int plen = snprintf(filepath, sizeof(filepath), "%.*s%s%.*s", (int)dirlen, dirname, needs_slash ? "/" : "",
                        (int)static_len, static_ptr);
    if (plen < 0 || plen >= (int)sizeof(filepath)) {
        conn_set_status(conn, StatusInternalServerError);
        return;
    }

    if (memchr(filepath, '%', (size_t)plen) || memchr(filepath, '+', (size_t)plen)) {
        url_percent_decode(filepath, decoded, (size_t)plen, sizeof(decoded));
        memcpy(filepath, decoded, (size_t)plen + 1);
    }

    /*
     * Resolve the target: prefer the path as-is; fall back to
     * appending "/index.html" for directory requests.
     */
    bool use_index = false;
    const char* serve_file = filepath;

    if (!is_file(filepath)) {
        int ilen =
            snprintf(index_file, sizeof(index_file), "%s%sindex.html", filepath, filepath[plen - 1] != '/' ? "/" : "");
        if (ilen < 0 || ilen >= (int)sizeof(index_file) || !is_file(index_file)) {
            conn_notfound(conn);
            return;
        }
        use_index = true;
        serve_file = index_file;
    }

    StrSlice content_type = use_index ? SS_LIT("text/html") : get_mimetype(filepath);
    conn_set_content_type(conn, content_type);

    if (!conn_servefile(conn, serve_file)) {
        conn_set_status(conn, StatusInternalServerError);
        conn_set_content_type(conn, SS_LIT("text/html"));
        conn_write_string(conn, "<h1>Error serving file</h1>");
    }
}

const char* get_path_param(PulsarConn* conn, const char* name) {
    if (!conn || !name) return NULL;
    route_t* route = conn->request.route;
    if (route && route->route_type == ROUTE_TYPE_PARAM) {
        PathParams* pp = route->state.path_params;
        if (!pp) return NULL;
        const size_t name_len = strlen(name);
        for (size_t i = 0; i < pp->match_count; i++) {
            const PathParam* p = &pp->items[i];
            if (p->name_len == name_len && memcmp(p->name, name, name_len) == 0) return p->value;
        }
    }
    return NULL;
}

INLINE void execute_all_middleware(PulsarCtx* ctx, route_t* route) {
    if (likely((global_mw_count | route->mw_count) == 0)) {
        return;
    }
    for (size_t i = 0; i < global_mw_count; i++) {
        global_middleware[i](ctx);
        if (ctx->conn->abort) return;
    }
    for (size_t i = 0; i < route->mw_count; i++) {
        route->middleware[i](ctx);
        if (ctx->conn->abort) return;
    }
}

void use_global_middleware(HttpHandler* mw, size_t count) {
    if (!count) return;
    ASSERT(count + global_mw_count <= MAX_GLOBAL_MIDDLEWARE);
    for (size_t i = 0; i < count; i++) global_middleware[global_mw_count++] = mw[i];
}

void use_route_middleware(route_t* route, HttpHandler* mw, size_t count) {
    if (!count) return;
    ASSERT(route->mw_count + count <= MAX_ROUTE_MIDDLEWARE);
    for (size_t i = 0; i < count; i++) route->middleware[route->mw_count++] = mw[i];
}

void pulsar_set_handler_userdata(void* userdata) { GLOBAL_HANDLER_USERDATA = userdata; }
void* pulsar_get_handler_userdata(void) { return GLOBAL_HANDLER_USERDATA; }

Request conn_get_request_metadata(PulsarConn* conn) {
    return (Request){
        .path = conn->request.path,
        .method = conn->request.method,
        .body = (StrSlice){.data = conn->request.body, .len = conn->request.content_length},
        .route_pattern = conn->request.route->pattern,
    };
}

static PlogState PLOG_STATE = {0};
int LOG_FD = -1;
PulsarCallback LOGGER_CALLBACK = NULL;

bool pulsar_set_callback(PulsarCallback cb, int fd) {
#if ENABLE_LOGGING
    if ((LOGGER_CALLBACK && cb) || (LOG_FD != -1 && fd != -1)) {
        LOG_ERROR("Cannot set logger callback: already set");
        return false;
    }
    LOGGER_CALLBACK = cb;
    LOG_FD = fd;
    return plog_init(&PLOG_STATE, LOG_FD);
#else
    LOGGER_CALLBACK = NULL;
    LOG_FD = -1;
    UNUSED(cb);
    UNUSED(fd);
    return true;
#endif
}

__attribute__((destructor)) void cleanup_logger() {
#if ENABLE_LOGGING
    if (LOG_FD != -1) {
        int drop = plog_drop_count(&PLOG_STATE);
        if (drop > 0) {
            fprintf(stderr,
                    "Dropped %d log entries due to full queue. Consider increasing "
                    "PLOG_RING_CAPACITY "
                    "or ensuring the logger keeps up with the request rate.\n",
                    drop);
        }
        plog_destroy(&PLOG_STATE);
        LOG_FD = -1;
    }
#endif
}

void pulsar_logger(PulsarCtx* ctx, uint64_t total_ns) {
    PulsarConn* conn = ctx->conn;
    const char* method = req_method(conn);
    const char* path = req_path(conn);
    http_status status_code = res_get_status(conn);
    const char* user_agent = req_header_get(conn, "User-Agent");
    if (!user_agent) {
        user_agent = "-";
    }

    char latency_str[24];
    if (total_ns < 1000) {
        snprintf(latency_str, sizeof(latency_str), "%3" PRIu64 "ns", total_ns);
    } else if (total_ns < 1000000) {
        snprintf(latency_str, sizeof(latency_str), "%5" PRIu64 "µs", total_ns / 1000);
    } else if (total_ns < 1000000000) {
        snprintf(latency_str, sizeof(latency_str), "%5" PRIu64 "ms", total_ns / 1000000);
    } else if (total_ns < UINT64_C(60000000000)) {
        snprintf(latency_str, sizeof(latency_str), "%5" PRIu64 "s", total_ns / 1000000000);
    } else {
        snprintf(latency_str, sizeof(latency_str), "%5" PRIu64 "m", total_ns / UINT64_C(60000000000));
    }
    char line[PLOG_LINE_MAX];
    int n = snprintf(line, sizeof(line), "[Pulsar] %-7s %-5s %3d %8s %s\n", method, path, (int)status_code, latency_str,
                     user_agent);
    if (n > 0 && n < (int)sizeof(line)) {
        plog_submit(&PLOG_STATE, line, (uint32_t)n);
    }
}

bool pulsar_set(PulsarConn* conn, const char* k, void* v, ValueFreeFunc ff) {
    return LocalsSetValue(&conn->locals, k, v, ff);
}

Arena* pulsar_get_arena(PulsarConn* conn) { return conn->arena; }
void* pulsar_alloc(PulsarConn* conn, size_t sz) { return arena_alloc(conn->arena, sz); }
void* pulsar_get(PulsarConn* conn, const char* k) { return LocalsGetValue(&conn->locals, k); }
void pulsar_delete(PulsarConn* conn, const char* k) { LocalsRemove(&conn->locals, k); }

INLINE void request_complete(PulsarConn* conn) {
#if ENABLE_LOGGING
    if (LOGGER_CALLBACK) {
        struct timespec end;
        clock_gettime(CLOCK_MONOTONIC, &end);
        uint64_t s_ns = (uint64_t)conn->start.tv_sec * 1000000000ULL + (uint64_t)conn->start.tv_nsec;
        uint64_t e_ns = (uint64_t)end.tv_sec * 1000000000ULL + (uint64_t)end.tv_nsec;
        PulsarCtx ctx = {.conn = conn, .userdata = GLOBAL_HANDLER_USERDATA};
        LOGGER_CALLBACK(&ctx, e_ns - s_ns);
    }
#endif
    UNUSED(conn);
}

/* ================================================================
 * HTTP Request Line Parser
 * ================================================================ */
INLINE int parse_request_line(const char* input, size_t input_len, request_t* req, const char** url_ptr,
                              size_t* url_len, const char** line_end) {
    if (unlikely(input_len < 14)) return -1;
    const char* ptr = input;

    uint32_t m4;
    memcpy(&m4, ptr, 4);
    if (m4 == UINT32_C(0x20544547)) { /* "GET " */
        req->method_type = HTTP_GET;
        *(uint32_t*)req->method = UINT32_C(0x00544547); /* "GET\0" */
        ptr += 4;
    } else if (m4 == UINT32_C(0x54534F50) && ptr[4] == ' ') { /* "POST " */
        req->method_type = HTTP_POST;
        memcpy(req->method, "POST", 5);
        ptr += 5;
    } else if (m4 == UINT32_C(0x44414548) && ptr[4] == ' ') { /* "HEAD " */
        req->method_type = HTTP_HEAD;
        memcpy(req->method, "HEAD", 5);
        ptr += 5;
    } else if (m4 == UINT32_C(0x20545550)) { /* "PUT " */
        req->method_type = HTTP_PUT;
        *(uint32_t*)req->method = UINT32_C(0x00545550); /* "PUT\0" */
        ptr += 4;
    } else {
        const char* sp = memchr(ptr, ' ', 8);
        if (!sp) return -1;
        size_t mlen = (size_t)(sp - ptr);
        if (mlen >= sizeof(req->method)) return -1;
        memcpy(req->method, ptr, mlen);
        req->method[mlen] = '\0';
        req->method_type = http_method_from_string(req->method, mlen);
        ptr = sp + 1;
    }

    const char* sp = memchr(ptr, ' ', input_len - (size_t)(ptr - input));
    if (unlikely(!sp)) return -1;
    *url_ptr = ptr;
    *url_len = (size_t)(sp - ptr);

    const char* proto = sp + 1;
    if (unlikely(input_len < (size_t)(proto - input) + 10)) return -1;

    uint64_t h1;
    uint16_t h2;
    memcpy(&h1, proto, 8);
    memcpy(&h2, proto + 8, 2);

    if (unlikely(h1 != UINT64_C(0x312E312F50545448) || h2 != UINT16_C(0x0A0D))) {
        return -1;
    }

    *line_end = proto + 10; /* past "HTTP/1.1\r\n": headers start here */
    return 0;
}

INLINE size_t decode_path_fast(const char* url, size_t url_len, char* dest, size_t dest_cap) {
    if (url_len >= dest_cap) url_len = dest_cap - 1;
    /* Single pass for '%' or '+': two memchr() calls cost two libc round-trips
     * over these (usually tiny) URLs. The loop below short-circuits on the
     * first escape char and the memcpy covers the common no-escape case. */
    size_t i = 0;
    for (; i < url_len; i++) {
        const char c = url[i];
        if (c == '%' || c == '+') break;
    }
    if (i == url_len) {
        memcpy(dest, url, url_len);
        dest[url_len] = '\0';
        return url_len;
    }
    return url_percent_decode(url, dest, url_len, dest_cap);
}

/* ================================================================
 * Core Request Processor
 * ================================================================ */
INLINE http_status process_request(PulsarConn* conn, const char* buf, size_t read_bytes, const char* end_of_headers,
                                   size_t* consumed, KeepAliveState* state, event_queue_t* queue) {
    *consumed = 0;
    if (!end_of_headers) return StatusBadRequest;

    request_t* req = &conn->request;
    size_t headers_len = (size_t)(end_of_headers - buf) + 4;

    const char* url_ptr = NULL;
    size_t url_len = 0;
    const char* line_end = NULL;

    if (parse_request_line(buf, read_bytes, req, &url_ptr, &url_len, &line_end) != 0) {
        return StatusBadRequest;
    }

    size_t path_len = decode_path_fast(url_ptr, url_len, req->path, MAX_PATH_LEN);

    if (!parse_query_params(conn, &path_len)) return StatusInternalServerError;
    /* Start header scan past the request line: the old code re-scanned it as a
     * giant pseudo-header (2 wasted memchrs per request). */
    const size_t hdr_off = (size_t)(line_end - buf);
    if (!parse_request_headers(conn, line_end, req->method_type, headers_len - hdr_off))
        return StatusInternalServerError;

    *consumed = headers_len + req->content_length;

    route_t* route = route_match(req->path, path_len, req->method_type, conn->arena);
    if (!route) return StatusNotFound;

    req->route = route;
    http_status status = parse_request_body(conn, buf, headers_len, read_bytes);
    if (status != StatusOK) return status;

    PulsarCtx ctx = {.conn = conn, .userdata = GLOBAL_HANDLER_USERDATA};
    execute_all_middleware(&ctx, route);
    if (!conn->abort) route->handler(&ctx);

    if (conn->offloaded) return StatusOK;

    if (HAS_CHUNKED_TRANSFER(conn->response.flags)) {
        request_complete(conn);
        if (conn->keep_alive) {
            AddKeepAliveConnection(conn, state);
            conn->closing = true;
            if (reset_connection(conn)) conn->closing = (event_mod_read(queue, conn->client_fd, conn) < 0);
        }
    } else {
        finalize_response(conn, req->method_type);
    }
    return StatusOK;
}

/* ================================================================
 * Socket Setup
 * ================================================================ */
INLINE void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        exit(EXIT_FAILURE);
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
        perror("fcntl F_SETFL");
        exit(EXIT_FAILURE);
    }
}

static int create_server_socket(const char* host, int port, int worker_cpu_id) {
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port: %d\n", port);
        exit(EXIT_FAILURE);
    }

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
    };
    struct addrinfo *result, *rp;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        exit(EXIT_FAILURE);
    }

    int fd = -1, opt = 1;
    for (rp = result; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) continue;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
            sys_close_direct(fd);
            continue;
        }
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        sys_close_direct(fd);
        fd = -1;
    }
    freeaddrinfo(result);

    if (fd == -1) {
        fprintf(stderr, "Could not bind to %s:%d\n", host ? host : "*", port);
        exit(EXIT_FAILURE);
    }

    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
    int rcv = 256 * 1024, snd = 256 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));

#ifdef __linux__
    int defer = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer, sizeof(defer));

#ifdef SO_INCOMING_CPU
    if (worker_cpu_id >= 0) {
        setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, &worker_cpu_id, sizeof(worker_cpu_id));
    }
#endif
#endif

    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
        sys_close_direct(fd);
        exit(EXIT_FAILURE);
    }
    return fd;
}

INLINE int conn_accept(int listen_fd) {
    (void)listen_fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    int client_fd = raw_accept4(listen_fd, (struct sockaddr*)&addr, &addr_len, SOCK_NONBLOCK);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) perror("accept");
        return -1;
    }

#ifndef __linux__
    set_nonblocking(client_fd);
#endif

    struct timeval tv = {.tv_sec = 30, .tv_usec = 0};
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int yes = 1;
#ifdef __linux__
    setsockopt(client_fd, IPPROTO_TCP, TCP_QUICKACK, &yes, sizeof(yes));
    unsigned int uto = 60000;
    setsockopt(client_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &uto, sizeof(uto));
    int ka_idle = 120, ka_intvl = 15, ka_cnt = 3;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &ka_idle, sizeof(ka_idle));
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, &ka_intvl, sizeof(ka_intvl));
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT, &ka_cnt, sizeof(ka_cnt));
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
    setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
    setsockopt(client_fd, IPPROTO_TCP, TCP_NOPUSH, &yes, sizeof(yes));
#ifdef TCP_KEEPIDLE
    int ka_idle = 120;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &ka_idle, sizeof(ka_idle));
#endif
#ifdef TCP_KEEPINTVL
    int ka_iv = 15;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, &ka_iv, sizeof(ka_iv));
#endif
#ifdef TCP_KEEPCNT
    int ka_cnt = 3;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT, &ka_cnt, sizeof(ka_cnt));
#endif
#endif

    return client_fd;
}

static void add_connection_to_worker(event_queue_t* queue, int client_fd, int worker_id, KeepAliveState* ka_state) {
    Arena* arena = arena_create(1 << 20);
    if (!arena) {
        fprintf(stderr, "add_connection_to_worker->arena_create failed\n");
        sys_close_direct(client_fd);
        return;
    }

    /* Allocate PulsarConn + dedicated permanent buffers in one contiguous block */
    size_t out_cap = STATUS_LINE_SIZE + HEADERS_DEFAULT_CAPACITY + STACK_BUFFER_SIZE;
    size_t total_alloc = sizeof(PulsarConn) + READ_BUFFER_SIZE + PATH_MAX + sizeof(headers_t) +
                         HEADERS_DEFAULT_CAPACITY + STATUS_LINE_SIZE + out_cap;

    PulsarConn* conn = calloc(1, total_alloc);
    if (!conn) {
        fprintf(stderr, "add_connection_to_worker calloc failed\n");
        sys_close_direct(client_fd);
        arena_destroy(arena);
        return;
    }

    char* ptr = (char*)conn + sizeof(PulsarConn);
    conn->read_buf = ptr;
    ptr += READ_BUFFER_SIZE;
    conn->request.path = ptr;
    ptr += PATH_MAX;
    conn->request.headers = (headers_t*)ptr;
    ptr += sizeof(headers_t);
    conn->response.headers_buf = ptr;
    ptr += HEADERS_DEFAULT_CAPACITY;
    conn->response.status_buf = ptr;
    ptr += STATUS_LINE_SIZE;
    conn->response.out_buf = ptr;
    conn->response.out_cap = (uint32_t)out_cap;

    if (!init_connection(conn, arena, client_fd, worker_id)) {
        fprintf(stderr, "init_connection failed\n");
        sys_close_direct(client_fd);
        LocalsClear(&conn->locals);
        arena_destroy(arena);
        free(conn);
        return;
    }

    conn->owner_queue = queue;
    conn->owner_ka_state = ka_state;
    conn->offloaded = false;

    if (event_add_read(queue, client_fd, conn) < 0) {
        perror("event_add_read");
        sys_close_direct(client_fd);
        conn->client_fd = -1;
        free_response_body(&conn->response);
        LocalsClear(&conn->locals);
        arena_destroy(arena);
        free(conn);
    }
}

static void handle_read(event_queue_t* queue, PulsarConn* conn, KeepAliveState* state) {
#if ENABLE_LOGGING
    if (LOGGER_CALLBACK) {
        clock_gettime(CLOCK_MONOTONIC, &conn->start);
    }
#endif

    ssize_t bytes_read =
        sys_read_direct(conn->client_fd, conn->read_buf + conn->pending_len, READ_BUFFER_SIZE - 1 - conn->pending_len);
    if (bytes_read < 0 && (bytes_read == -EAGAIN || bytes_read == -EWOULDBLOCK)) return;
    if (bytes_read <= 0) {
        conn->closing = true;
        return;
    }

    size_t total = conn->pending_len + (size_t)bytes_read;
    conn->read_buf[total] = '\0';

    const char* buf = conn->read_buf;

    const char* end_of_headers = find_headers_end(buf, total);
    if (!end_of_headers) {
        // Headers not complete yet. If the buffer is full and we still
        // don't have a full header block, the request is too large.
        if (total == (size_t)(READ_BUFFER_SIZE - 1)) {
            conn->closing = true;
            return;
        }
        conn->pending_len = total;
        return;
    }

    size_t consumed = 0;
    http_status status = process_request(conn, buf, total, end_of_headers, &consumed, state, queue);
    if (status != StatusOK) {
        write_error(conn, status);
    }

    if (conn->offloaded) return;

    handle_write(queue, conn, state);
    if (conn->closing) return;

    if (consumed < total) {
        memmove(conn->read_buf, conn->read_buf + consumed, total - consumed);
        conn->pending_len = total - consumed;
    } else {
        conn->pending_len = 0;
    }
}

/* ================================================================
 * Single-Syscall handle_write (Supports write & writev)
 * ================================================================ */
static void handle_write(event_queue_t* queue, PulsarConn* conn, KeepAliveState* state) {
    response_t* res = &conn->response;
    int client_fd = conn->client_fd;
    const bool sending_file = res->file_fd > 0 && res->file_size > 0;
    ssize_t sent = -1;

    for (;;) {
        sent = 0;
        bool complete = false;

        if (sending_file) {
            if (!HAS_HEADERS_WRITTEN(res->flags)) {
                if (res->out_len == 0) {
                    size_t hdr_total = (size_t)res->status_len + (size_t)res->headers_len;
                    if (hdr_total <= res->out_cap) {
                        __builtin_memcpy(res->out_buf, res->status_buf, res->status_len);
                        __builtin_memcpy(res->out_buf + res->status_len, res->headers_buf, res->headers_len);
                        res->out_len = (uint32_t)hdr_total;
                        res->out_sent = 0;
                    }
                }
                sent = sys_write_direct(client_fd, res->out_buf + res->out_sent, res->out_len - res->out_sent);
                if (unlikely(sent < 0)) goto handle_error;
                if (unlikely(sent == 0)) return;

                res->out_sent += (uint32_t)sent;
                if (res->out_sent == res->out_len) {
                    SET_HEADERS_WRITTEN(res->flags);
                }
                continue;
            }

            /* Range sends stop at range_end (e+1); plain sends run to EOF.
             * range_end is always initialized in conn_servefile, so a stale
             * flag can at worst truncate, never over-send or loop. */
            const off_t send_end = HAS_RANGE_REQUEST(res->flags) ? (off_t)res->range_end : (off_t)res->file_size;
            off_t rem = send_end - res->file_offset;
            if (rem <= 0) {
                complete = true;
            } else {
                off_t chunk = HAS_RANGE_REQUEST(res->flags) ? (off_t)MIN(1 << 20, (size_t)rem) : rem;

                sent = file_sendfile(client_fd, res->file_fd, &res->file_offset, (size_t)chunk);
                if (sent == -1 && errno == EAGAIN) {
                    sent = 0;
                }
                if (unlikely(sent < 0)) {
                    sent = -errno;
                    goto handle_error;
                }
                if (sent == 0) {
                    /* Socket buffer full (file bigger than sndbuf): re-arm for
                     * writability exactly like handle_error does. A bare
                     * return here leaks the connection: the fd is only armed
                     * for READ, so no write event would ever resume the
                     * transfer and the request hung until keep-alive timeout. */
                    SET_WRITE_PENDING(res->flags);
                    if (event_mod_write(queue, conn->client_fd, conn) < 0) {
                        sys_close_direct(res->file_fd);
                        res->file_fd = -1;
                        conn->closing = true;
                    }
                    return;
                }
                complete = (res->file_offset >= send_end);
            }
        } else if (likely(!HAS_HEAP_ALLOCATED(res->flags) && res->out_len > 0)) {
            /* Fast Path: 1 Single sys_write_direct for pre-formatted contiguous buffer */
            sent = sys_write_direct(client_fd, res->out_buf + res->out_sent, res->out_len - res->out_sent);
            if (unlikely(sent < 0)) goto handle_error;
            if (sent == 0) return;

            res->out_sent += (uint32_t)sent;
            complete = (res->out_sent == res->out_len);
        } else {
            /* 1 Single sys_writev_direct for Split Header + Heap Body */
            if (res->out_len == 0) {
                size_t hdr_total = (size_t)res->status_len + (size_t)res->headers_len;
                if (hdr_total <= res->out_cap) {
                    __builtin_memcpy(res->out_buf, res->status_buf, res->status_len);
                    __builtin_memcpy(res->out_buf + res->status_len, res->headers_buf, res->headers_len);
                    res->out_len = (uint32_t)hdr_total;
                    res->out_sent = 0;
                }
            }

            struct iovec iov[2];
            int iovcnt = 0;

            if (res->out_sent < res->out_len) {
                iov[iovcnt].iov_base = res->out_buf + res->out_sent;
                iov[iovcnt].iov_len = res->out_len - res->out_sent;
                iovcnt++;
            }
            if (res->body_sent < res->body_len) {
                iov[iovcnt].iov_base = (char*)res->body.heap + res->body_sent;
                iov[iovcnt].iov_len = res->body_len - res->body_sent;
                iovcnt++;
            }

            if (iovcnt == 1) {
                sent = sys_write_direct(client_fd, iov[0].iov_base, iov[0].iov_len);
            } else if (iovcnt > 1) {
                sent = sys_writev_direct(client_fd, iov, iovcnt);
            } else {
                complete = true;
            }

            if (unlikely(sent < 0)) goto handle_error;
            if (sent == 0 && !complete) return;

            size_t rem = (size_t)sent;
            if (res->out_sent < res->out_len) {
                size_t h_rem = (size_t)res->out_len - (size_t)res->out_sent;
                if (rem < h_rem) {
                    res->out_sent += (uint32_t)rem;
                    rem = 0;
                } else {
                    res->out_sent = res->out_len;
                    rem -= h_rem;
                    SET_HEADERS_WRITTEN(res->flags);
                }
            }
            if (rem > 0 && res->body_sent < res->body_len) {
                res->body_sent += (uint32_t)rem;
            }
            complete = (res->out_sent == res->out_len && res->body_sent == res->body_len);
        }

        if (complete) {
            request_complete(conn);
            if (sending_file) {
                sys_close_direct(res->file_fd);
                res->file_fd = -1;
            }

            const bool was_pending = HAS_WRITE_PENDING(res->flags);
            CLR_WRITE_PENDING(res->flags);

            if (conn->keep_alive) {
                AddKeepAliveConnection(conn, state);
                if (reset_connection(conn)) {
                    if (was_pending) {
                        if (event_mod_read(queue, conn->client_fd, conn) < 0) {
                            conn->closing = true;
                        }
                    }
                } else {
                    conn->closing = true;
                }
            } else {
                conn->closing = true;
            }
            return;
        }
    }

handle_error:
    if (sent == -EAGAIN || sent == -EWOULDBLOCK) {
        SET_WRITE_PENDING(res->flags);
        if (event_mod_write(queue, conn->client_fd, conn) < 0) {
            if (sending_file) {
                sys_close_direct(res->file_fd);
                res->file_fd = -1;
            }
            conn->closing = true;
        }
        return;
    }

    if (sending_file) {
        sys_close_direct(res->file_fd);
        res->file_fd = -1;
    }
    conn->closing = true;
    request_complete(conn);
}

/* ================================================================
 * Worker Thread
 * ================================================================ */
typedef struct {
    event_queue_t* queue;
    int id;
    int listen_fd;
    KeepAliveState* keep_alive_state;
} WorkerData;

void* worker_thread(void* arg) {
    WorkerData* worker = (WorkerData*)arg;
    event_queue_t* queue = worker->queue;
    int worker_id = worker->id;
    int listen_fd = worker->listen_fd;
    KeepAliveState* ka_state = worker->keep_alive_state;

    if (event_add_server(queue, listen_fd) < 0) {
        perror("event_add_server");
        return NULL;
    }

    event_t events[MAX_EVENTS] = {0};
    long last_timeout_check = 0;
    int loop_counter = 0;
    time_t last_sync_time = 0;

    while (server_running) {
        int n = event_wait(queue, events, MAX_EVENTS, 500);
        if (n == -1) {
            if (errno == EINTR) continue;
            perror("event_wait");
            continue;
        }

        /* Amortized date update check: avoid time() syscall storm */
        loop_counter++;
        if (n == 0 || loop_counter >= 128) {
            time_t now_sec = time(NULL);
            if (now_sec != last_sync_time) {
                last_sync_time = now_sec;
                if (now_sec != atomic_load_explicit(&g_current_time, memory_order_relaxed)) {
                    update_date_header(now_sec);
                }
            }

            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - last_timeout_check >= 5) {
                CheckKeepAliveTimeouts(ka_state, queue);
                last_timeout_check = now.tv_sec;
            }
            loop_counter = 0;
        }

        for (int i = 0; i < n; i++) {
            const event_t* ev = &events[i];

            if (event_get_fd(ev) == listen_fd) {
                int client_fd;
                while ((client_fd = conn_accept(listen_fd)) > 0) {
                    add_connection_to_worker(queue, client_fd, worker_id, ka_state);
                }
            } else {
                PulsarConn* conn = (PulsarConn*)event_get_data(ev);
                if (!conn) continue;

                conn->worker_id = worker_id;

                if (event_is_read(ev))
                    handle_read(queue, conn, ka_state);
                else if (event_is_write(ev))
                    handle_write(queue, conn, ka_state);
                else if (event_is_error(ev))
                    conn->closing = true;

                if (conn->closing) close_connection(queue, conn, ka_state);
            }
        }
    }

    event_delete(queue, listen_fd);
    sys_close_direct(listen_fd);
    event_queue_free(queue);
    return NULL;
}

/* ================================================================
 * pulsar_run — Public Entry Point
 * ================================================================ */
int pulsar_run(const char* addr, int port) {
    for (int i = 0; i < NUM_WORKERS; i++) {
        worker_listen_fds[i] = create_server_socket(addr, port, i);
        if (worker_listen_fds[i] < 0) {
            fprintf(stderr, "create_server_socket %d failed\n", i);
            exit(EXIT_FAILURE);
        }
        set_nonblocking(worker_listen_fds[i]);
    }

    install_signal_handler();
    sort_routes();
    init_mimetypes();

    for (int i = 0; i < NUM_SLOW_WORKERS; i++) {
        slow_workers[i].id = i;
        slow_workers[i].queue = event_queue_create();
        if (!slow_workers[i].queue) {
            perror("slow event_queue_create");
            exit(EXIT_FAILURE);
        }
        memset(&slow_workers[i].keep_alive_state, 0, sizeof(KeepAliveState));

        if (pthread_create(&slow_workers[i].thread, NULL, slow_worker_thread, &slow_workers[i]) != 0) {
            perror("pthread_create slow worker");
            exit(EXIT_FAILURE);
        }
    }

    pthread_t workers[NUM_WORKERS] = {0};
    WorkerData worker_data[NUM_WORKERS] = {0};
    KeepAliveState keep_alive_states[NUM_WORKERS] = {0};

    for (int i = 0; i < NUM_WORKERS; i++) {
        event_queue_t* queue = event_queue_create();
        if (!queue) {
            perror("event_queue_create");
            exit(EXIT_FAILURE);
        }

        worker_data[i].queue = queue;
        worker_data[i].id = i;
        worker_data[i].listen_fd = worker_listen_fds[i];
        worker_data[i].keep_alive_state = &keep_alive_states[i];

        if (pthread_create(&workers[i], NULL, worker_thread, &worker_data[i]) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }

        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
        pthread_setaffinity_np(workers[i], sizeof(cpu_set_t), &cpuset);
    }

    printf("\nStarting server with %d workers (%d slow)\n", NUM_WORKERS, NUM_SLOW_WORKERS);
    printf("Listening on http://%s:%d\n", addr ? addr : "0.0.0.0", port);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    for (int i = 0; i < NUM_SLOW_WORKERS; i++) {
        pthread_join(slow_workers[i].thread, NULL);
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        sys_close_direct(worker_listen_fds[i]);
    }
    return 0;
}
