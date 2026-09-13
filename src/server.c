#include "internal.h"
#include "mimetypes.h"
#include "pulsar_itoa.h"
#include "workerpool.h"

#include <pthread.h>
#include <sched.h>
#include <unistd.h>

/* ================================================================
 * Process-wide runtime state
 * ================================================================ */

ALIGN(64) volatile sig_atomic_t server_running = 1;
static int worker_listen_fds[NUM_WORKERS];
WorkerPool worker_pools[NUM_WORKERS];

/* Cached exact "/" GET route. Populated on first hot-path hit; routes are
 * read-only after sort_routes() so the cached pointer stays valid. */
alignas(64) static route_t* g_cached_root_get = NULL;

/* Forward Declarations */
INLINE void finalize_response(PulsarConn* conn, HttpMethod method);
INLINE void handle_write(event_queue_t* queue, PulsarConn* conn, KeepAliveState* state);

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

INLINE uint16_t snapshot_date_header(char* dst, uint32_t* cached_gen, uint32_t batch_gen) {
    uint16_t len = g_date_hdr_len; /* read-only after startup, stays in L1 */
    if (likely(batch_gen != 0 && batch_gen == *cached_gen)) {
        return len;
    }
    if (unlikely(len == 0 || batch_gen == 0)) {
        if (unlikely(len == 0)) return 0;
        /* Pre-init batch: copy from slot 0 without advancing the cache. */
        memcpy(dst, g_date_slots[0].data, len);
        return len;
    }
    int idx = atomic_load_explicit(&g_date_cur, memory_order_relaxed);
    if (unlikely((unsigned)idx > 1u)) idx = 0;
    memcpy(dst, g_date_slots[idx].data, len);
    *cached_gen = batch_gen;
    return len;
}

INLINE void write_error(PulsarConn* conn, http_status status) {
    conn_set_status(conn, status);
    conn_set_content_type(conn, SS_LIT(PLAINTEXT_TYPE));
    finalize_response(conn, conn->request.method_type);
}

/* ================================================================
 * Middleware dispatch (registry lives in middleware.c)
 * ================================================================ */

INLINE void execute_all_middleware(PulsarCtx* ctx, route_t* route) {
    if (global_mw_count == 0 && route->mw_count == 0) {
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

INLINE void request_complete(PulsarConn* conn) {
#if ENABLE_LOGGING
    if (LOGGER_CALLBACK) {
        uint64_t s_ns = conn->start;
        uint64_t e_ns = pulsar_now_ns();
        uint64_t total_ns = (e_ns > s_ns) ? (e_ns - s_ns) : 0;

        PulsarCtx ctx = {.conn = conn, .userdata = g_handler_userdata};
        LOGGER_CALLBACK(&ctx, total_ns);
    }
#endif
    UNUSED(conn);
}

#define CRLF_WORD 0x0A0D

INLINE size_t fmt_cl_small(char* dst, size_t cl) {
    if (cl < 10) {
        dst[0] = (char)('0' + cl);
        return 1;
    }
    if (cl < 100) {
        /* Two-digit table lookup: no division (even constant-folded) at all. */
        dst[0] = DIGIT_PAIRS[cl * 2];
        dst[1] = DIGIT_PAIRS[cl * 2 + 1];
        return 2;
    }
    if (cl < 1000) {
        /* Reciprocal multiply for /100 (same magic as put4), remainder from
         * the table. Covers the entire inline-body Content-Length range. */
        uint32_t q = (uint32_t)(((uint64_t)(uint32_t)cl * 1374389535ULL) >> 37);
        uint32_t r = (uint32_t)cl - q * 100u;
        dst[0] = (char)('0' + q);
        dst[1] = DIGIT_PAIRS[r * 2];
        dst[2] = DIGIT_PAIRS[r * 2 + 1];
        return 3;
    }
    return pulsar_itoa((uint64_t)cl, dst);
}

__attribute__((no_stack_protector)) INLINE void finalize_response(PulsarConn* conn,
                                                                  HttpMethod method) {
    response_t* resp = &conn->response;

    /* Handle non-200 status code updates */
    if (unlikely(resp->status_code != StatusOK)) {
        StrSlice st = get_http_status(resp->status_code);
        /* status_len is 0 when no status line was pre-populated (e.g. early
         * error return via write_error where headers start at buf[0]).
         * In that case old_len must be 0 so the whole header block shifts. */
        size_t old_len = resp->status_len;
        if (old_len > resp->headers_len) old_len = 0;
        if (st.len == old_len) {
            memcpy(resp->buf, st.data, st.len);
        } else {
            size_t rest = resp->headers_len - old_len;
            memmove(resp->buf + st.len, resp->buf + old_len, rest);
            memcpy(resp->buf, st.data, st.len);
            resp->headers_len = (uint32_t)(st.len + rest);
        }
        resp->status_len = (uint8_t)st.len;
        /* The 200 OK prefix staged in buf[0..) is gone: force the next
         * request on this connection to re-stage it. */
        resp->date_gen = 0;
    }

    /* Content-Length */
    if (!HAS_RANGE_REQUEST(resp->flags)) {
        size_t cl = (method != HTTP_OPTIONS)
                        ? ((resp->file_fd >= 0) ? (size_t)resp->file_size : (size_t)resp->body_len)
                        : 0;

        char* dst = resp->buf + resp->headers_len;
        *(uint64_t*)(dst + 0) = UINT64_C(0x2d746e65746e6f43); /* "Content-" */
        *(uint64_t*)(dst + 8) = UINT64_C(0x203a6874676e654c); /* "Length: " */
        size_t digits = fmt_cl_small(dst + 16, cl);
        *(uint16_t*)(dst + 16 + digits) = CRLF_WORD;
        resp->headers_len += (uint32_t)(18 + digits);
    }

    /* Header block trailing CRLF */
    *(uint16_t*)(resp->buf + resp->headers_len) = CRLF_WORD;
    resp->headers_len += 2;

    /* File or heap fallback bodies: out_len represents headers only in buf */
    if (unlikely(resp->file_fd >= 0 || HAS_HEAP_ALLOCATED(resp->flags))) {
        resp->out_len = resp->headers_len;
        resp->out_sent = 0;
        return;
    }

    /* Fast Path: close the gap between headers and the inline body staging
     * area. Regions never overlap (dest < RESP_BODY_OFFSET <= src).
     * Small bodies (the entire benchmark profile: 13–20 B hello/json) are
     * moved with fixed-size 8/4/2/1 stores that always inline — no libc
     * memcpy PLT call, no register spill. Larger inline bodies fall back
     * to libc memcpy, which wins once SIMD setup amortizes (~128 B+). */
    size_t b_len = resp->body_len;
    if (b_len > 0) {
        char* d = resp->buf + resp->headers_len;
        const char* s = resp->buf + RESP_BODY_OFFSET;
        if (b_len <= 128) {
            size_t n = b_len;
            while (n >= 8) {
                uint64_t w;
                memcpy(&w, s, 8);
                memcpy(d, &w, 8);
                d += 8;
                s += 8;
                n -= 8;
            }
            if (n >= 4) {
                uint32_t w;
                memcpy(&w, s, 4);
                memcpy(d, &w, 4);
                d += 4;
                s += 4;
                n -= 4;
            }
            if (n >= 2) {
                uint16_t w;
                memcpy(&w, s, 2);
                memcpy(d, &w, 2);
                d += 2;
                s += 2;
                n -= 2;
            }
            if (n) *d = *s;
        } else {
            memcpy(d, s, b_len);
        }
    }
    resp->out_len = resp->headers_len + (uint32_t)b_len;
    resp->out_sent = 0;
}

/* ================================================================
 * Request Body
 * ================================================================ */

static http_status parse_request_body(PulsarConn* conn, const char* buf, size_t headers_len,
                                      size_t read_bytes) {
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
        perror("arena_alloc failed to allocate body");
        return StatusInternalServerError;
    }

    memcpy(req->body, buf + headers_len, body_available);
    req->body[body_available] = '\0';

    size_t received = body_available;
    while (received < content_length) {
        ssize_t n =
            sys_read_direct(conn->client_fd, req->body + received, content_length - received);
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
 * Core Request Processor
 * ================================================================ */
INLINE http_status process_request(PulsarConn* conn, const char* buf, size_t read_bytes,
                                   const char* end_of_headers, size_t* consumed,
                                   KeepAliveState* state, event_queue_t* queue,
                                   uint32_t batch_date_gen) {
    *consumed = 0;
    if (!end_of_headers) return StatusBadRequest;

    request_t* req = &conn->request;
    response_t* res = &conn->response;
    size_t headers_len = (size_t)(end_of_headers - buf) + 4;

    const char* url_ptr = NULL;
    size_t url_len = 0;
    const char* line_end = NULL;

    int prl = parse_request_line_simd(buf, read_bytes, req, &url_ptr, &url_len, &line_end);
    if (unlikely(prl < 0)) {
        /* Malformed request line: skip past these headers so handle_read
         * never re-parses the same bytes (error-loop), and let the caller
         * close the connection after the error response. */
        *consumed = headers_len;
        return StatusBadRequest;
    }

    size_t path_len;
    route_t* route;
    if (likely(prl == 1)) {
        /* Exact "GET /" hot path: path is known, no percent-encoding or
         * query string is possible in the 16-byte form. Reuse the cached
         * root route instead of hashing + radix matching per request. */
        req->path[0] = '/';
        req->path[1] = '\0';
        path_len = 1;
        route = g_cached_root_get;
        if (unlikely(!route)) {
            route = route_match(req->path, path_len, req->method_type, conn->arena);
            if (likely(route)) {
                g_cached_root_get = route;
                /* Root is exact/static; match_method_tree never allocated. */
            }
        }
    } else {
        path_len = decode_path_fast(url_ptr, url_len, req->path, sizeof(req->path));

        http_status qs = parse_query_params(conn, &path_len);
        if (unlikely(qs != StatusOK)) {
            *consumed = headers_len;
            return qs;
        }
        route = route_match(req->path, path_len, req->method_type, conn->arena);
    }

    /* Route is resolved before headers: matching needs only path + method.
     * Unknown paths 404 here, before any header work. *consumed covers the
     * header block; a possible body is irrelevant because the caller closes
     * the connection after any error response. */
    if (unlikely(!route)) {
        *consumed = headers_len;
        return StatusNotFound;
    }
    req->route = route;

    /* Stash the raw header block for lazy parsing, then take the minimal
     * scan on the hot path: safe method to a non-static route needs only
     * keep-alive (Content-Length is definitionally unused, Range is only
     * read by conn_servefile which materializes on demand). Everything
     * else (unsafe methods, static routes) takes the full parse. */
    const size_t hdr_off = (size_t)(line_end - buf);
    req->hdr_data = line_end;
    req->hdr_len_raw = headers_len - hdr_off;
    req->headers_parsed = false;
    /* content_length/range_hdr already cleared by reset_connection. */

    bool safe_fast_path = false;
    if (likely(SAFE_METHOD(req->method_type) && route->route_type != ROUTE_TYPE_STATIC)) {
        http_status ks = scan_keepalive_only(conn, req->hdr_data, req->hdr_len_raw);
        if (unlikely(ks != StatusOK)) {
            *consumed = headers_len;
            return ks;
        }
        *consumed = headers_len; /* no body on safe methods */
        safe_fast_path = true;
    } else {
        http_status hs =
            parse_request_headers(conn, req->hdr_data, req->method_type, req->hdr_len_raw);
        if (unlikely(hs != StatusOK)) {
            *consumed = headers_len;
            return hs;
        }
        req->headers_parsed = true;
        *consumed = headers_len + req->content_length;
    }

    if (!safe_fast_path) {
        http_status status = parse_request_body(conn, buf, headers_len, read_bytes);
        if (status != StatusOK) return status;
    }

    uint16_t prefix_len = snapshot_date_header(res->buf, &res->date_gen, batch_date_gen);
    res->status_len = 17;
    res->status_code = StatusOK;
    res->headers_len = prefix_len;

    PulsarCtx ctx = {.conn = conn, .userdata = g_handler_userdata};
    execute_all_middleware(&ctx, route);
    if (!conn->abort) route->handler(&ctx);

#if ENABLE_SLOW_WORKERS
    if (conn->offloaded) return StatusOK;
#endif

    if (HAS_CHUNKED_TRANSFER(conn->response.flags)) {
        request_complete(conn);
        if (conn->keep_alive) {
            AddKeepAliveConnection(conn, state);
            conn->closing = true;
            if (reset_connection(conn))
                conn->closing = (event_mod_read(queue, conn->client_fd, conn) < 0);
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

    int fd = -1;
    const int opt = 1;

    for (rp = result; rp; rp = rp->ai_next) {
        // Create non-blocking and close-on-exec atomically (zero fcntl syscalls)
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, rp->ai_protocol);
        if (fd == -1) continue;

        // Separate calls for REUSEADDR and REUSEPORT
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0 ||
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
            sys_close_direct(fd);
            fd = -1;
            continue;
        }

#ifdef IPV6_V6ONLY
        if (rp->ai_family == AF_INET6) {
            int no = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
        }
#endif

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;

        sys_close_direct(fd);
        fd = -1;
    }
    freeaddrinfo(result);

    if (fd == -1) {
        fprintf(stderr, "Could not bind to %s:%d\n", host ? host : "*", port);
        exit(EXIT_FAILURE);
    }

    // Keepalive on listener
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

    // TCP_DEFER_ACCEPT: Do not wake up epoll until HTTP request data arrives!
    int defer = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer, sizeof(defer));

    // TCP_FASTOPEN: Accept data in the SYN packet
    int fastopen_qlen = 1024;
    setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &fastopen_qlen, sizeof(fastopen_qlen));

    // Bind kernel packet processing directly to this worker's CPU core
    if (worker_cpu_id >= 0) {
        int cpu = worker_cpu_id;
        setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, sizeof(cpu));
    }

    // Maximum backlog.
    if (listen(fd, 65535) < 0) {
        perror("listen");
        sys_close_direct(fd);
        exit(EXIT_FAILURE);
    }
    return fd;
}

INLINE int conn_accept(int listen_fd) {
    // Pass NULL, NULL so the kernel skips copying peer address structures.
    // Set both SOCK_NONBLOCK and SOCK_CLOEXEC atomically.
    int client_fd = raw_accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (unlikely(client_fd < 0)) {
        return -1;
    }

    // The ONLY socket option that matters for HTTP performance:
    // Disables Nagle's algorithm so small HTTP responses flush immediately.
    const int yes = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    return client_fd;
}

static void add_connection_to_worker(event_queue_t* queue, int client_fd, int worker_id,
                                     KeepAliveState* ka_state) {
    Arena* arena = NULL;
    PulsarConn* conn = worker_pool_acquire(worker_id, &arena);
    if (!conn || !arena) {
        fprintf(stderr, "add_connection_to_worker pool acquire failed\n");
        sys_close_direct(client_fd);
        arena_destroy(arena);
        free(conn);
        return;
    }

    if (!init_connection(conn, arena, client_fd, worker_id)) {
        fprintf(stderr, "init_connection failed\n");
        sys_close_direct(client_fd);
        locals_destroy(&conn->locals);
        worker_pool_release(worker_id, conn, arena);
        return;
    }

    conn->owner_queue = queue;
    conn->owner_ka_state = ka_state;

#if ENABLE_SLOW_WORKERS
    conn->offloaded = false;
#endif

    if (event_add_read(queue, client_fd, conn) < 0) {
        perror("event_add_read");
        sys_close_direct(client_fd);
        conn->client_fd = -1;
        free_response_body(&conn->response);
        locals_destroy(&conn->locals);
        worker_pool_release(worker_id, conn, arena);
    }
}

/* ================================================================
 * handle_read (Zero-TLS Lookup via base_buf parameter)
 * batch_date_gen is sampled once per epoll batch by the worker loop:
 * no TSC reads and no atomic loads on the request path.
 * ================================================================ */
INLINE void handle_read(event_queue_t* queue, PulsarConn* conn, KeepAliveState* state,
                        char* base_buf, uint32_t batch_date_gen) {
#if ENABLE_LOGGING
    if (LOGGER_CALLBACK) {
        conn->start = pulsar_now_ns();
    }
#endif

    size_t pending = conn->pending_len;
    size_t max_read = READ_BUFFER_SIZE - 1;
    char* read_ptr = base_buf;

    // Restore unparsed tail from previous event directly into base_buf
    if (unlikely(pending > 0)) {
        memcpy(base_buf, conn->pending_buf, pending);
        read_ptr += pending;
        max_read -= pending;
    }

    // Read from socket directly into the offset
    ssize_t bytes_read = sys_read_direct(conn->client_fd, read_ptr, max_read);
    if (bytes_read < 0 && (bytes_read == -EAGAIN || bytes_read == -EWOULDBLOCK)) return;
    if (bytes_read <= 0) {
        conn->closing = true;
        return;
    }

    size_t total = pending + (size_t)bytes_read;
    conn->read_buf = base_buf;

    /* Liveness is stamped by the worker loop (batch_mono); nothing to do. */

    // Pipelining loop: process all back-to-back requests in base_buf
    size_t offset = 0;
    while (offset < total) {
        size_t available = total - offset;
        const char* cur_buf = base_buf + offset;

        const char* end_of_headers = find_headers_end_simd(cur_buf, available);
        if (!end_of_headers) {
            // Incomplete headers: need more network data
            break;
        }

        size_t consumed = 0;
        http_status status = process_request(conn, cur_buf, available, end_of_headers, &consumed,
                                             state, queue, batch_date_gen);
        if (unlikely(status != StatusOK)) {
            /* Error responses must not keep a potentially desynchronized
             * stream alive: send the error, then close */
            conn->keep_alive = false;
            write_error(conn, status);
        }

#if ENABLE_SLOW_WORKERS
        if (conn->offloaded) return;
#endif

        // Only trigger write if a response was actually produced
        if (conn->response.out_len > 0 || conn->response.file_fd > 0) {
            handle_write(queue, conn, state);
            if (conn->closing) return;

            // If socket buffer filled up (EAGAIN), pause processing pipelined requests
            if (HAS_WRITE_PENDING(conn->response.flags)) {
                offset += consumed;
                break;
            }
        }

        // If process_request consumed 0 bytes (e.g. waiting for full body), stop
        if (consumed == 0) {
            break;
        }

        offset += consumed;
    }

    // Save any incomplete trailing fragment for the next read
    size_t leftover = total - offset;
    if (leftover > 0) {
        if (likely(leftover < sizeof(conn->pending_buf))) {
            memcpy(conn->pending_buf, base_buf + offset, leftover);
            conn->pending_len = leftover;
        } else {
            // Header or part exceeded pending buffer capacity
            conn->closing = true;
        }
    } else {
        conn->pending_len = 0;
    }
}

/* Forward declaration for complex/slow fallback */
INLINE void handle_write_slow(event_queue_t* queue, PulsarConn* conn, KeepAliveState* state);

/* ================================================================
 * handle_write (Fast-Path Zero-Store Dispatcher)
 * ================================================================ */
INLINE void handle_write(event_queue_t* queue, PulsarConn* conn, KeepAliveState* state) {
    response_t* res = &conn->response;
    const uint8_t flags = res->flags;

    // =========================================================================
    // FAST PATH: Small/Medium Contiguous In-Memory Buffer (99.9% of HTTP traffic)
    // =========================================================================
    if (likely((flags & (HTTP_HEAP_ALLOCATED | HTTP_RANGE_REQUEST)) == 0 && res->file_fd <= 0)) {
        const uint32_t out_len = res->out_len;
        const uint32_t out_sent = res->out_sent;
        const uint32_t to_send = out_len - out_sent;

        ssize_t sent = sys_write_direct(conn->client_fd, res->buf + out_sent, to_send);

        // 1Common Case: Response 100% written in 1 syscall!
        if (likely(sent == (ssize_t)to_send)) {
            // DO NOT store to res->out_sent! It is discarded in reset_connection.
            request_complete(conn);

            const bool was_pending = HAS_WRITE_PENDING(flags);
            CLR_WRITE_PENDING(res->flags);

            if (likely(conn->keep_alive)) {
                AddKeepAliveConnection(conn, state);
                if (unlikely(!reset_connection(conn))) {
                    conn->closing = true;
                    return;
                }
                if (unlikely(was_pending)) {
                    if (event_mod_read(queue, conn->client_fd, conn) < 0) {
                        conn->closing = true;
                    }
                }
            } else {
                conn->closing = true;
            }
            return;
        }

        // Partial write: Socket buffer filled up partially
        if (sent > 0) {
            res->out_sent = out_sent + (uint32_t)sent;
            SET_WRITE_PENDING(res->flags);
            if (event_mod_write(queue, conn->client_fd, conn) < 0) {
                conn->closing = true;
            }
            return;
        }

        // Socket buffer completely full (EAGAIN / EWOULDBLOCK)
        if (sent < 0 && (sent == -EAGAIN || sent == -EWOULDBLOCK)) {
            SET_WRITE_PENDING(res->flags);
            if (event_mod_write(queue, conn->client_fd, conn) < 0) {
                conn->closing = true;
            }
            return;
        }

        // Socket error (EPIPE, ECONNRESET, etc.)
        conn->closing = true;
        request_complete(conn);
        return;
    }

    // =========================================================================
    // SLOW PATH: sendfile() & writev() for Heap Buffers
    // =========================================================================
    handle_write_slow(queue, conn, state);
}

/* ================================================================
 * handle_write_slow: Isolated to keep handle_write L1i-cache tiny
 * ================================================================ */
INLINE void handle_write_slow(event_queue_t* queue, PulsarConn* conn, KeepAliveState* state) {
    response_t* res = &conn->response;
    int client_fd = conn->client_fd;
    const bool sending_file = res->file_fd > 0 && res->file_size > 0;
    ssize_t sent = -1;

    for (;;) {
        sent = 0;
        bool complete = false;

        if (sending_file) {
            if (!HAS_HEADERS_WRITTEN(res->flags)) {
                sent = sys_write_direct(client_fd, res->buf + res->out_sent,
                                        res->out_len - res->out_sent);
                if (unlikely(sent < 0)) goto handle_error;
                if (unlikely(sent == 0)) return;

                res->out_sent += (uint32_t)sent;
                if (res->out_sent == res->out_len) {
                    SET_HEADERS_WRITTEN(res->flags);
                }
                continue;
            }

            const off_t send_end =
                HAS_RANGE_REQUEST(res->flags) ? (off_t)res->range_end : (off_t)res->file_size;
            off_t rem = send_end - res->file_offset;
            if (rem <= 0) {
                complete = true;
            } else {
                off_t chunk =
                    HAS_RANGE_REQUEST(res->flags) ? (off_t)MIN(1 << 20, (size_t)rem) : rem;

                sent = file_sendfile(client_fd, res->file_fd, &res->file_offset, (size_t)chunk);
                if (sent == -1 && errno == EAGAIN) {
                    sent = 0;
                }
                if (unlikely(sent < 0)) {
                    sent = -errno;
                    goto handle_error;
                }
                if (sent == 0) {
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
        } else {
            /* Large body fallback: Header in res->buf + Heap Body */
            struct iovec iov[2];
            int iovcnt = 0;

            if (res->out_sent < res->out_len) {
                iov[iovcnt].iov_base = res->buf + res->out_sent;
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
    ALIGN(64) char read_buf[READ_BUFFER_SIZE] = {0};

    worker_pool_init(worker_id);

    if (event_add_server(queue, listen_fd) < 0) {
        perror("event_add_server");
        worker_pool_cleanup(worker_id);
        return NULL;
    }

    event_t events[MAX_EVENTS] = {0};
    struct epoll_event raw_events[MAX_EVENTS] = {0};

    time_t last_timeout_check = 0;
    int loop_counter = 0;

    while (server_running) {
        int n = event_wait(queue, raw_events, events, MAX_EVENTS, 500);
        if (n == -1) {
            if (errno == EINTR) continue;
            perror("event_wait");
            continue;
        }

        /* Per-batch sampling: ONE monotonic read + ONE relaxed Date load per
         * epoll return, amortized over all events in the batch. The request
         * path itself performs no TSC reads and no atomic loads. */
        time_t batch_mono = 0;
        uint32_t batch_date_gen = 0;
        if (likely(n > 0)) {
            batch_mono = pulsar_mono_sec();
            batch_date_gen = atomic_load_explicit(&g_date_gen, memory_order_relaxed);
        }

        /* Date header is refreshed by the background date thread;
         * workers only handle keep-alive timeouts here. */
        if (unlikely(++loop_counter >= 128)) {
            loop_counter = 0;
            /* Reuse the batch timestamp when available to avoid a second TSC
             * read; fall back to a fresh read on empty batches. */
            time_t mono_now = (n > 0) ? batch_mono : pulsar_mono_sec();

            if (mono_now - last_timeout_check >= 5) {
                CheckKeepAliveTimeouts(ka_state, queue, worker_id);
                last_timeout_check = mono_now;
            }
        }

        for (int i = 0; i < n; i++) {
            if (i + 1 < n && events[i + 1].data) {
                __builtin_prefetch((const char*)events[i + 1].data, 0, 3);
                __builtin_prefetch((const char*)events[i + 1].data + 64, 0, 3);
            }

            event_t* ev = &events[i];
            PulsarConn* conn = (PulsarConn*)ev->data;

            if (unlikely(conn == NULL)) {
                int client_fd;
                while ((client_fd = conn_accept(listen_fd)) > 0) {
                    add_connection_to_worker(queue, client_fd, worker_id, ka_state);
                }
            } else {
                /* Any event proves the peer is alive (one store, no TSC).
                 * This also covers writable-only events for pending sends. */
                conn->last_activity = batch_mono;
                if (likely(ev->readable))
                    handle_read(queue, conn, ka_state, read_buf, batch_date_gen);
                else if (ev->writable)
                    handle_write(queue, conn, ka_state);
                else if (ev->error)
                    conn->closing = true;

                if (conn->closing) close_connection(queue, conn, ka_state, worker_id);
            }
        }
    }

    event_delete(queue, listen_fd);
    sys_close_direct(listen_fd);
    event_queue_close(queue);
    worker_pool_cleanup(worker_id);
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
    pulsar_time_init();
    refresh_date_header_now();

    pthread_t date_thread = 0;
    bool date_thread_started = false;
    if (pthread_create(&date_thread, NULL, date_updater_thread, NULL) != 0) {
        perror("pthread_create date updater (continuing without background refresh)");
    } else {
        date_thread_started = true;
    }

#if ENABLE_SLOW_WORKERS
    for (int i = 0; i < NUM_SLOW_WORKERS; i++) {
        slow_workers[i].id = i;
        if (event_queue_create(&slow_workers[i].queue) != 0) {
            perror("slow event_queue_create");
            for (int j = 0; j < i; j++) {
                event_queue_close(&slow_workers[j].queue);
            }
            exit(EXIT_FAILURE);
        }
        memset(&slow_workers[i].ka_state, 0, sizeof(KeepAliveState));

        if (pthread_create(&slow_workers[i].thread, NULL, slow_worker_thread, &slow_workers[i]) !=
            0) {
            perror("pthread_create slow worker");
            exit(EXIT_FAILURE);
        }
    }
#endif

    pthread_t workers[NUM_WORKERS] = {0};
    WorkerData worker_data[NUM_WORKERS] = {0};
    KeepAliveState keep_alive_states[NUM_WORKERS] = {0};
    event_queue_t queues[NUM_WORKERS];

    for (int i = 0; i < NUM_WORKERS; i++) {
        if (event_queue_create(&queues[i]) != 0) {
            perror("event_queue_create");
            for (int j = 0; j < i; j++) {
                event_queue_close(&queues[j]);
            }
            exit(EXIT_FAILURE);
        }

        worker_data[i].queue = &queues[i];
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

#if ENABLE_SLOW_WORKERS
    printf("\nStarting server with %d workers (%d slow)\n", NUM_WORKERS, NUM_SLOW_WORKERS);
#else
    printf("\nStarting server with %d workers\n", NUM_WORKERS);
#endif
    printf("Listening on http://%s:%d\n", addr ? addr : "0.0.0.0", port);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }
#if ENABLE_SLOW_WORKERS
    for (int i = 0; i < NUM_SLOW_WORKERS; i++) {
        pthread_join(slow_workers[i].thread, NULL);
    }
#endif

    if (date_thread_started) {
        pthread_join(date_thread, NULL);
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        sys_close_direct(worker_listen_fds[i]);
    }
    return 0;
}
