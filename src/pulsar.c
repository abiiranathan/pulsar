#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>

#ifndef ALLOW_PULSAR_TYPES
#define ALLOW_PULSAR_TYPES
#include "types.h"
#undef ALLOW_PULSAR_TYPES
#endif

#include "../include/events.h"
#include "../include/mimetypes.h"
#include "../include/plog.h"
#include "../include/pulsar.h"

static int server_fd = -1;
volatile sig_atomic_t server_running = 1;
static HttpHandler global_middleware[MAX_GLOBAL_MIDDLEWARE] = {0};
static size_t global_mw_count = 0;
static void* GLOBAL_HANDLER_USERDATA = NULL;

// reserves space for \r\n\0 in the response header buffer
#define SAFETY_MARGIN 3

static _Atomic time_t cached_date_ts = 0;
static char cached_date_hdr[64] = {0};
static int cached_date_len = 0;

#define conn_timedout(now, last_activity) ((now) - (last_activity) > CONNECTION_TIMEOUT)

typedef struct KeepAliveState {
    PulsarConn* head;
    PulsarConn* tail;
    size_t count;
} KeepAliveState;

/* ================================================================
 * Forward Declarations
 * ================================================================ */
static void finalize_response(PulsarConn* conn, HttpMethod method);
static void close_connection(int queue_fd, PulsarConn* conn, KeepAliveState* ka_state);

/* ================================================================
 * Utility: fast u64 → decimal string (no snprintf overhead)
 * ================================================================ */
INLINE int u64_to_dec(char* buf, uint64_t v) {
    if (v == 0) {
        buf[0] = '0';
        return 1;
    }
    char tmp[20];
    int len = 0;
    while (v) {
        tmp[len++] = (char)('0' + v % 10);
        v /= 10;
    }
    for (int i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];
    return len;
}

static void RemoveKeepAliveConnection(PulsarConn* conn, KeepAliveState* state) {
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

static void CheckKeepAliveTimeouts(KeepAliveState* state, int epoll_fd) {
    PulsarConn* current = state->head;
    time_t now = time(NULL);
    while (current) {
        PulsarConn* next = current->next;
        if (conn_timedout(now, current->last_activity)) { close_connection(epoll_fd, current, state); }
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

static inline void response_init(response_t* resp, Arena* arena) {
    *resp = (response_t){
        .body_capacity = WRITE_BUFFER_SIZE,
        .file_fd = -1,
    };

    resp->headers_buf = arena_alloc_align(arena, HEADERS_BUF_SIZE, 32);
    resp->status_buf = arena_alloc_align(arena, STATUS_LINE_SIZE, 32);
}

INLINE void free_response_body(response_t* resp) {
    if (resp->heap_allocated && resp->body.heap) {
        free(resp->body.heap);
        resp->body.heap = NULL;
        resp->heap_allocated = false;
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
    conn->next = NULL;
    conn->prev = NULL;

    LocalsInit(&conn->locals);

    conn->read_buf = arena_alloc(arena, READ_BUFFER_SIZE);
    req->path = arena_alloc(arena, PATH_MAX);
    req->headers = arena_alloc(arena, sizeof(headers_t));
    if (req->headers) headers_init(req->headers);

    response_init(res, arena);

    return (conn->read_buf && req->path && req->headers && res->status_buf && res->headers_buf);
}

static bool reset_connection(PulsarConn* conn) {
    conn->closing = false;
    conn->keep_alive = true;
    conn->abort = false;
    response_t* res = &conn->response;
    request_t* req = &conn->request;
    Arena* arena = conn->arena;

    if (req->body) free(req->body);

    free_response_body(res);

    req->method[0] = '\0';
    req->method_type = HTTP_INVALID;
    req->content_length = 0;
    req->body = NULL;
    req->query_params = NULL;
    req->route = NULL;
    LocalsClear(&conn->locals);
    arena_reset(arena);

    // Init request.
    req->path = arena_alloc(arena, PATH_MAX);
    req->headers = arena_alloc(arena, sizeof(headers_t));
    conn->read_buf = arena_alloc(arena, READ_BUFFER_SIZE);
    if (req->headers) headers_init(req->headers);
    response_init(res, arena);

    if (!conn->in_keep_alive) {
        conn->next = NULL;
        conn->prev = NULL;
    }
    return (conn->read_buf && req->path && req->headers && res->status_buf && res->headers_buf);
}

static void close_connection(int queue_fd, PulsarConn* conn, KeepAliveState* ka_state) {
    if (!conn || conn->client_fd == -1) return;

    event_delete(queue_fd, conn->client_fd);
    close(conn->client_fd);
    conn->client_fd = -1;

    RemoveKeepAliveConnection(conn, ka_state);

    if (conn->request.body) free(conn->request.body);
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
 * Request Parsing
 * ================================================================ */

/* Finds "\r\n\r\n" in buf[0..len). Returns pointer to the '\r' or NULL.
 * Uses memchr to skip non-'\r' bytes in bulk, then checks the 3-byte
 * suffix with a single 32-bit load — no SIMD setup overhead. */
INLINE const char* find_headers_end(const char* buf, size_t len) {
    if (len < 4) return NULL;

    const char* p = buf;
    const char* end = buf + len - 3; /* need 4 bytes from p */

    while (p < end) {
        p = memchr(p, '\r', (size_t)(end - p));
        if (!p) return NULL;

        /* Load 4 bytes at once and compare as a little-endian uint32.
         * "\r\n\r\n" = 0x0a0d0a0d in LE. Avoids 3 separate byte checks. */
        uint32_t v;
        memcpy(&v, p, 4); /* memcpy for strict-aliasing safety */
        if (v == UINT32_C(0x0a0d0a0d)) return p;

        p++; /* skip this '\r' and try next */
    }
    return NULL;
}

static bool parse_request_headers(PulsarConn* conn, HttpMethod method, size_t headers_len) {
    const char* ptr = conn->read_buf;
    const char* end = ptr + headers_len;
    const bool is_safe = SAFE_METHOD(method);
    request_t* req = &conn->request;
    headers_t* headers = req->headers;
    conn->keep_alive = true;
    uint8_t flags = 0;  // bit 0: content_length_set  bit 1: connection_set

    while (ptr < end) {
        // --- name: runs up to the colon ---
        const char* const colon = memchr(ptr, ':', (size_t)(end - ptr));
        if (!colon) break;

        const size_t name_len = (size_t)(colon - ptr);
        if (name_len == 0) {
            // A bare colon is an invalid header name (RFC 9110 §5.1).
            fprintf(stderr, "Invalid header: empty name\n");
            return false;
        }

        // --- value: skip leading OWS, then find CRLF ---
        const char* value_start = colon + 1;
        while (value_start < end && (*value_start == ' ' || *value_start == '\t'))
            value_start++;

        const char* const eol = memchr(value_start, '\r', (size_t)(end - value_start));
        if (!eol || eol + 1 >= end || eol[1] != '\n') break;

        // Strip trailing OWS before the CRLF (RFC 9110 §5.5).
        const char* value_end = eol;
        while (value_end > value_start && (value_end[-1] == ' ' || value_end[-1] == '\t'))
            value_end--;

        const size_t value_len = (size_t)(value_end - value_start);
        StrSlice name = {.data = ptr, .len = name_len};
        StrSlice value = {.data = value_start, .len = value_len};

        // --- Special-case Content-Length (unsafe methods only, first occurrence). ---
        if (!is_safe && name_len == 14 && !(flags & 1)) {
            if (strncasecmp(name.data, "Content-Length", 14) == 0) {
                // UINT64_MAX is 20 digits; 21 bytes is the exact buffer needed.
                char buf[21];
                if (value_len >= sizeof(buf)) {
                    fprintf(stderr, "Content-Length value too long (%zu bytes)\n", value_len);
                    return false;
                }
                memcpy(buf, value_start, value_len);
                buf[value_len] = '\0';
                StoError code;
                if ((code = str_to_ulong(buf, &req->content_length)) != STO_SUCCESS) {
                    fprintf(stderr, "Invalid Content-Length '%s': %s\n", buf, sto_error_string(code));
                    return false;
                }
                flags |= 1;
            }
        }

        // Set Connection Keep-Alive
        if (name_len == 10 && !(flags & 2)) {
            if (strncasecmp(name.data, "Connection", 10) == 0) {
                conn->keep_alive = !(value_len == 5 && strncasecmp(value_start, "close", 5) == 0);
                flags |= 2;
            }
        }

        if (!headers_set(headers, name, value)) { return false; }
        ptr = eol + 2;  // Advance past \r\n.
    }
    return true;
}

static bool parse_query_params(PulsarConn* conn, size_t* path_len) {
    char* const path = conn->request.path;
    const char* query = strchr(path, '?');
    if (!query) return true;

    // Truncate the path in-place and update the caller's length.
    path[query - path] = '\0';
    *path_len = (size_t)(query - path);

    const char* ptr = query + 1;          // Points into read_buf; no copy needed.
    const char* end = ptr + strlen(ptr);  // Or pass the known length down if available.

    conn->request.query_params = arena_alloc(conn->arena, sizeof(headers_t));
    if (!conn->request.query_params) return false;
    headers_init(conn->request.query_params);

    while (ptr < end) {
        // --- key: runs up to '=' or '&' or end ---
        const char* eq = memchr(ptr, '=', (size_t)(end - ptr));
        const char* amp = memchr(ptr, '&', (size_t)(end - ptr));

        // No '=' in this segment → treat as a boolean flag with empty value.
        const char* key_end = eq && (!amp || eq < amp) ? eq : (amp ? amp : end);
        StrSlice key = {.data = ptr, .len = (size_t)(key_end - ptr)};

        StrSlice value = {.data = key_end, .len = 0};  // Default: empty.

        if (eq && (!amp || eq < amp)) {
            // --- value: runs up to '&' or end ---
            const char* val_start = eq + 1;
            const char* val_end = amp ? amp : end;
            value = (StrSlice){.data = val_start, .len = (size_t)(val_end - val_start)};
            ptr = val_end;
        } else {
            ptr = key_end;
        }

        // Skip the '&' separator.
        if (ptr < end && *ptr == '&') ptr++;

        if (key.len == 0) continue;  // Skip empty keys (e.g. trailing '&').

        if (!headers_set(conn->request.query_params, key, value)) { return false; }
    }
    return true;
}

static bool parse_request_body(PulsarConn* conn, size_t headers_len, size_t read_bytes) {
    if (conn->request.content_length == 0) return true;

    request_t* req = &conn->request;
    size_t content_length = req->content_length;
    size_t body_available = read_bytes - headers_len;
    ASSERT(body_available <= content_length);

    if (content_length > MAX_BODY_SIZE) {
        conn_set_status(conn, StatusRequestEntityTooLarge);
        return false;
    }

    req->body = malloc(content_length + 1);
    if (!req->body) {
        perror("malloc body");
        return false;
    }

    memcpy(req->body, conn->read_buf + headers_len, body_available);
    req->body[body_available] = '\0';

    size_t received = body_available;
    while (received < content_length) {
        ssize_t n = read(conn->client_fd, req->body + received, content_length - received);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10);
                continue;
            }
            perror("read body");
            return false;
        }
        if (n == 0) {
            perror("read body EOF");
            return false;
        }
        received += (size_t)n;
    }
    return true;
}

/* ================================================================
 * Request Getters
 * ================================================================ */

char* req_body(PulsarConn* conn) {
    return conn->request.body;
}

StrSlice req_body_slice(PulsarConn* conn) {
    return (StrSlice){
        .data = conn->request.body,
        .len = conn->request.content_length,
    };
}

const char* req_method(PulsarConn* conn) {
    return conn->request.method;
}
const char* req_path(PulsarConn* conn) {
    return conn->request.path;
}

StrSlice query_get(PulsarConn* conn, const char* name) {
    if (!conn->request.query_params) return (StrSlice){0};
    StrSlice h = headers_get(conn->request.query_params, name);
    return ss_is_valid(h) ? h : ss_empty();
}

headers_t* query_params(PulsarConn* conn) {
    return conn->request.query_params;
}

const headers_t* req_headers(PulsarConn* conn) {
    return (const headers_t*)conn->request.headers;
}

StrSlice req_header_get(PulsarConn* conn, const char* name) {
    StrSlice h = headers_get(conn->request.headers, name);
    return ss_is_valid(h) ? h : ss_empty();
}

/* ================================================================
 * Response Status
 * ================================================================ */
void conn_set_status(PulsarConn* restrict conn, http_status code) {
    StrSlice status = get_http_status(code);
    response_t* res = &conn->response;
    res->status_code = code;
    res->status_len = status.len;
    memcpy(res->status_buf, status.data, status.len);
}

http_status res_get_status(PulsarConn* conn) {
    return conn->response.status_code;
}

/* ================================================================
 * Response Header Accessors
 * ================================================================ */
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
    size_t required = name.len + value.len + 4;  // ': ' + '\r\n'
    size_t remaining = HEADERS_BUF_SIZE - resp->headers_len - SAFETY_MARGIN;

    if (required > remaining) {
        fprintf(stderr, "Not enough space left for response headers\n");
        conn->closing = true;
        return;
    }

    char* dest = resp->headers_buf + resp->headers_len;
    memcpy(dest, name.data, name.len);
    dest[name.len] = ':';
    dest[name.len + 1] = ' ';
    memcpy(dest + name.len + 2, value.data, value.len);
    dest[name.len + 2 + value.len] = '\r';
    dest[name.len + 2 + value.len + 1] = '\n';
    resp->headers_len += required;
}

void conn_writeheader_raw(PulsarConn* conn, const char* header, size_t length) {
    // Check that header ends with \r\n
    if (length < 2 || header[length - 2] != '\r' || header[length - 1] != '\n') {
        fprintf(stderr, "Headers must end with \\r\\n\n");
        return;
    }

    response_t* resp = &conn->response;
    size_t offset = resp->headers_len;
    size_t remaining = (HEADERS_BUF_SIZE - offset - SAFETY_MARGIN);
    if (length > remaining) {
        conn->closing = true;
        return;
    }
    memcpy(resp->headers_buf + offset, header, length);
    resp->headers_len += length;
}

void conn_writeheaders_vec(PulsarConn* conn, const struct iovec* headers, size_t count) {
    response_t* resp = &conn->response;
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++)
        total_len += headers[i].iov_len;

    size_t remaining = HEADERS_BUF_SIZE - resp->headers_len - SAFETY_MARGIN;
    if (total_len > remaining) {
        conn->closing = true;
        return;
    }

    char* dest = resp->headers_buf + resp->headers_len;
    for (size_t i = 0; i < count; i++) {
        memcpy(dest, headers[i].iov_base, headers[i].iov_len);
        dest += headers[i].iov_len;
    }
    resp->headers_len += total_len;
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

    if (likely(!res->heap_allocated)) {
        if (required <= STACK_BUFFER_SIZE) {
            memcpy(res->body.stack + body_len, data, len);
            res->body_len += len;
            return (int)len;
        }

        // Migrate stack buffer → heap
        size_t cap = WRITE_BUFFER_SIZE;
        while (cap < required) {
            if (cap > SIZE_MAX / 2) {
                cap = required;
                break;
            }
            cap *= 2;
        }
        uint8_t* hp = aligned_alloc(CACHE_LINE_SIZE, cap);
        if (!hp) {
            perror("aligned_alloc");
            return -1;
        }
        memcpy(hp, res->body.stack, body_len);
        res->heap_allocated = true;
        res->body_capacity = cap;
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
        uint8_t* nb = realloc(res->body.heap, cap);
        if (!nb) {
            perror("realloc body");
            return -1;
        }
        res->body.heap = nb;
        res->body_capacity = cap;
    }

    memcpy(res->body.heap + body_len, data, len);
    res->body_len += len;
    return (int)len;
}

int conn_notfound(PulsarConn* conn) {
    conn_set_status(conn, StatusNotFound);
    conn_set_content_type(conn, SS_LIT(PLAINTEXT_TYPE));
    return conn_write(conn, "404 Not Found", 13);
}

int conn_write_string(PulsarConn* conn, const char* str) {
    return str ? conn_write(conn, str, strlen(str)) : 0;
}

__attribute__((format(printf, 2, 3))) int conn_writef(PulsarConn* conn, const char* restrict fmt, ...) {
    va_list args;
    char sbuf[1024];
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

void conn_abort(PulsarConn* conn) {
    conn->abort = true;
}

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
    if (resp->headers_len + needed >= HEADERS_BUF_SIZE - SAFETY_MARGIN) {
        conn->closing = true;
        return;
    }
    char* dest = resp->headers_buf + resp->headers_len;
    memcpy(dest, "Location: ", 10);
    dest += 10;
    memcpy(dest, location, loc_len);
    dest += loc_len;
    *dest++ = '\r';
    *dest++ = '\n';
    resp->headers_len += needed;
}

/* ================================================================
 * Cached Server + Date Headers
 * ================================================================ */
INLINE void write_server_headers(PulsarConn* conn) {
    conn_writeheader_raw(conn, "Server: Pulsar/1.0\r\n", 20);

    time_t now = conn->last_activity;
    time_t ts = atomic_load_explicit(&cached_date_ts, memory_order_relaxed);
    if (now != ts) {
        // Race is benign: at worst two threads format the same second.
        char buf[64];
        int n = (int)strftime(buf, sizeof(buf), "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&now));
        if (n > 0) {
            memcpy(cached_date_hdr, buf, (size_t)n);
            cached_date_len = n;
            atomic_store_explicit(&cached_date_ts, now, memory_order_relaxed);
        }
    }
    if (cached_date_len > 0) conn_writeheader_raw(conn, cached_date_hdr, (size_t)cached_date_len);
}

/* ================================================================
 * Chunked Transfer & SSE
 * ================================================================ */
INLINE ssize_t writev_retry(int fd, struct iovec* iov, int iovcnt) {
    ssize_t total = 0;
    while (iovcnt > 0) {
        ssize_t written = writev(fd, iov, iovcnt);
        if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10);
                continue;
            }
            return -1;
        }
        total += written;
        ssize_t rem = written;
        int i = 0;
        for (; i < iovcnt && rem > 0; i++) {
            if ((size_t)rem < iov[i].iov_len) {
                iov[i].iov_base = (char*)iov[i].iov_base + rem;
                iov[i].iov_len -= (size_t)rem;
                break;
            }
            rem -= (ssize_t)iov[i].iov_len;
        }
        iov += i;
        iovcnt -= i;
    }
    return total;
}

void conn_start_sse(PulsarConn* conn) {
    conn_set_status(conn, StatusOK);
    static const char SSE_HEADERS
        [] = "Content-Type: text/event-stream\r\n"
             "Cache-Control: no-cache\r\n"
             "Connection: keep-alive\r\n"
             "Transfer-Encoding: chunked\r\n";
    conn_writeheader_raw(conn, SSE_HEADERS, sizeof(SSE_HEADERS) - 1);
    SET_CONTENT_TYPE(conn->response.flags);
    SET_CHUNKED_TRANSFER(conn->response.flags);
}

void conn_start_chunked_transfer(PulsarConn* conn, int max_age_seconds) {
    conn_set_status(conn, StatusOK);
    static const char TRANS_HEADERS
        [] = "Connection: keep-alive\r\n"
             "Transfer-Encoding: chunked\r\n";
    conn_writef(conn, "Cache-Control: public, max-age=%d\r\n", max_age_seconds);
    conn_writeheader_raw(conn, TRANS_HEADERS, sizeof(TRANS_HEADERS) - 1);
    SET_CONTENT_TYPE(conn->response.flags);
    SET_CHUNKED_TRANSFER(conn->response.flags);
}

ssize_t conn_write_chunk(PulsarConn* conn, const void* data, size_t size) {
    struct iovec iov[6];
    int iovcnt = 0;
    char chunk_hdr[32];
    static const char trailer[] = "\r\n";

    if (!HAS_HEADERS_WRITTEN(conn->response.flags)) {
#if WRITE_SERVER_HEADERS
        write_server_headers(conn);
#endif
        assert(conn->response.headers_len < HEADERS_BUF_SIZE - 3);
        memcpy(conn->response.headers_buf + conn->response.headers_len, "\r\n", 2);
        conn->response.headers_len += 2;

        iov[iovcnt++] = (struct iovec){conn->response.status_buf, conn->response.status_len};
        iov[iovcnt++] = (struct iovec){conn->response.headers_buf, conn->response.headers_len};
        SET_HEADERS_WRITTEN(conn->response.flags);
    }

    if (size == 0) {
        static const char final_chunk[] = "0\r\n\r\n";
        iov[iovcnt++] = (struct iovec){(void*)final_chunk, sizeof(final_chunk) - 1};
        return writev_retry(conn->client_fd, iov, iovcnt);
    }

    int hlen = snprintf(chunk_hdr, sizeof(chunk_hdr), "%zx\r\n", size);
    iov[iovcnt++] = (struct iovec){chunk_hdr, (size_t)hlen};
    iov[iovcnt++] = (struct iovec){(void*)data, size};
    iov[iovcnt++] = (struct iovec){(void*)trailer, 2};
    return writev_retry(conn->client_fd, iov, iovcnt);
}

#define BATCH_SIZE 4096

void conn_send_event(PulsarConn* conn, const SSEvent* evt) {
    bool send_headers = false;
    if (!HAS_HEADERS_WRITTEN(conn->response.flags)) {
#if WRITE_SERVER_HEADERS
        write_server_headers(conn);
#endif
        ASSERT(conn->response.headers_len < HEADERS_BUF_SIZE - 3);
        memcpy(conn->response.headers_buf + conn->response.headers_len, "\r\n", 2);
        conn->response.headers_len += 2;
        SET_HEADERS_WRITTEN(conn->response.flags);
        send_headers = true;
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

    if (send_headers) {
        struct iovec iov[2] = {
            {conn->response.status_buf, conn->response.status_len},
            {conn->response.headers_buf, conn->response.headers_len},
        };
        writev_retry(conn->client_fd, iov, 2);
    }

    if (ss_is_valid(evt->event)) {
        FLUSH_IF_NEEDED(evt->event.len + 8);
        bpos += (size_t)snprintf(batch + bpos, BATCH_SIZE - bpos, "event: %.*s\n", (int)evt->event.len,
                                 evt->event.data);
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

void conn_end_chunked_transfer(PulsarConn* conn) {
    conn_write_chunk(conn, NULL, 0);
}
void conn_end_sse(PulsarConn* conn) {
    conn_write_chunk(conn, NULL, 0);
}

bool conn_is_open(PulsarConn* conn) {
    return conn && conn->client_fd != -1 && !conn->closing;
}
int conn_worker_id(PulsarConn* conn) {
    return conn ? conn->worker_id : 0;
}

/* ================================================================
 * Range Request Helpers
 * ================================================================ */
#define MAX_RANGE_HDR 64
INLINE bool parse_range(StrSlice hdr, ssize_t* start, ssize_t* end, bool* has_end) {
    if (!ss_contains(hdr, SS_LIT("bytes="))) return false;

    /* sscanf requires a null-terminated string; StrSlice is not guaranteed to
     * be null-terminated, so we materialise a bounded copy on the stack.
     * Range headers are short by spec (RFC 9110 §14.1), so a 64-byte buffer
     * is more than sufficient. */
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
    if (sb < 0 || eb < 0) return false;
    *start = sb;
    *end = eb;
    return true;
}

INLINE void send_range_headers(PulsarConn* conn, ssize_t start, ssize_t end, off_t file_size) {
    static const char hfmt
        [] = "Accept-Ranges: bytes\r\n"
             "Content-Length: %ld\r\n"
             "Content-Range: bytes %ld-%ld/%lld\r\n";
    response_t* resp = &conn->response;
    size_t remaining = HEADERS_BUF_SIZE - resp->headers_len - SAFETY_MARGIN;
    if (remaining > 164) {
        int len = snprintf(resp->headers_buf + resp->headers_len, remaining, hfmt, end - start + 1, start, end,
                           (long long)file_size);
        if (len > 0 && (size_t)len < remaining) {
            resp->headers_len += (uint16_t)len;
            return;
        }
    }
    conn->closing = true;
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
        close(fd);
        return false;
    }

    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&sb.st_mtime));
    conn_writeheader(conn, SS_LIT("Last-Modified"), ss_from_cstr(tbuf));

    if (!HAS_CONTENT_TYPE(conn->response.flags)) { conn_set_content_type(conn, get_mimetype((char*)filename)); }

    conn->response.file_fd = fd;
    conn->response.file_size = sb.st_size;
    conn->response.file_offset = 0;

    StrSlice range_hdr = headers_get(conn->request.headers, "Range");
    if (!range_hdr.data) return true;

    ssize_t s = 0, e = 0;
    bool has_end;
    if (parse_range(range_hdr, &s, &e, &has_end)) {
        if (!validate_range(has_end, &s, &e, sb.st_size)) {
            close(fd);
            conn_set_status(conn, StatusRequestedRangeNotSatisfiable);
            return false;
        }
        conn_set_status(conn, StatusPartialContent);
        send_range_headers(conn, s, e, sb.st_size);
        conn->response.file_offset = s;
        conn->response.file_size = sb.st_size;
        conn->response.max_range = (uint32_t)(e - s + 1);
        SET_RANGE_REQUEST(conn->response.flags);
    }
    return true;
}

/* ================================================================
 * Finalize Response
 * ================================================================ */
static void finalize_response(PulsarConn* conn, HttpMethod method) {
    response_t* resp = &conn->response;
    if (resp->status_len == 0) conn_set_status(conn, StatusOK);

    if (likely(!HAS_RANGE_REQUEST(resp->flags))) {
        size_t cl = 0;
        if (method != HTTP_OPTIONS) cl = (resp->file_fd >= 0) ? resp->file_size : resp->body_len;

        // Fast serializer: avoid snprintf on every single request.
        char cl_buf[40] = "Content-Length: ";
        int cl_len = 16 + u64_to_dec(cl_buf + 16, (uint64_t)cl);
        cl_buf[cl_len++] = '\r';
        cl_buf[cl_len++] = '\n';
        conn_writeheader_raw(conn, cl_buf, (size_t)cl_len);
    }

#if WRITE_SERVER_HEADERS
    write_server_headers(conn);
#endif

    assert(resp->headers_len < HEADERS_BUF_SIZE - SAFETY_MARGIN);
    memcpy(resp->headers_buf + resp->headers_len, "\r\n", 2);
    resp->headers_len += 2;
    resp->headers_buf[HEADERS_BUF_SIZE - 1] = '\0';
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

    bool is_malicious = is_malicious_path(path);
    const char* static_ptr = path + pattern_len;
    size_t static_len = strlen(static_ptr);

    if (strcmp(pattern, "/") != 0) {
        static_ptr += (*static_ptr == '/');
        static_len -= (*static_ptr == '/');
    }

    bool path_too_long = (dirlen >= PATH_MAX) | (static_len >= PATH_MAX) | ((dirlen + static_len + 2) >= PATH_MAX);

    enum { RESP_MALICIOUS = 1, RESP_TOO_LONG = 2, RESP_PROCESS = 3 } rtype = RESP_PROCESS;
    if (is_malicious) rtype = RESP_MALICIOUS;
    if (path_too_long) rtype = RESP_TOO_LONG;

    char filepath[PATH_MAX] = {0};
    char decoded_path[PATH_MAX] = {0};
    char index_file[PATH_MAX] = {0};
    bool file_found = false;

    if (rtype == RESP_PROCESS) {
        bool needs_slash = (dirlen > 0) & (dirname[dirlen - 1] != '/');
        bool diff_prefix = strncmp(static_ptr, route->pattern, pattern_len) != 0;
        int plen = snprintf(filepath, PATH_MAX, "%.*s%s%.*s", (int)dirlen, dirname,
                            (diff_prefix & needs_slash) ? "/" : "", (int)static_len, static_ptr);

        if (plen >= 0 && plen < PATH_MAX) {
            if (strstr(filepath, "%") || strstr(filepath, "+")) {
                url_percent_decode(filepath, decoded_path, (size_t)plen, PATH_MAX);
                strncpy(filepath, decoded_path, sizeof(filepath));
            }

            file_found = is_file(filepath);
            if (!file_found) {
                int ilen = snprintf(index_file, sizeof(index_file), "%s/index.html", filepath);
                file_found = (ilen >= 0 && ilen < PATH_MAX) && is_file(index_file);
            }
        }
    }

    switch (rtype) {
        case RESP_MALICIOUS:
            conn_notfound(conn);
            break;
        case RESP_TOO_LONG:
            conn_set_status(conn, StatusRequestURITooLong);
            conn_set_content_type(conn, SS_LIT("text/html"));
            conn_write_string(conn, "<h1>Path too long</h1>");
            break;
        case RESP_PROCESS:
            if (file_found) {
                bool use_index = !is_file(filepath);
                const char* serve_file = use_index ? index_file : filepath;
                StrSlice content_type = use_index ? SS_LIT("text/html") : get_mimetype(filepath);
                conn_set_content_type(conn, content_type);
                if (!conn_servefile(conn, serve_file)) {
                    conn_set_status(conn, StatusInternalServerError);
                    conn_set_content_type(conn, SS_LIT("text/html"));
                    conn_write_string(conn, "<h1>Error serving file</h1>");
                }
            } else {
                conn_notfound(conn);
            }
            break;
    }
}

/* ================================================================
 * Path Parameters
 * ================================================================ */
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

/* ================================================================
 * Middleware
 * ================================================================ */
INLINE void execute_all_middleware(PulsarCtx* ctx, route_t* route) {
#define RUN_MW(mw, n)                     \
    for (size_t _i = 0; _i < (n); _i++) { \
        (mw)[_i](ctx);                    \
        if (ctx->conn->abort) return;     \
    }
    RUN_MW(global_middleware, global_mw_count);
    RUN_MW(route->middleware, route->mw_count);
#undef RUN_MW
}

void use_global_middleware(HttpHandler* mw, size_t count) {
    if (!count) return;
    ASSERT(count + global_mw_count <= MAX_GLOBAL_MIDDLEWARE);
    for (size_t i = 0; i < count; i++)
        global_middleware[global_mw_count++] = mw[i];
}

void use_route_middleware(route_t* route, HttpHandler* mw, size_t count) {
    if (!count) return;
    ASSERT(route->mw_count + count <= MAX_ROUTE_MIDDLEWARE);
    for (size_t i = 0; i < count; i++)
        route->middleware[route->mw_count++] = mw[i];
}

/* ================================================================
 * Global Config / Callbacks / Locals
 * ================================================================ */
void pulsar_set_handler_userdata(void* userdata) {
    GLOBAL_HANDLER_USERDATA = userdata;
}

void* pulsar_get_handler_userdata(void) {
    return GLOBAL_HANDLER_USERDATA;
}

Request conn_get_request_metadata(PulsarConn* conn) {
    return (Request){
        .path = conn->request.path,
        .method = conn->request.method,
        .body = (StrSlice){.data = conn->request.body, .len = conn->request.content_length},
        .route_pattern = conn->request.route->pattern,
    };
}

static PlogState PLOG_STATE = {0};             // State for the plog async logger.
static int LOG_FD = -1;                        // Set to a valid file descriptor to enable logging.
static PulsarCallback LOGGER_CALLBACK = NULL;  // User-provided callback for logging request latency.

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

/** Async logging callback for Pulsar.
* ---------------------------------------
*
 * This logger is asynchronous and non-blocking as possible: 
 * it formats the log line on the stack and submits it to plog without any locks or syscalls in the hot path.
 *
 * This is called after every request, and is passed the total latency in nanoseconds.
 * It gathers request info from the connection
 * and submits a formatted log line to the logger.
 * The callback must be set via pulsar_set_callback() before starting the server.
 * You can customize the PLOG_LINE_MAX macro to increase the maximum log line length if needed.
 *
 */
void pulsar_logger(PulsarCtx* ctx, uint64_t total_ns) {
    PulsarConn* conn = ctx->conn;
    const char* method = req_method(conn);
    const char* path = req_path(conn);
    http_status status_code = res_get_status(conn);
    StrSlice user_agent = req_header_get(conn, "User-Agent");
    if (!ss_is_valid(user_agent)) { user_agent = SS_LIT("-"); }

    /* Format latency with the most readable unit. */
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

    /*
     * Build the full log line on the stack.  snprintf + plog_submit is the
     * entire hot-path cost — no locks, no syscalls.
     */
    char line[PLOG_LINE_MAX];
    int n = snprintf(line, sizeof(line), "[Pulsar] %-7s %-5s %3d %8s %.*s\n", method, path, (int)status_code,
                     latency_str, (int)user_agent.len, user_agent.data);
    if (n > 0 && n < (int)sizeof(line)) { plog_submit(&PLOG_STATE, line, (uint32_t)n); }
}

bool pulsar_set(PulsarConn* conn, const char* k, void* v, ValueFreeFunc ff) {
    return LocalsSetValue(&conn->locals, k, v, ff);
}

// Get a thread-safe arena for this connection.
// It's lifetime is tied to the handler and will be reset or destroyed when
// the handler returns.
Arena* pulsar_get_arena(PulsarConn* conn) {
    return conn->arena;
}

void* pulsar_alloc(PulsarConn* conn, size_t sz) {
    return arena_alloc(conn->arena, sz);
}
void* pulsar_get(PulsarConn* conn, const char* k) {
    return LocalsGetValue(&conn->locals, k);
}
void pulsar_delete(PulsarConn* conn, const char* k) {
    LocalsRemove(&conn->locals, k);
}

/* ================================================================
 * Logging / Latency
 * ================================================================ */

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
INLINE int parse_request_line(const char* input, size_t input_len, char* method, size_t method_size, size_t* method_len,
                              char* url, size_t url_size, size_t* url_len, char* protocol, size_t protocol_size,
                              size_t* protocol_len) {
    const char* ptr = input;
    const char* end = input + input_len;

#define PARSE_TOKEN(out, osz, olen)                      \
    do {                                                 \
        const char* ts = ptr;                            \
        while (ptr < end && *ptr != ' ' && *ptr != '\0') \
            ptr++;                                       \
        size_t tl = (size_t)(ptr - ts);                  \
        if (tl == 0 || tl >= (osz)) return -1;           \
        memcpy((out), ts, tl);                           \
        (out)[tl] = '\0';                                \
        *(olen) = tl;                                    \
        while (ptr < end && *ptr == ' ')                 \
            ptr++;                                       \
    } while (0)

    PARSE_TOKEN(method, method_size, method_len);
    if (ptr >= end) return -1;
    PARSE_TOKEN(url, url_size, url_len);
    if (ptr >= end) return -1;

    const char* ps = ptr;
    while (ptr < end && *ptr != '\r' && *ptr != '\n' && *ptr != '\0')
        ptr++;
    size_t plen = (size_t)(ptr - ps);
    if (plen == 0 || plen >= protocol_size) return -1;
    memcpy(protocol, ps, plen);
    protocol[plen] = '\0';
    *protocol_len = plen;
#undef PARSE_TOKEN
    return 0;
}

/* ================================================================
 * Core Request Processor
 * ================================================================ */
static http_status process_request(PulsarConn* conn, size_t read_bytes, KeepAliveState* state, int queue_fd) {
    // Use AVX2-accelerated memmem instead of strstr for header boundary search.
    const char* end_of_headers = find_headers_end(conn->read_buf, read_bytes);
    if (!end_of_headers) return StatusBadRequest;

    request_t* req = &conn->request;
    size_t headers_len = (size_t)(end_of_headers - conn->read_buf) + 4;

    char url[MAX_PATH_LEN + 1];
    char http_protocol[16] = {0};
    size_t method_len = 0, url_len = 0, protocol_len = 0;

    if (parse_request_line(conn->read_buf, read_bytes, req->method, sizeof(req->method), &method_len, url, sizeof(url),
                           &url_len, http_protocol, sizeof(http_protocol), &protocol_len) != 0)
        return StatusBadRequest;

    size_t path_len = url_percent_decode(url, req->path, url_len, MAX_PATH_LEN);

    if (strncmp(http_protocol, "HTTP/1.1", protocol_len) != 0) return StatusHTTPVersionNotSupported;

    req->method_type = http_method_from_string(req->method, method_len);
    if (!METHOD_VALID(req->method_type)) return StatusMethodNotAllowed;

    if (!parse_query_params(conn, &path_len)) return StatusInternalServerError;
    if (!parse_request_headers(conn, req->method_type, headers_len)) return StatusInternalServerError;

    route_t* route = route_match(req->path, path_len, req->method_type, conn->arena);
    if (!route) return StatusNotFound;

    req->route = route;
    if (!parse_request_body(conn, headers_len, read_bytes)) return StatusInternalServerError;

    PulsarCtx ctx = {.conn = conn, .userdata = GLOBAL_HANDLER_USERDATA};
    execute_all_middleware(&ctx, route);
    if (!conn->abort) route->handler(&ctx);

    if (HAS_CHUNKED_TRANSFER(conn->response.flags)) {
        request_complete(conn);
        if (conn->keep_alive) {
            AddKeepAliveConnection(conn, state);
            conn->closing = true;
            if (reset_connection(conn)) conn->closing = (event_mod_read(queue_fd, conn->client_fd, conn) < 0);
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

static int create_server_socket(const char* host, int port) {
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
            close(fd);
            continue;
        }
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(result);

    if (fd == -1) {
        fprintf(stderr, "Could not bind to %s:%d\n", host ? host : "*", port);
        exit(EXIT_FAILURE);
    }

    // These options ARE inherited by accepted sockets on Linux — set once here.
    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
    int rcv = 256 * 1024, snd = 256 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));

    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
        close(fd);
        exit(EXIT_FAILURE);
    }
    return fd;
}

/* ================================================================
 * Accept & Per-Connection Socket Options
 *
 * Only set options that are NOT inherited from the listening socket.
 * SO_RCVTIMEO/SO_SNDTIMEO, TCP keepalive timers, and TCP_QUICKACK
 * must be set per accepted socket.
 * ================================================================ */
INLINE int conn_accept(int worker_id) {
    (void)worker_id;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

#ifdef __linux__
    int client_fd = accept4(server_fd, (struct sockaddr*)&addr, &addr_len, SOCK_NONBLOCK);
#else
    int client_fd = accept(server_fd, (struct sockaddr*)&addr, &addr_len);
#endif
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) perror("accept");
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

/* ================================================================
 * Event Loop: Add / Read / Write
 * ================================================================ */
static void add_connection_to_worker(int queue_fd, int client_fd, int worker_id) {
    Arena* arena = arena_create(1 << 20);
    if (!arena) {
        fprintf(stderr, "add_connection_to_worker->arena_create failed\n");
        close(client_fd);
        return;
    }

    PulsarConn* conn = calloc(1, sizeof(*conn));
    if (!conn || !arena) {
        fprintf(stderr, "add_connection_to_worker malloc failed\n");
        close(client_fd);
        arena_destroy(arena);
        return;
    }

    if (!init_connection(conn, arena, client_fd, worker_id)) {
        fprintf(stderr, "init_connection failed\n");
        close(client_fd);
        LocalsClear(&conn->locals);
        arena_destroy(arena);
        free(conn);
        return;
    }

    if (event_add_read(queue_fd, client_fd, conn) < 0) {
        perror("event_add_read");
        close(client_fd);
        conn->client_fd = -1;
        if (conn->request.body) free(conn->request.body);
        free_response_body(&conn->response);
        LocalsClear(&conn->locals);
        arena_destroy(arena);
        free(conn);
    }
}

// Forward declaration to break circular dependency between handle_read and handle_write.
static void handle_write(int queue_fd, PulsarConn* conn, KeepAliveState* state);

static void handle_read(int queue_fd, PulsarConn* conn, KeepAliveState* state) {
    // Record the start time as early as possible to capture request processing latency.
#if ENABLE_LOGGING
    if (LOGGER_CALLBACK) { clock_gettime(CLOCK_MONOTONIC, &conn->start); }
#endif

    ssize_t bytes_read = read(conn->client_fd, conn->read_buf, READ_BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        conn->closing = true;
        return;
    }
    conn->read_buf[bytes_read] = '\0';

    http_status status = process_request(conn, (size_t)bytes_read, state, queue_fd);
    if (status != StatusOK) { write_error(conn, status); }

    /* 
     * If the connection was already reset or set to close (e.g., during chunked
     * or SSE handshakes inside process_request), do not invoke handle_write.
     */
    if (conn->request.method_type != HTTP_INVALID && !conn->closing) { handle_write(queue_fd, conn, state); }
}

static void handle_write(int queue_fd, PulsarConn* conn, KeepAliveState* state) {
    response_t* res = &conn->response;
    int client_fd = conn->client_fd;
    const bool sending_file = res->file_fd > 0 && res->file_size > 0;

    for (;;) {
        ssize_t sent = 0;
        bool complete = false;

        if (sending_file) {
            if (!HAS_HEADERS_WRITTEN(res->flags)) {
                struct iovec iov[2] = {
                    {res->status_buf + res->status_sent, res->status_len - res->status_sent},
                    {res->headers_buf + res->headers_sent, res->headers_len - res->headers_sent},
                };
                sent = writev(client_fd, iov, 2);
                if (unlikely(sent < 0)) goto handle_error;
                if (unlikely(sent == 0)) return;

                size_t sp = MIN((size_t)sent, iov[0].iov_len);
                res->status_sent += sp;
                res->headers_sent += (size_t)sent - sp;
                if (res->status_sent == res->status_len && res->headers_sent == res->headers_len)
                    SET_HEADERS_WRITTEN(res->flags);
                continue;
            }

            off_t rem = (off_t)res->file_size - res->file_offset;
            if (rem <= 0) {
                complete = true;
            } else {
                off_t chunk = HAS_RANGE_REQUEST(res->flags) ? (off_t)MIN(1 << 20, (size_t)rem) : rem;

#if defined(__linux__)
                off_t off = res->file_offset;
                sent = sendfile(client_fd, res->file_fd, &off, (size_t)chunk);
                if (sent > 0) res->file_offset = off;
#elif defined(__APPLE__) || defined(__FreeBSD__)
                off_t len = chunk;
                int r = sendfile(res->file_fd, client_fd, res->file_offset, &len, NULL, 0);
                if (r == 0 || (r == -1 && errno == EAGAIN)) {
                    sent = len;
                    res->file_offset += sent;
                } else
                    sent = -1;
#else
                static _Thread_local char fbuf[1 << 20];
                chunk = MIN(chunk, (off_t)sizeof(fbuf));
                ssize_t rb = pread(res->file_fd, fbuf, (size_t)chunk, res->file_offset);
                if (rb <= 0) {
                    sent = -1;
                    errno = EIO;
                } else {
                    sent = write(client_fd, fbuf, (size_t)rb);
                    if (sent > 0) res->file_offset += sent;
                }
#endif
                if (unlikely(sent < 0)) goto handle_error;
                if (sent == 0) return;
                complete = (res->file_offset >= (off_t)res->file_size);
            }
        } else {
            struct iovec iov[3] = {
                {res->status_buf + res->status_sent, res->status_len - res->status_sent},
                {res->headers_buf + res->headers_sent, res->headers_len - res->headers_sent},
                {(res->heap_allocated ? res->body.heap : res->body.stack) + res->body_sent,
                 res->body_len - res->body_sent},
            };
            sent = writev(client_fd, iov, 3);
            if (unlikely(sent < 0)) goto handle_error;
            if (sent == 0) return;

            size_t rem = (size_t)sent, s;
            s = MIN(rem, iov[0].iov_len);
            res->status_sent += s;
            rem -= s;
            s = MIN(rem, iov[1].iov_len);
            res->headers_sent += s;
            rem -= s;
            s = MIN(rem, iov[2].iov_len);
            res->body_sent += s;

            complete = (res->status_sent == res->status_len) && (res->headers_sent == res->headers_len) &&
                       (res->body_sent == res->body_len);
        }

        if (complete) {
            request_complete(conn);
            if (sending_file) {
                close(res->file_fd);
                res->file_fd = -1;
            }

            // Capture write pending state prior to connection resetting.
            const bool was_pending = HAS_WRITE_PENDING(res->flags);
            CLR_WRITE_PENDING(res->flags);

            if (conn->keep_alive) {
                AddKeepAliveConnection(conn, state);
                if (reset_connection(conn)) {
                    /*
                     * If the write was previously deferred (having hit EAGAIN),
                     * we must modify the event mask back to read (EPOLLIN).
                     * If it completed synchronously, it is already armed for
                     * read from the original event_add_read.
                     */
                    if (was_pending) {
                        if (event_mod_read(queue_fd, conn->client_fd, conn) < 0) { conn->closing = true; }
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
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        /* 
         * Write blocked. Arm for EPOLLOUT and wait for epoll to trigger.
         * The file descriptor is kept open so transmission can resume.
         */
        SET_WRITE_PENDING(res->flags);
        if (event_mod_write(queue_fd, conn->client_fd, conn) < 0) {
            if (sending_file) {
                close(res->file_fd);
                res->file_fd = -1;
            }
            conn->closing = true;
        }
        return;
    }

    if (sending_file) {
        close(res->file_fd);
        res->file_fd = -1;
    }
    if (errno != EPIPE) { perror("write failed"); }
    conn->closing = true;
    request_complete(conn);
}

/* ================================================================
 * Worker Thread
 * ================================================================ */
typedef struct {
    int queue_fd;
    int id;
    KeepAliveState* keep_alive_state;
} WorkerData;

void* worker_thread(void* arg) {
    WorkerData* worker = (WorkerData*)arg;
    int queue_fd = worker->queue_fd;
    int worker_id = worker->id;
    KeepAliveState* ka_state = worker->keep_alive_state;

    if (event_add_server(queue_fd, server_fd) < 0) {
        perror("event_add_server");
        return NULL;
    }

    event_t events[MAX_EVENTS] = {0};
    long last_timeout_check = 0;
    int loop_counter = 0;

    while (server_running) {
        int n = event_wait(queue_fd, events, MAX_EVENTS, 500);
        if (n == -1) {
            if (errno == EINTR) continue;
            perror("event_wait");
            continue;
        }

        // Only check the clock when the event wait times out (n == 0)
        // or every 100 loop iterations to prevent starvation under heavy load
        loop_counter++;
        if (n == 0 || loop_counter >= 100) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - last_timeout_check >= 5) {
                CheckKeepAliveTimeouts(ka_state, queue_fd);
                last_timeout_check = now.tv_sec;
            }
            loop_counter = 0;
        }

        for (int i = 0; i < n; i++) {
            const event_t* ev = &events[i];

            if (event_get_fd(ev) == server_fd) {
                int client_fd = conn_accept(worker_id);
                if (client_fd > 0) add_connection_to_worker(queue_fd, client_fd, worker_id);
            } else {
                PulsarConn* conn = (PulsarConn*)event_get_data(ev);
                if (!conn) continue;

                conn->worker_id = worker_id;

                if (event_is_read(ev))
                    handle_read(queue_fd, conn, ka_state);
                else if (event_is_write(ev))
                    handle_write(queue_fd, conn, ka_state);
                else if (event_is_error(ev))
                    conn->closing = true;

                if (conn->closing) close_connection(queue_fd, conn, ka_state);
            }
        }
    }

    event_delete(queue_fd, server_fd);
    close(queue_fd);
    return NULL;
}

/* ================================================================
 * pulsar_run — public entry point
 * ================================================================ */
int pulsar_run(const char* addr, int port) {
    server_fd = create_server_socket(addr, port);
    set_nonblocking(server_fd);

    install_signal_handler();
    sort_routes();
    init_mimetypes();

    pthread_t workers[NUM_WORKERS] = {0};
    WorkerData worker_data[NUM_WORKERS] = {0};
    KeepAliveState keep_alive_states[NUM_WORKERS] = {0};

    for (int i = 0; i < NUM_WORKERS; i++) {
        int queue_fd = event_queue_create();
        if (queue_fd == -1) {
            perror("event_queue_create");
            exit(EXIT_FAILURE);
        }

        worker_data[i].queue_fd = queue_fd;
        worker_data[i].id = i;
        worker_data[i].keep_alive_state = &keep_alive_states[i];

        if (pthread_create(&workers[i], NULL, worker_thread, &worker_data[i])) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    printf("\nStarting server with %d workers\n", NUM_WORKERS);
    printf("Listening on http://%s:%d\n", addr ? addr : "0.0.0.0", port);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }
    close(server_fd);
    return 0;
}
