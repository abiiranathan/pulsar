#include "../include/pulsar.h"
#include <solidc/macros.h>
#include "../include/events.h"

#define SAFETY_MARGIN 3  // reserves space for \r\n\0 in the response header buffer

static int server_fd                                        = -1;   // Server socket file descriptor
volatile sig_atomic_t server_running                        = 1;    // Server running flag
static HttpHandler global_middleware[MAX_GLOBAL_MIDDLEWARE] = {0};  // Global middleware array
static size_t global_mw_count                               = 0;    // Global middleware count
static PulsarCallback LOGGER_CALLBACK = NULL;  // No logger callback by default.

typedef struct KeepAliveState {
    connection_t* head;
    connection_t* tail;
    size_t count;
} KeepAliveState;

// Forward declarations.
INLINE void finalize_response(connection_t* conn, HttpMethod method);
INLINE void close_connection(int queue_fd, connection_t* conn, KeepAliveState* ka_state);

INLINE int get_num_available_cores() {
    return sysconf(_SC_NPROCESSORS_ONLN);
}

INLINE bool conn_timedout(time_t now, time_t last_activity) {
    return (now - last_activity) > CONNECTION_TIMEOUT;
}

INLINE void RemoveKeepAliveConnection(connection_t* conn, KeepAliveState* state) {
    if (!conn->in_keep_alive) {
        return;
    }

    // Update neighbors
    if (conn->prev) {
        conn->prev->next = conn->next;
    } else {
        state->head = conn->next;
    }

    if (conn->next) {
        conn->next->prev = conn->prev;
    } else {
        state->tail = conn->prev;
    }

    // Clear pointers
    conn->prev = NULL;
    conn->next = NULL;
    state->count--;
    conn->in_keep_alive = false;
}

INLINE void AddKeepAliveConnection(connection_t* conn, KeepAliveState* state) {
    if (conn->in_keep_alive) return;

    // Add to front
    conn->next = state->head;
    conn->prev = NULL;

    if (state->head) {
        state->head->prev = conn;
    } else {
        state->tail = conn;
    }

    state->head = conn;
    state->count++;
    conn->in_keep_alive = true;
}

INLINE void CheckKeepAliveTimeouts(KeepAliveState* state, int worker_id, int epoll_fd) {
    connection_t* current = state->head;
    time_t now            = time(NULL);
    while (current) {
        connection_t* next = current->next;
        if (conn_timedout(now, current->last_activity)) {
            // printf("Worker %d: closing timeout connection: %p\n", worker_id, (void*)current);
            UNUSED(worker_id);
            close_connection(epoll_fd, current, state);
        }
        current = next;
    }

#if defined(__linux__)
    // Release memory to OS
    malloc_trim(0);
#endif
}

// Signal handler for graceful shutdown.
void handle_sigint(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        server_running = 0;
    }
}

static void install_signal_handler(void) {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);  // Ignore SIGPIPE signal
}

/* ================================================================
 * Connection Management Functions
 * ================================================================ */

INLINE request_t* create_request(Arena* arena) {
    // Allocate request structure.
    request_t* req = arena_alloc(arena, sizeof(request_t));
    if (!req) {
        return NULL;
    }

    // Allocate request headers
    req->headers = headers_new(arena);
    if (!req->headers) {
        return NULL;
    };

    /* Allocate path */
    req->path = arena_alloc(arena, MAX_PATH_LEN + 1);
    if (!req->path) {
        return NULL;
    }

    req->method[0]      = '\0';          // Init method to empty string.
    req->method_type    = HTTP_INVALID;  // Initial method is not valid
    req->content_length = 0;             // No content length.
    req->body           = NULL;          /* Init body to NULL */
    req->query_params   = NULL;          // No query params initially
    req->route          = NULL;          // No matching route.
    return req;
}

static inline void response_init(response_t* resp) {
    if (!resp) return;
    resp->status_code                 = 0;  // HTTP status code
    resp->type                        = ResponseTypeBuffer;
    resp->state.buffer.heap_allocated = false;
    resp->state.buffer.heap_allocated = false;              // Start with stack allocation
    resp->state.buffer.body_len       = 0;                  // No body content initially
    resp->state.buffer.body_capacity  = WRITE_BUFFER_SIZE;  // Default to write buffer capacity

    // Length tracking
    resp->headers_len = 0;
    resp->status_len  = 0;
    resp->flags       = 0;

    // Epoll retry state
    resp->retry.status_sent  = 0;
    resp->retry.headers_sent = 0;
    resp->retry.body_sent    = 0;
}

INLINE response_t* create_response(Arena* arena) {
    response_t* resp = arena_alloc(arena, sizeof(response_t));
    if (resp) response_init(resp);
    return resp;
}

// Free request body. (Request structure is arena-allocated.)
INLINE void free_request(request_t* req) {
    if (!req) return;

    if (req->body) {
        free(req->body);
        req->body = NULL;
    }
}

INLINE void free_response(response_t* resp) {
    if (!resp) return;

    switch (resp->type) {
        case ResponseTypeBuffer:
            BufferResponse* b = &resp->state.buffer;
            if (b->heap_allocated && b->body.heap) {
                free(b->body.heap);
            }
        case ResponseTypeFile:
            break;
    }
}

INLINE bool init_connection(connection_t* conn, Arena* arena, int client_fd) {
    conn->closing       = false;
    conn->client_fd     = client_fd;
    conn->keep_alive    = true;
    conn->in_keep_alive = false;
    conn->abort         = false;
    conn->arena         = arena;
    conn->last_activity = time(NULL);
    conn->response      = create_response(arena);
    conn->read_buf[0]   = '\0';
    conn->request       = create_request(arena);
    conn->locals        = malloc(sizeof(Locals));
    if (conn->locals) LocalsInit(conn->locals);

#if ENABLE_LOGGING
    clock_gettime(CLOCK_MONOTONIC, &conn->start);
#endif
    conn->next = NULL;
    conn->prev = NULL;
    return (conn->request && conn->response && conn->locals);
}

INLINE bool reset_connection(connection_t* conn) {
    conn->closing    = false;
    conn->keep_alive = true;    // Default to Keep-Alive
    conn->abort      = false;   // Connection not aborted
    free(conn->request->body);  // Free request body.

    // Reset response buffer before resetting arena.
    switch (conn->response->type) {
        case ResponseTypeBuffer:
            if (conn->response->state.buffer.heap_allocated) {
                free(conn->response->state.buffer.body.heap);
            }
        default:
            // fall through
    }

    // Reset locals
    if (conn->locals) LocalsReset(conn->locals);
    arena_reset(conn->arena);

#if ENABLE_LOGGING
    clock_gettime(CLOCK_MONOTONIC, &conn->start);
#endif
    conn->request     = create_request(conn->arena);
    conn->response    = create_response(conn->arena);
    conn->read_buf[0] = '\0';

    // Don't reset these fields if connection is in keep-alive list
    if (!conn->in_keep_alive) {
        conn->next = NULL;
        conn->prev = NULL;
    }
    return (conn->request && conn->response);
}

/* ================================================================
 * Updated Connection Management Functions
 * ================================================================ */

INLINE void close_connection(int queue_fd, connection_t* conn, KeepAliveState* ka_state) {
    if (!conn || conn->client_fd == -1) return;

    event_delete(queue_fd, conn->client_fd);
    close(conn->client_fd);
    conn->client_fd = -1;

    RemoveKeepAliveConnection(conn, ka_state);

    free_request(conn->request);
    free_response(conn->response);
    LocalsReset(conn->locals);
    free(conn->locals);

    if (conn->arena) arena_destroy(conn->arena);
    free(conn);
}

// Send an error response during request processing.
INLINE void send_error_response(connection_t* conn, http_status status) {
    const char* status_text = conn_set_status(conn, status);  // is non-NULL.
    conn_set_content_type(conn, PLAINTEXT_TYPE);
    conn_write_string(conn, status_text);
    finalize_response(conn, conn->request->method_type);
    conn->last_activity = time(NULL);
    // Switch to writing the response.
}

/* ================================================================
 * Request Parsing Functions
 * ================================================================ */

INLINE bool parse_request_headers(connection_t* restrict conn, HttpMethod method,
                                  size_t headers_len) {
    const char* restrict ptr = conn->read_buf;
    const char* const end    = ptr + headers_len;
    const bool is_safe       = SAFE_METHOD(method);
    request_t* const req     = conn->request;
    Arena* const arena       = conn->arena;
    headers_t* const headers = req->headers;

    // Initialize connection defaults and pack flags into single byte
    conn->keep_alive = true;
    uint8_t flags    = 0;  // bit 0: content_length_set, bit 1: connection_set

    while (ptr < end) {
        // Parse header name
        const char* const colon = (const char*)memchr(ptr, ':', (size_t)(end - ptr));
        if (!colon) break;

        const size_t name_len = (size_t)(colon - ptr);

        // Move to header value (combine pointer arithmetic)
        const char* value_start = colon + 1;
        while (value_start < end && *value_start == ' ')
            value_start++;

        // Parse header value
        const char* const eol = (const char*)memchr(value_start, '\r', (size_t)(end - value_start));
        if (!eol || eol + 1 >= end || eol[1] != '\n') break;

        const size_t value_len = (size_t)(eol - value_start);

        // Check for special headers with minimal branching
        if (name_len == 14 && !(flags & 1) && !is_safe) {
            // Check Content-Length (most common case first)
            if (strncasecmp(ptr, "Content-Length", 14) == 0) {
                char buf[32];  // Enough for max uint64_t
                if (value_len < sizeof(buf)) {
                    memcpy(buf, value_start, value_len);
                    buf[value_len] = '\0';

                    // Parse string to ulong
                    StoError code;
                    if ((code = str_to_ulong(buf, &req->content_length)) != STO_SUCCESS) {
                        fprintf(stderr, "Invalid content length: %s\n", sto_error_string(code));
                        return false;
                    };

                    flags |= 1;  // Set content_length_set
                }
                return false;
            }
        } else if (name_len == 10 && !(flags & 2)) {
            if (strncasecmp(ptr, "Connection", 10) == 0) {
                conn->keep_alive = !(value_len == 5 && strncasecmp(value_start, "close", 5) == 0);
                flags |= 2;  // Set connection_set
            }
        }

        // Allocate and store header (only if we still need to store it)
        char* const name = arena_strdupn(arena, ptr, name_len);
        if (unlikely(!name)) return false;

        char* const value = arena_strdupn(arena, value_start, value_len);
        if (unlikely(!value)) return false;

        if (unlikely(!headers_set(headers, name, value))) {
            return false;
        }

        ptr = eol + 2;  // Skip CRLF
    }

    return true;
}

INLINE bool parse_query_params(connection_t* conn) {
    char* path  = conn->request->path;
    char* query = strchr(path, '?');
    if (!query) return true;

    *query = '\0';
    query++;

    conn->request->query_params = headers_new(conn->arena);
    if (!conn->request->query_params) return false;

    char* save_ptr1 = NULL;
    char* save_ptr2 = NULL;
    char* pair      = strtok_r(query, "&", &save_ptr1);

    while (pair) {
        char* key   = strtok_r(pair, "=", &save_ptr2);
        char* value = strtok_r(NULL, "", &save_ptr2);

        if (key) {
            // query_params own memory of key and value using an arena.
            headers_set(conn->request->query_params, key, value ? value : "");
        }
        pair = strtok_r(NULL, "&", &save_ptr1);
    }
    return true;
}

INLINE bool parse_request_body(connection_t* conn, size_t headers_len, size_t read_bytes) {
    if (conn->request->content_length == 0) return true;

    request_t* req        = conn->request;
    size_t content_length = req->content_length;
    size_t body_available = read_bytes - headers_len;
    ASSERT(body_available <= content_length);

    if (content_length > MAX_BODY_SIZE) {
        conn_set_status(conn, StatusRequestEntityTooLarge);
        return false;
    }

    // Allocate full request body (+ null byte for safety).
    req->body = malloc(content_length + 1);
    if (!req->body) {
        perror("malloc for body");
        return false;
    }

    memcpy(req->body, conn->read_buf + headers_len, body_available);
    req->body[body_available] = '\0';

    size_t body_received = body_available;
    while (body_received < content_length) {
        size_t remaining = content_length - body_received;
        ssize_t count    = read(conn->client_fd, req->body + body_received, remaining);
        if (count == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(500);
                continue;
            }
            perror("read");
            return false;
        } else if (count == 0) {
            perror("read");
            return false;
        }
        body_received += (size_t)count;
    }
    return true;
}

/*===============================================================
Request getters.
*/

// Returns request body or NULL if not available.
const char* req_body(connection_t* conn) {
    return conn->request->body;
}

const char* req_method(connection_t* conn) {
    return conn->request->method;
}

const char* req_path(connection_t* conn) {
    return conn->request->path;
}

// Get value for a query parameter if present or NULL.
const char* query_get(connection_t* conn, const char* name) {
    if (!conn->request->query_params) return NULL;  // no query params.
    return headers_get(conn->request->query_params, name);
}

headers_t* query_params(connection_t* conn) {
    return conn->request->query_params;
}

const char* req_header_get(connection_t* conn, const char* name) {
    return headers_get(conn->request->headers, name);
}

// Returns request body size. (Content-Length).
size_t req_content_len(connection_t* conn) {
    return conn->request->content_length;
}

/* ================================================================
 * Response Handling Functions
 * ================================================================ */

// Fast integer to string conversion for 3-digit HTTP status codes
static inline int format_status_code(char* restrict dest, int code) {
    dest[0] = '0' + (code / 100);
    dest[1] = '0' + ((code / 10) % 10);
    dest[2] = '0' + (code % 10);
    return 3;
}

const char* conn_set_status(connection_t* restrict conn, http_status code) {
    const status_info_t* status = get_http_status(code);
    response_t* res             = conn->response;
    res->status_code            = code;

    int written =
        snprintf(res->status_buf, STATUS_LINE_SIZE, "HTTP/1.1 %hu %s\r\n", code, status->text);

    // Make sure there is no overflow.
    assert(written > 0 && written < STATUS_LINE_SIZE);
    res->status_len = written;
    return status->text;
}

// Get the value of a response header. Returns a dynamically allocated char* pointer or NULL
// If header does not exist or malloc fails.
char* res_header_get(connection_t* conn, const char* name) {
    response_t* res = conn->response;
    char* buf       = res->headers_buf;

    // Terminate so we can use strstr.
    buf[res->headers_len] = '\0';
    char* ptr             = strstr(buf, name);
    if (!ptr) return NULL;  // Header not found

    // move past name, colon and space
    ptr += (strlen(name) + 2);

    // Find the next \r\n.
    char* value_end = strstr(ptr, "\r\n");
    if (!value_end) return NULL;  // Invalid header.

    size_t value_len = (size_t)(value_end - ptr);
    char* header     = malloc(value_len + 1);
    if (!header) return NULL;

    memcpy(header, ptr, value_len);
    header[value_len] = '\0';
    return header;
}

// Get the value of a response header, copying it into the buffer of size dest_size.
// Returns true on success or false if buffer is very small or header not found.
bool res_header_get_buf(connection_t* conn, const char* name, char* dest, size_t dest_size) {
    response_t* res = conn->response;
    char* buf       = res->headers_buf;

    // Terminate so we can use strstr.
    buf[res->headers_len] = '\0';
    char* ptr             = strstr(buf, name);
    if (!ptr) return NULL;  // Header not found

    // move past name, colon and space
    ptr += (strlen(name) + 2);

    // Find the next \r\n.
    char* value_end = strstr(ptr, "\r\n");
    if (!value_end) return NULL;  // Invalid header.

    size_t value_len = (size_t)(value_end - ptr);

    // Destination buffer is too small.
    if (dest_size <= value_len + 1) {
        return false;
    }

    memcpy(dest, ptr, value_len);
    dest[value_len] = '\0';
    return dest;
}

http_status res_get_status(connection_t* conn) {
    return conn->response->status_code;
}

void conn_writeheader(connection_t* conn, const char* name, const char* value) {
    // Calculate lengths once
    size_t name_len  = strlen(name);
    size_t value_len = strlen(value);

    // Check buffer space first
    response_t* resp = conn->response;
    size_t required  = name_len + value_len + 4;                  // ": \r\n"
    size_t remaining = HEADERS_BUF_SIZE - resp->headers_len - 3;  // Reserve for final \r\n

    if (required > remaining) {
        conn->closing = true;
        return;
    }

    // Build header directly in buffer
    char* dest = resp->headers_buf + resp->headers_len;
    memcpy(dest, name, name_len);
    dest += name_len;
    *dest++ = ':';
    *dest++ = ' ';
    memcpy(dest, value, value_len);
    dest += value_len;
    *dest++ = '\r';
    *dest++ = '\n';

    resp->headers_len += required;

    // Not necessary to be NULL-terminated. Perf->SLOW instruction
    // resp->headers_buf[resp->headers_len] = '\0';
}

void conn_writeheader_raw(connection_t* conn, const char* header, size_t length) {
    response_t* resp = conn->response;
    size_t remaining = HEADERS_BUF_SIZE - resp->headers_len - SAFETY_MARGIN;
    if (length > remaining) {
        conn->closing = true;  // Not enough space
        return;
    }

    memcpy(resp->headers_buf + resp->headers_len, header, length);
    resp->headers_len += length;

    // Not necessary to be NULL-terminated. Perf->SLOW instruction
    // resp->headers_buf[resp->headers_len] = '\0';
}

void conn_writeheaders_vec(connection_t* conn, const struct iovec* headers, size_t count) {
    response_t* resp = conn->response;

    // Calculate total length first
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++) {
        total_len += headers[i].iov_len;
    }

    size_t remaining = HEADERS_BUF_SIZE - resp->headers_len - SAFETY_MARGIN;
    if (total_len > remaining) {
        conn->closing = true;
        return;
    }

    // Copy all headers in one pass
    char* dest = resp->headers_buf + resp->headers_len;
    for (size_t i = 0; i < count; i++) {
        memcpy(dest, headers[i].iov_base, headers[i].iov_len);
        dest += headers[i].iov_len;
    }

    resp->headers_len += total_len;
}

void conn_set_content_type(connection_t* conn, const char* content_type) {
    if (HAS_CONTENT_TYPE(conn->response->flags)) {
        return;
    }

    conn_writeheader(conn, "Content-Type", content_type);
    SET_CONTENT_TYPE(conn->response->flags);
}

int conn_write(connection_t* conn, const void* data, size_t len) {
    response_t* res = conn->response;
    assert(res->type == ResponseTypeBuffer && "Must be in buffer response mode");
    BufferResponse* b = &res->state.buffer;

    size_t body_len = b->body_len;
    size_t required = body_len + len;

    // Fast path: stack buffer without allocation
    if (likely(!b->heap_allocated)) {
        if (required <= STACK_BUFFER_SIZE) {
            memcpy(b->body.stack + body_len, data, len);
            b->body_len += len;
            return (int)len;
        } else {
            // Need to migrate to heap - COPY FIRST before changing union state
            size_t heap_capacity = WRITE_BUFFER_SIZE;

            // Ensure heap capacity is sufficient
            while (heap_capacity < required) {
                // Check if we can safely double without overflow
                if (heap_capacity <= SIZE_MAX / 2) {
                    heap_capacity *= 2;
                } else {
                    // Can't double safely, check if we have enough room for required size
                    if (required > SIZE_MAX) {
                        fprintf(stderr, "Memory requirement exceeds maximum addressable space\n");
                        return -1;
                    }

                    // Set to required size (largest safe allocation)
                    heap_capacity = required;
                    break;
                }
            }

            uint8_t* heap_buffer = aligned_alloc(CACHE_LINE_SIZE, heap_capacity);
            if (!heap_buffer) {
                perror("aligned_alloc failed");
                return -1;
            }

            // Copy existing stack data to heap BEFORE changing union state
            memcpy(heap_buffer, b->body.stack, body_len);

            // Now safe to switch to heap mode
            b->heap_allocated = true;
            b->body_capacity  = heap_capacity;
            b->body.heap      = heap_buffer;
        }
    }

    // Heap path: ensure sufficient capacity
    if (required > b->body_capacity) {

        size_t new_capacity = b->body_capacity;
        while (new_capacity < required) {
            // Check for overflow before doubling
            if (new_capacity > SIZE_MAX / 2) {
                fprintf(stderr, "Memory requirement too large\n");
                return -1;
            }
            new_capacity *= 2;
        }

        uint8_t* new_buffer = realloc(b->body.heap, new_capacity);
        if (!new_buffer) {
            perror("realloc failed");
            return -1;
        }
        b->body.heap     = new_buffer;
        b->body_capacity = new_capacity;
    }

    memcpy(b->body.heap + body_len, data, len);
    b->body_len += len;
    return (int)len;
}

// Send a 404 response (StatusNotFound)
int conn_notfound(connection_t* conn) {
    conn_set_status(conn, StatusNotFound);
    conn_set_content_type(conn, PLAINTEXT_TYPE);
    return conn_write(conn, "404 Not Found", 13);
}

int conn_write_string(connection_t* conn, const char* str) {
    return str ? conn_write(conn, str, strlen(str)) : 0;
}

__attribute__((format(printf, 2, 3))) int conn_writef(connection_t* conn, const char* restrict fmt,
                                                      ...) {
    va_list args;
    char stack_buf[1024];
    char* heap_buf = NULL;
    int len, result;

    va_start(args, fmt);
    len = vsnprintf(stack_buf, sizeof(stack_buf), fmt, args);
    va_end(args);

    if (len < 0) return 0;  // formatting error.

    // If stack buffer was sufficient
    if (len < (int)sizeof(stack_buf)) {
        return conn_write(conn, stack_buf, (size_t)len);
    }

    // Need larger buffer - allocate exact size
    heap_buf = malloc((size_t)len + 1);
    if (!heap_buf) {
        perror("malloc");
        return 0;
    }

    va_start(args, fmt);
    vsnprintf(heap_buf, (size_t)len + 1, fmt, args);
    va_end(args);

    result = conn_write(conn, heap_buf, (size_t)len);
    free(heap_buf);
    return result;
}

void conn_abort(connection_t* conn) {
    conn->abort = true;
}

void conn_send(connection_t* conn, http_status status, const void* data, size_t length) {
    conn_set_status(conn, status);
    conn_write(conn, data, length);
}

void conn_send_json(connection_t* conn, http_status status, const char* json) {
    conn_writeheader_raw(conn, "Content-Type: application/json\r\n", 32);
    SET_CONTENT_TYPE(conn->response->flags);
    conn_send(conn, status, json, strlen(json));
}

void conn_send_html(connection_t* conn, http_status status, const char* html) {
    conn_writeheader_raw(conn, "Content-Type: text/html\r\n", 25);
    SET_CONTENT_TYPE(conn->response->flags);
    conn_send(conn, status, html, strlen(html));
}

void conn_send_text(connection_t* conn, http_status status, const char* text) {
    conn_writeheader_raw(conn, "Content-Type: text/plain\r\n", 26);
    SET_CONTENT_TYPE(conn->response->flags);
    conn_send(conn, status, text, strlen(text));
}

void conn_send_redirect(connection_t* conn, const char* location, bool permanent) {
    // Set status code
    conn_set_status(conn, permanent ? StatusMovedPermanently : StatusFound);

    response_t* resp    = conn->response;
    size_t location_len = strlen(location);
    size_t required     = 10 + location_len + 2;  // "Location: " + location + "\r\n"
    if (resp->headers_len + required >= HEADERS_BUF_SIZE - SAFETY_MARGIN) {
        conn->closing = true;
        return;
    }

    // Write header directly to buffer
    char* dest = resp->headers_buf + resp->headers_len;
    memcpy(dest, "Location: ", 10);
    dest += 10;
    memcpy(dest, location, location_len);
    dest += location_len;
    *dest++ = '\r';
    *dest++ = '\n';

    resp->headers_len += required;

    // Not necessary to be NULL-terminated. Perf->SLOW instruction
    // resp->headers_buf[resp->headers_len] = '\0';
}

void conn_send_xml(connection_t* conn, http_status status, const char* xml) {
    conn_writeheader_raw(conn, "Content-Type: application/xml\r\n", 31);
    SET_CONTENT_TYPE(conn->response->flags);
    conn_send(conn, status, xml, strlen(xml));
}

void conn_send_javascript(connection_t* conn, http_status status, const char* javascript) {
    conn_writeheader_raw(conn, "Content-Type: application/javascript\r\n", 38);
    SET_CONTENT_TYPE(conn->response->flags);
    conn_send(conn, status, javascript, strlen(javascript));
}

void conn_send_css(connection_t* conn, http_status status, const char* css) {
    conn_writeheader_raw(conn, "Content-Type: text/css\r\n", 24);
    SET_CONTENT_TYPE(conn->response->flags);
    conn_send(conn, status, css, strlen(css));
}

// Start SSE event.
void conn_start_sse(connection_t* conn) {
    // Set status and SSE headers
    conn_set_status(conn, StatusOK);

    static const char SSE_HEADERS[] =
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n";

    conn_writeheader_raw(conn, SSE_HEADERS, sizeof(SSE_HEADERS) - 1);
    SET_CONTENT_TYPE(conn->response->flags);
    SET_CHUNKED_TRANSFER(conn->response->flags);
}

void conn_start_chunked_transfer(connection_t* conn, int max_age_seconds) {
    // Set status and SSE headers
    conn_set_status(conn, StatusOK);

    static const char TRANS_HEADERS[] =
        "Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n";

    // Add cache headers
    conn_writef(conn, "Cache-Control: public, max-age=%d\r\n", max_age_seconds);

    conn_writeheader_raw(conn, TRANS_HEADERS, sizeof(TRANS_HEADERS) - 1);
    SET_CONTENT_TYPE(conn->response->flags);
    SET_CHUNKED_TRANSFER(conn->response->flags);
}

INLINE ssize_t writev_retry(int fd, struct iovec* iov, int iovcnt) {
    ssize_t total_written = 0;

    while (iovcnt > 0) {
        ssize_t written = writev(fd, iov, iovcnt);
        if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(500);
                continue;  // retry
            }
            return -1;  // permanent write error
        }

        total_written += written;

        // Advance iov based on bytes written
        ssize_t remaining = written;
        int i             = 0;
        for (; i < iovcnt && remaining > 0; ++i) {
            if ((size_t)remaining < iov[i].iov_len) {
                iov[i].iov_base = (char*)iov[i].iov_base + remaining;
                iov[i].iov_len -= (size_t)remaining;
                break;
            }
            remaining -= iov[i].iov_len;
        }

        // Move iov pointer and count forward
        iov += i;
        iovcnt -= i;
    }
    return total_written;
}

INLINE void write_server_headers(connection_t* conn) {
    char date_buf[64];
    int written;
    conn_writeheader_raw(conn, "Server: Pulsar/1.0\r\n", 20);
    written = strftime(date_buf, sizeof(date_buf), "Date: %a, %d %b %Y %H:%M:%S GMT\r\n",
                       gmtime(&conn->last_activity));
    conn_writeheader_raw(conn, date_buf, (size_t)written);
}

ssize_t conn_write_chunk(connection_t* conn, const void* data, size_t size) {
    struct iovec iov[6];
    int iovcnt = 0;

    char chunk_header[32];
    const char* trailer = "\r\n";

    // If headers not yet sent, send status line and headers first
    if (!HAS_HEADERS_WRITTEN(conn->response->flags)) {
#if WRITE_SERVER_HEADERS
        write_server_headers(conn);
#endif
        // We must have enough space for terminating \r\n and null.
        assert(conn->response->headers_len < HEADERS_BUF_SIZE - 3);
        memcpy(conn->response->headers_buf + conn->response->headers_len, "\r\n", 2);
        conn->response->headers_len += 2;

        // Not required to be NULL-terminated.
        // conn->response->headers_buf[HEADERS_BUF_SIZE - 1] = '\0';

        // Add status line first
        iov[iovcnt].iov_base = conn->response->status_buf;
        iov[iovcnt].iov_len  = conn->response->status_len;
        iovcnt++;

        // Then add headers
        iov[iovcnt].iov_base = conn->response->headers_buf;
        iov[iovcnt].iov_len  = conn->response->headers_len;
        iovcnt++;

        SET_HEADERS_WRITTEN(conn->response->flags);
    }

    // Final chunk?
    if (size == 0) {
        static const char final_chunk[] = "0\r\n\r\n";
        iov[iovcnt].iov_base            = (void*)final_chunk;
        iov[iovcnt].iov_len             = sizeof(final_chunk) - 1;
        iovcnt++;
        return writev_retry(conn->client_fd, iov, iovcnt);
    }

    // Regular chunk
    int header_len = snprintf(chunk_header, sizeof(chunk_header), "%zx\r\n", size);
    iov[iovcnt++]  = (struct iovec){.iov_base = chunk_header, .iov_len = (size_t)header_len};
    iov[iovcnt++]  = (struct iovec){.iov_base = (void*)data, .iov_len = size};
    iov[iovcnt++]  = (struct iovec){.iov_base = (void*)trailer, .iov_len = 2};

    return writev_retry(conn->client_fd, iov, iovcnt);
}

// SSE batch size.
#define BATCH_SIZE 4096

void conn_send_event(connection_t* conn, const sse_event_t* evt) {
    // Handle headers if not yet sent
    bool send_headers = false;
    if (!HAS_HEADERS_WRITTEN(conn->response->flags)) {
#if WRITE_SERVER_HEADERS
        write_server_headers(conn);
#endif
        assert(conn->response->headers_len < HEADERS_BUF_SIZE - 3);
        memcpy(conn->response->headers_buf + conn->response->headers_len, "\r\n", 2);
        conn->response->headers_len += 2;
        conn->response->headers_buf[conn->response->headers_len] = '\0';
        SET_HEADERS_WRITTEN(conn->response->flags);
        send_headers = true;
    }

    // Use larger buffer for batching - could be made configurable
    char batch_buf[BATCH_SIZE];
    size_t batch_pos = 0;

// Helper macro to flush buffer when needed
#define FLUSH_IF_NEEDED(needed_space)                                                              \
    do {                                                                                           \
        if (batch_pos + (needed_space) > BATCH_SIZE) {                                             \
            if (batch_pos > 0) {                                                                   \
                conn_write_chunk(conn, batch_buf, batch_pos);                                      \
                batch_pos = 0;                                                                     \
            }                                                                                      \
        }                                                                                          \
    } while (0)

    // Send headers first if needed
    if (send_headers) {
        struct iovec iov[2];
        int iovcnt = 0;

        iov[iovcnt++] = (struct iovec){.iov_base = conn->response->status_buf,
                                       .iov_len  = conn->response->status_len};
        iov[iovcnt++] = (struct iovec){
            .iov_base = conn->response->headers_buf,
            .iov_len  = conn->response->headers_len,
        };

        writev_retry(conn->client_fd, iov, iovcnt);
    }

    // Build event field
    if (evt->event && evt->event_len) {
        size_t needed = evt->event_len + 8;  // "event: " + "\n"
        FLUSH_IF_NEEDED(needed);

        batch_pos += (size_t)snprintf(batch_buf + batch_pos, BATCH_SIZE - batch_pos,
                                      "event: %.*s\n", (int)evt->event_len, evt->event);
    }

    // Build data field(s) - handle multiline data efficiently
    const char* data_ptr  = evt->data;
    size_t data_remaining = evt->data_len;

    while (data_remaining > 0) {
        const char* line_end = memchr(data_ptr, '\n', data_remaining);
        size_t line_len      = line_end ? (size_t)(line_end - data_ptr) : data_remaining;

        // Conservative space check: "data: " + line + "\n" + some margin
        size_t needed = line_len + 8;
        FLUSH_IF_NEEDED(needed);

        // Ensure we don't overflow the buffer
        size_t max_line = BATCH_SIZE - batch_pos - 8;
        if (line_len > max_line) {
            line_len = max_line;
        }

        batch_pos += (size_t)snprintf(batch_buf + batch_pos, BATCH_SIZE - batch_pos, "data: %.*s\n",
                                      (int)line_len, data_ptr);

        data_ptr += line_len;
        data_remaining -= line_len;

        // Skip the newline if we found one
        if (data_remaining > 0 && *data_ptr == '\n') {
            ++data_ptr;
            --data_remaining;
        }
    }

    // Build id field
    if (evt->id && evt->id_len) {
        size_t needed = evt->id_len + 5;  // "id: " + "\n"
        FLUSH_IF_NEEDED(needed);

        batch_pos += (size_t)snprintf(batch_buf + batch_pos, BATCH_SIZE - batch_pos, "id: %.*s\n",
                                      (int)evt->id_len, evt->id);
    }

    // Add event terminator
    FLUSH_IF_NEEDED(1);
    batch_buf[batch_pos++] = '\n';

    // Final flush
    if (batch_pos > 0) {
        conn_write_chunk(conn, batch_buf, batch_pos);
    }

#undef FLUSH_IF_NEEDED
}

// End chunked transfer (works for both SSE and generic chunked)
void conn_end_chunked_transfer(connection_t* conn) {
    conn_write_chunk(conn, NULL, 0);  // Send final chunk
}

// Alias for backward compatibility
void conn_end_sse(connection_t* conn) {
    conn_write_chunk(conn, NULL, 0);  // Send final chunk
}

// Returns true if connection is still open.
bool conn_is_open(connection_t* conn) {
    return conn && (conn->client_fd != -1 && !conn->closing);
}

// Parses the Range header and extracts start and end values
INLINE bool parse_range(const char* range_header, ssize_t* start, ssize_t* end,
                        bool* has_end_range) {
    if (strstr(range_header, "bytes=") != NULL) {
        if (sscanf(range_header, "bytes=%ld-%ld", start, end) == 2) {
            *has_end_range = true;
            return true;
        } else if (sscanf(range_header, "bytes=%ld-", start) == 1) {
            *has_end_range = false;
            return true;
        }
    }
    return false;
}

// Validates the requested range against the file size
INLINE bool validate_range(bool has_end_range, ssize_t* start, ssize_t* end, off64_t file_size) {
    if (!start || !end) return false;

    ssize_t start_byte = *start, end_byte = *end;
    ssize_t chunk_size = (4 * 1024 * 1024) - 1;  // 4 MB chunks.

    if (!has_end_range && start_byte >= 0) {
        end_byte = start_byte + chunk_size;
    } else if (start_byte < 0) {
        // Http range requests can be negative :) Wieird but true
        // I had to read the RFC to understand this, who would have thought?
        // https://datatracker.ietf.org/doc/html/rfc7233
        start_byte = file_size + start_byte;  // subtract from the file size
        end_byte =
            start_byte + chunk_size;  // send the next chunk size (if not more than the file size)
    } else if (end_byte < 0) {
        // Even the end range can be negative. Deal with it!
        end_byte = file_size + end_byte;
    }

    // Ensure the end of the range doesn't exceed the file size.
    if (end_byte >= file_size) {
        end_byte = file_size - 1;
    }

    // Ensure the start and end range are within the file size
    if (start_byte < 0 || end_byte < 0) {
        return false;
    }

    *start = start_byte;
    *end   = end_byte;
    return true;
}

// Write headers for the Content-Range, Accept-Ranges and content-length.
// Also sets the status code for partial content.
INLINE void send_range_headers(connection_t* conn, ssize_t start, ssize_t end, off64_t file_size) {
    static const char header_fmt[] =
        "Accept-Ranges: bytes\r\n"
        "Content-Length: %ld\r\n"
        "Content-Range: bytes %ld-%ld/%ld\r\n";

    response_t* resp      = conn->response;
    size_t remaining      = HEADERS_BUF_SIZE - resp->headers_len - SAFETY_MARGIN;
    size_t content_length = conn->request->method_type == HTTP_OPTIONS ? 0 : (size_t)file_size;

    // enough for above range headers
    if (remaining > 164) {
        char* dest = resp->headers_buf + resp->headers_len;
        int len =
            snprintf(dest, remaining, header_fmt, end - start + 1, start, end, content_length);
        if (len > 0 && (size_t)len < remaining) {
            resp->headers_len += len;
            return;
        }
    }

    // Not enough space in response buffer.
    conn->closing = true;
}

bool conn_servefile(connection_t* conn, const char* filename) {
    if (!filename) return false;

    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return false;
    }

    struct stat stat_buf;
    if (fstat(fd, &stat_buf) != 0) {
        perror("fstat");
        close(fd);
        return false;
    }

    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&stat_buf.st_mtime));
    conn_writeheader(conn, "Last-Modified", time_buf);

    // Set mime type if not already set
    if (!HAS_CONTENT_TYPE(conn->response->flags)) {
        const char* mimetype = get_mimetype((char*)filename);
        conn_set_content_type(conn, mimetype);
    }

    // Switch response type to file mode and initialize.
    conn->response->type = ResponseTypeFile;
    FileResponse* fr     = &conn->response->state.file;
    fr->file_fd          = fd;
    fr->file_size        = stat_buf.st_size;
    fr->file_offset      = 0;

    const char* range_header = headers_get(conn->request->headers, "Range");
    if (!range_header) {
        return true;
    }

    // If we have a "Range" request, modify offset and file size to serve correct range.
    ssize_t start_offset = 0, end_offset = 0;
    bool range_valid, has_end_range;
    if (parse_range(range_header, &start_offset, &end_offset, &has_end_range)) {
        range_valid = validate_range(has_end_range, &start_offset, &end_offset, stat_buf.st_size);
        if (!range_valid) {
            close(fd);
            conn_set_status(conn, StatusRequestedRangeNotSatisfiable);
            return false;
        }

        // Set status code
        conn_set_status(conn, StatusPartialContent);

        // Write range response headers.
        send_range_headers(conn, start_offset, end_offset, stat_buf.st_size);

        // Update file offset and size.
        fr->file_offset = start_offset;
        fr->file_size   = stat_buf.st_size;
        fr->max_range   = end_offset - start_offset + 1;
        SET_RANGE_REQUEST(conn->response->flags);
    }

    return true;
}

// Build the complete HTTP response
INLINE void finalize_response(connection_t* conn, HttpMethod method) {
    char contentLen[32];
    size_t contentLength = 0;

    response_t* resp = conn->response;
    if (resp->status_len == 0) conn_set_status(conn, StatusOK);

    // Write content length
    if (!HAS_RANGE_REQUEST(resp->flags) && method != HTTP_OPTIONS) {
        switch (resp->type) {
            case ResponseTypeBuffer:
                BufferResponse* br = &resp->state.buffer;
                contentLength      = br->body_len;
                break;
            case ResponseTypeFile:
                FileResponse* fr = &resp->state.file;
                contentLength    = fr->file_size;
                break;
        }

        snprintf(contentLen, sizeof(contentLen), "%zu", contentLength);
        conn_writeheader(conn, "Content-Length", contentLen);
    }

#if WRITE_SERVER_HEADERS
    write_server_headers(conn);
#endif

    assert(resp->headers_len < HEADERS_BUF_SIZE - SAFETY_MARGIN);

    // Terminate headers.
    memcpy(resp->headers_buf + resp->headers_len, "\r\n", 2);
    resp->headers_len += 2;
    resp->headers_buf[HEADERS_BUF_SIZE - 1] = '\0';
}

void static_file_handler(connection_t* conn) {
    route_t* route      = conn->request->route;
    const char* path    = conn->request->path;
    const char* dirname = route->dirname;
    size_t dirlen       = route->dirname_len;
    size_t pattern_len  = route->pattern_len;

    // Early validation - single exit point for malicious paths
    bool is_malicious = is_malicious_path(path);

    // Calculate static path pointer and length
    const char* static_ptr = path + pattern_len;
    size_t static_len      = strlen(static_ptr);

    // Skip leading slash
    static_ptr += (*static_ptr == '/');
    static_len -= (*static_ptr == '/');

    // Validate all path lengths at once
    bool path_too_long =
        (dirlen >= PATH_MAX) | (static_len >= PATH_MAX) | ((dirlen + static_len + 2) >= PATH_MAX);

    // Determine response type based on validation
    enum { RESP_MALICIOUS = 1, RESP_TOO_LONG = 2, RESP_PROCESS = 3 } response_type = RESP_PROCESS;

    response_type = is_malicious ? RESP_MALICIOUS : response_type;
    response_type = path_too_long ? RESP_TOO_LONG : response_type;

    // Pre-allocate buffers to improve cache locality
    char filepath[PATH_MAX]   = {0};
    char index_file[PATH_MAX] = {0};

    // Process file path construction and serving
    bool file_served = false;
    bool file_found  = false;

    if (response_type == RESP_PROCESS) {
        // Build file path
        bool is_different_prefix = strncmp(static_ptr, route->pattern, pattern_len) != 0;
        bool needs_slash         = (dirlen > 0) & (dirname[dirlen - 1] != '/');

        int pathLen =
            snprintf(filepath, PATH_MAX, "%.*s%s%.*s", (int)dirlen, dirname,
                     (is_different_prefix & needs_slash) ? "/" : "", (int)static_len, static_ptr);

        bool valid_path = (pathLen >= 0) & (pathLen < PATH_MAX);

        if (valid_path) {
            // URL decode if needed
            bool needs_decode = (strstr(filepath, "%") != NULL || strstr(filepath, "+") != NULL);
            if (needs_decode) {
                url_percent_decode(filepath, filepath, (size_t)pathLen, PATH_MAX);
            }

            // Check if direct file exists
            file_found = is_file(filepath);

            if (!file_found) {
                // Try index.html
                int index_len = snprintf(index_file, sizeof(index_file), "%s/index.html", filepath);
                bool valid_index = (index_len >= 0) & (index_len < PATH_MAX);
                file_found       = valid_index & is_file(index_file);
            }
        }
    }

    // Single branching point for all responses
    switch (response_type) {
        case RESP_MALICIOUS:
            conn_notfound(conn);
            break;

        case RESP_TOO_LONG:
            conn_set_status(conn, StatusRequestURITooLong);
            conn_set_content_type(conn, "text/html");
            conn_write_string(conn, "<h1>Path too long</h1>");
            break;

        case RESP_PROCESS:
            if (file_found) {
                // Determine which file to serve and content type
                const char* serve_file   = filepath;
                const char* content_type = get_mimetype(filepath);

                // Use index.html if original file wasn't found
                if (!is_file(filepath)) {
                    serve_file   = index_file;
                    content_type = "text/html";
                }

                conn_set_content_type(conn, content_type);
                file_served = conn_servefile(conn, serve_file);

                if (!file_served) {
                    conn_set_status(conn, StatusInternalServerError);
                    conn_set_content_type(conn, "text/html");
                    conn_write_string(conn, "<h1>Error serving file</h1>");
                }
            } else {
                conn_notfound(conn);
            }
            break;
    }
}

const char* get_path_param(connection_t* conn, const char* name) {
    if (!name) return NULL;
    route_t* route = conn->request->route;
    if (!route) return NULL;

    PathParams* path_params = route->path_params;
    for (size_t i = 0; i < path_params->match_count; i++) {
        if (strcmp(path_params->params[i].name, name) == 0) {
            return path_params->params[i].value;
        }
    }
    return NULL;
}

INLINE void execute_all_middleware(connection_t* conn, route_t* route) {
#define EXECUTE_MIDDLEWARE(mw, count)                                                              \
    do {                                                                                           \
        size_t index = 0;                                                                          \
        if (count > 0) {                                                                           \
            while (index < count) {                                                                \
                mw[index++](conn);                                                                 \
                if (conn->abort) {                                                                 \
                    return;                                                                        \
                }                                                                                  \
            }                                                                                      \
        }                                                                                          \
    } while (0)

    EXECUTE_MIDDLEWARE(global_middleware, global_mw_count);
    EXECUTE_MIDDLEWARE(route->middleware, route->mw_count);
#undef EXECUTE_MIDDLEWARE
}

void use_global_middleware(HttpHandler* middleware, size_t count) {
    if (count == 0) return;
    ASSERT(count + global_mw_count <= MAX_GLOBAL_MIDDLEWARE);

    for (size_t i = 0; i < count; i++) {
        global_middleware[global_mw_count++] = middleware[i];
    }
}

void use_route_middleware(route_t* route, HttpHandler* middleware, size_t count) {
    if (count == 0) return;
    ASSERT(route->mw_count + count <= MAX_ROUTE_MIDDLEWARE);

    for (size_t i = 0; i < count; i++) {
        route->middleware[route->mw_count++] = middleware[i];
    }
}

void pulsar_set_callback(PulsarCallback cb) {
    LOGGER_CALLBACK = cb;
}

bool pulsar_set_context_value(connection_t* conn, const char* key, void* value,
                              ValueFreeFunc free_func) {
    return LocalsSetValue(conn->locals, key, value, free_func);
}

void* pulsar_get_context_value(connection_t* conn, const char* key) {
    return LocalsGetValue(conn->locals, key);
}

void pulsar_delete_context_value(connection_t* conn, const char* key) {
    LocalsRemove(conn->locals, key);
}

#if ENABLE_LOGGING
INLINE void post_request_logger(connection_t* conn) {
    if (LOGGER_CALLBACK) {
        struct timespec end;
        clock_gettime(CLOCK_MONOTONIC_COARSE, &end);

        uint64_t start_ns =
            (uint64_t)conn->start.tv_sec * 1000000000ULL + (size_t)conn->start.tv_nsec;
        uint64_t end_ns     = (uint64_t)end.tv_sec * 1000000000ULL + (size_t)end.tv_nsec;
        uint64_t latency_ns = end_ns - start_ns;
        LOGGER_CALLBACK(conn, latency_ns);
    }
}
#endif

// Support for dynamic sscanf string size.
#define FORMAT(S)   "%" #S "s"
#define RESOLVE(S)  FORMAT(S)
#define STATUS_LINE ("%7s" RESOLVE(MAX_PATH_LEN) "%15s")

__attribute_warn_unused_result__ INLINE http_status process_request(connection_t* conn,
                                                                    size_t read_bytes,
                                                                    KeepAliveState* state,
                                                                    int queue_fd) {
    // replace with memmem for safety(but slower)
    char* end_of_headers = strstr(conn->read_buf, "\r\n\r\n");
    if (!end_of_headers) {
        return StatusBadRequest;
    }

    size_t headers_len = (size_t)(end_of_headers - conn->read_buf) + 4;
    char url[MAX_PATH_LEN + 1];
    url[0] = '\0';

    char http_protocol[16] = {0};
    if (sscanf(conn->read_buf, STATUS_LINE, conn->request->method, url, http_protocol) != 3) {
        return StatusBadRequest;
    }

    // Percent-decode the URL into connection request path.
    // src, dest, src_len, dst_len.
    url_percent_decode(url, conn->request->path, strlen(url), MAX_PATH_LEN);

    // Validate HTTP version. We only support http 1.1
    if (strcmp(http_protocol, "HTTP/1.1") != 0) {
        return StatusHTTPVersionNotSupported;
    }

    conn->request->method_type = http_method_from_string(conn->request->method);
    if (!METHOD_VALID(conn->request->method_type)) {
        return StatusMethodNotAllowed;
    }

    if (!parse_query_params(conn)) {
        return StatusInternalServerError;
    }

    // We need to parse the headers even for 404.
    if (!parse_request_headers(conn, conn->request->method_type, headers_len)) {
        return StatusInternalServerError;
    };

    route_t* route = route_match(conn->request->path, conn->request->method_type);
    if (route) {
        conn->request->route = route;
        if (!parse_request_body(conn, headers_len, read_bytes)) {
            return StatusInternalServerError;
        }
    }

    if (route) {
        // Prefetch response and buffer
        __builtin_prefetch(conn->response, 0, 3);
        execute_all_middleware(conn, route);
        if (!conn->abort) {
            route->handler(conn);
        }
    } else {
        return StatusNotFound;
    }

    // Chunked transfer is handled by the handler directly outside event loop.
    if (HAS_CHUNKED_TRANSFER(conn->response->flags)) {
        if (conn->keep_alive) {
            conn->last_activity = time(NULL);
            AddKeepAliveConnection(conn, state);
            conn->closing = true;
            if (reset_connection(conn)) {
                conn->closing = (event_mod_read(queue_fd, conn->client_fd, conn) < 0);
            }
        }
#if ENABLE_LOGGING
        post_request_logger(conn);
#endif
    } else {
        finalize_response(conn, conn->request->method_type);
        conn->last_activity = time(NULL);
        // Switch to writing response.
    }
    return StatusOK;
}

/* ================================================================
 * Socket and Connection I/O Functions
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

    int fd;
    int opt               = 1;
    struct addrinfo hints = {0};
    struct addrinfo *result, *rp;

    hints.ai_family    = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype  = SOCK_STREAM;  // TCP
    hints.ai_flags     = AI_PASSIVE;   // For wildcard IP address
    hints.ai_protocol  = 0;            /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr      = NULL;
    hints.ai_next      = NULL;

    // Convert port to string for getaddrinfo
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    // Resolve host (or use INADDR_ANY if NULL)
    int ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        exit(EXIT_FAILURE);
    }

    // Try each address until we successfully bind
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) continue;

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
            perror("setsockopt");
            close(fd);
            continue;
        }

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;  // Success

        close(fd);
    }

    freeaddrinfo(result);

    if (rp == NULL) {
        fprintf(stderr, "Could not bind to %s:%d\n", host ? host : "*", port);
        exit(EXIT_FAILURE);
    }

    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return fd;
}

INLINE int conn_accept(int worker_id) {
    (void)worker_id;

    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Accept with fast path (Linux 4.3+)
#ifdef __linux__
    client_fd = accept4(server_fd, (struct sockaddr*)&client_addr, &client_addr_len, SOCK_NONBLOCK);
#else
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
#endif

    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("accept");
        }
        return -1;
    }

#ifndef __linux__
    set_nonblocking(client_fd);
#endif

    // Set socket timeouts - CRITICAL for preventing hanging connections
    struct timeval read_timeout  = {.tv_sec  = 30,  // 30 second read timeout
                                    .tv_usec = 0};
    struct timeval write_timeout = {.tv_sec  = 30,  // 30 second write timeout
                                    .tv_usec = 0};

    if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
    }

    if (setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &write_timeout, sizeof(write_timeout)) < 0) {
        perror("setsockopt SO_SNDTIMEO");
    }

    // Set high-performance options
    int yes = 1;
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) < 0) {
        perror("setsockopt TCP_NODELAY");
    }

    // Set TCP keepalive to detect dead connections
    if (setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) < 0) {
        perror("setsockopt SO_KEEPALIVE");
    }

#ifdef __linux__
    // Configure keepalive parameters
    int keepalive_idle     = 120;  // Start probes after 2 minutes of inactivity
    int keepalive_interval = 15;   // Send probe every 15 seconds
    int keepalive_count    = 3;    // Close after 3 failed probes

    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_idle, sizeof(keepalive_idle));
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_interval,
               sizeof(keepalive_interval));
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_count, sizeof(keepalive_count));

    // Additional Linux-specific optimizations
    // Enable TCP Fast Open (if configured)
    setsockopt(client_fd, SOL_TCP, TCP_FASTOPEN, &yes, sizeof(yes));

    // Enable TCP Quick ACK
    setsockopt(client_fd, IPPROTO_TCP, TCP_QUICKACK, &yes, sizeof(yes));

    // Set user timeout (total time for unacknowledged data)
    unsigned int user_timeout = 60000;  // 60 seconds in milliseconds
    setsockopt(client_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout, sizeof(user_timeout));

    // Set maximum segment size
    int mss = 1460;  // Standard Ethernet MTU - headers
    setsockopt(client_fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));

    // Optimize buffer sizes for high throughput
    int rcv_bufsize = 256 * 1024;  // 256KB receive buffer (reduced from 1MB)
    int snd_bufsize = 256 * 1024;  // 256KB send buffer (reduced from 1MB)
    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &rcv_bufsize, sizeof(rcv_bufsize));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &snd_bufsize, sizeof(snd_bufsize));
#endif

// BSD/Darwin optimizations
#if defined(__APPLE__) || defined(__FreeBSD__)
    // Disable SIGPIPE generation
    setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));

    // Enable TCP_NOPUSH (similar to TCP_CORK)
    setsockopt(client_fd, IPPROTO_TCP, TCP_NOPUSH, &yes, sizeof(yes));

    // BSD keepalive settings
#ifdef TCP_KEEPIDLE
    int keepalive_idle = 120;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_idle, sizeof(keepalive_idle));
#endif
#ifdef TCP_KEEPINTVL
    int keepalive_interval = 15;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_interval,
               sizeof(keepalive_interval));
#endif
#ifdef TCP_KEEPCNT
    int keepalive_count = 3;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_count, sizeof(keepalive_count));
#endif
#endif

    return client_fd;
}

/* ================================================================
 * Socket and Connection I/O Functions
 * ================================================================ */

INLINE void add_connection_to_worker(int queue_fd, int client_fd) {
    connection_t* conn = malloc(sizeof(connection_t));
    if (!conn) {
        perror("malloc");
        close(client_fd);
        return;
    }

    Arena* arena = arena_create(ARENA_CAPACITY);
    if (!arena) {
        fprintf(stderr, "arena_create failed\n");
        close(client_fd);
        free(conn);
        return;
    }

    if (!init_connection(conn, arena, client_fd)) {
        fprintf(stderr, "init_connection failed\n");
        close(client_fd);
        free(conn);
        return;
    }

    if (event_add_read(queue_fd, client_fd, conn) < 0) {
        perror("event_add_read");
        conn->closing = true;
        return;
    }
}

INLINE void handle_read(int queue_fd, connection_t* conn, KeepAliveState* state) {
    // Read the headers into connection buffer.
    ssize_t bytes_read = read(conn->client_fd, conn->read_buf, READ_BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        // connection reset by peer
        // or EWOULDBLOCK (Should not happen since socket is ready to read)
        conn->closing = true;
        return;
    }
    conn->read_buf[bytes_read] = '\0';

    // Process the request and parse the headers / query params.
    http_status status;
    if ((status = process_request(conn, (size_t)bytes_read, state, queue_fd)) != StatusOK) {
        send_error_response(conn, status);
        return;
    };

    // Switch to writing response.
    if (event_mod_write(queue_fd, conn->client_fd, conn) < 0) {
        perror("event_mod_write");
        conn->closing = true;
    }
}

// ==================== Response Writers===============================
/** Maximum chunk size for file transfers (1MB). */
#define MAX_CHUNK_SIZE 4096

/** Thread-local buffer for fallback file operations. */
#if !defined(__linux__) && !defined(__APPLE__) && defined(__FreeBSD__)
static thread_local char file_buffer[MAX_CHUNK_SIZE];
#endif

INLINE void handle_write_error(connection_t* conn, const char* operation) {
    // Only mark for closing if it's a persistent error, not transient ones
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        // Ignore EPIPE (broken pipe), which just means client disconnected
        if (errno != EPIPE) {
            perror(operation);
        }
        conn->closing = true;
    }
}

/**
 * Completes request processing and handles connection state transitions.
 * @param conn The connection that completed processing.
 * @param queue_fd Event queue file descriptor.
 * @param state Keep-alive state manager.
 */
INLINE void complete_request(connection_t* conn, int queue_fd, KeepAliveState* state) {

#if ENABLE_LOGGING
    post_request_logger(conn);
#endif

    if (!conn->keep_alive) {
        conn->closing = true;
        return;
    }

    // Keep the connection in keep-alive linked list
    conn->last_activity = time(NULL);
    AddKeepAliveConnection(conn, state);

    // Reset connection state
    if (!reset_connection(conn)) {
        conn->closing = true;
        return;
    }

    // Re-arm EPOLL to resume reading
    if (event_mod_read(queue_fd, conn->client_fd, conn) == -1) {
        conn->closing = true;
        return;
    }
}

/**
 * Updates the retry counters after a partial write operation.
 * @param res Response containing retry state.
 * @param sent Total bytes sent.
 * @param status_len Length of status line segment.
 * @param headers_len Length of headers segment.
 * @param body_len Length of body segment.
 */
INLINE void update_retry_counters(response_t* res, size_t sent, size_t status_len,
                                  size_t headers_len, size_t body_len) {
    size_t remaining = sent;

    // Update status_sent
    if (remaining > 0) {
        size_t segment = MIN(remaining, status_len);
        res->retry.status_sent += segment;
        remaining -= segment;
    }

    // Update headers_sent
    if (remaining > 0) {
        size_t segment = MIN(remaining, headers_len);
        res->retry.headers_sent += segment;
        remaining -= segment;
    }

    // Update body_sent
    if (remaining > 0) {
        size_t segment = MIN(remaining, body_len);
        res->retry.body_sent += segment;
    }
}

/**
 * Writes response headers (status line + headers) using vectored I/O.
 * @param res Response containing header data.
 * @param client_fd Client socket file descriptor.
 * @return Number of bytes sent, or -1 on error.
 */
INLINE ssize_t write_file_response_headers(response_t* res, int client_fd) {
    // Calculate remaining bytes for each segment
    size_t status_remaining  = res->status_len - res->retry.status_sent;
    size_t headers_remaining = res->headers_len - res->retry.headers_sent;

    // If everything is already sent, mark headers as written
    if (status_remaining == 0 && headers_remaining == 0) {
        SET_HEADERS_WRITTEN(res->flags);
        return 0;
    }

    struct iovec iov[2] = {
        {.iov_base = res->status_buf + res->retry.status_sent, .iov_len = status_remaining},
        {.iov_base = res->headers_buf + res->retry.headers_sent, .iov_len = headers_remaining}};

    ssize_t sent = writev(client_fd, iov, 2);
    if (sent <= 0) {
        return sent;  // Error or no bytes sent
    }

    // Update retry counters for the amount actually sent
    update_retry_counters(res, (size_t)sent, status_remaining, headers_remaining, 0);

    // Check if all headers have been sent
    if (res->retry.status_sent == res->status_len && res->retry.headers_sent == res->headers_len) {
        SET_HEADERS_WRITTEN(res->flags);
    }

    return sent;
}

/**
 * Platform-specific file transfer using the most efficient method available.
 * @param client_fd Client socket file descriptor.
 * @param file_fd Source file descriptor.
 * @param offset Current file offset (updated on success).
 * @param chunk_size Number of bytes to transfer.
 * @return Number of bytes sent, or -1 on error.
 */
INLINE ssize_t send_chunk(int client_fd, int file_fd, off_t* offset, off_t chunk_size) {
#if defined(__linux__)
    // Linux: Use zero-copy sendfile
    return sendfile(client_fd, file_fd, offset, (size_t)chunk_size);

#elif defined(__APPLE__) || defined(__FreeBSD__)
    // BSD: Use BSD-style sendfile
    off_t len  = chunk_size;
    int result = sendfile(file_fd, client_fd, *offset, &len, NULL, 0);
    if (result == 0 || (result == -1 && errno == EAGAIN)) {
        *offset += len;
        return len;
    }
    return -1;

#else
    // Fallback: Read then write for other systems
    chunk_size = MIN(chunk_size, (off_t)sizeof(file_buffer));

    ssize_t read_bytes = pread(file_fd, file_buffer, (size_t)chunk_size, *offset);
    if (read_bytes <= 0) {
        errno = (read_bytes == 0) ? EIO : errno;
        return -1;
    }

    ssize_t sent = write(client_fd, file_buffer, (size_t)read_bytes);
    if (sent > 0) {
        *offset += sent;
    }
    return sent;
#endif
}

/**
 * Handles file-based response writing with platform-optimized transfer.
 * @param queue_fd Event queue file descriptor.
 * @param conn Connection handling the response.
 * @param state Keep-alive state manager.
 */
INLINE void handle_file_write(int queue_fd, connection_t* conn, KeepAliveState* state) {
    response_t* res  = conn->response;
    FileResponse* fr = &res->state.file;
    ssize_t sent     = -1;
    bool is_range    = HAS_RANGE_REQUEST(res->flags);

    // Write headers if not already done
    if (!HAS_HEADERS_WRITTEN(res->flags)) {
        sent = write_file_response_headers(res, conn->client_fd);
        if (sent < 0) {
            handle_write_error(conn, "header write failed");
            return;
        }
        if (sent == 0) {
            return;  // Socket buffer full, wait for next write event
        }
    }

    // Keep sending data until done.
    while (1) {
        // Calculate remaining file data
        off_t remaining = fr->file_size - fr->file_offset;
        if (remaining <= 0) {
            close(fr->file_fd);
            fr->file_fd = -1;
            complete_request(conn, queue_fd, state);
            return;
        }

        off_t chunk_size = is_range ? (off_t)MIN(MAX_CHUNK_SIZE, (size_t)remaining) : remaining;
        off_t offset     = (off_t)fr->file_offset;
        sent             = send_chunk(conn->client_fd, fr->file_fd, &offset, chunk_size);
        if (sent < 0) {
            close(fr->file_fd);
            fr->file_fd = -1;
            handle_write_error(conn, "file transfer failed");
            return;
        }

        if (sent == 0) {
            return;  // Socket buffer full, wait for next write event
        }
        fr->file_offset += offset;

        // Check if transfer is complete
        if (fr->file_offset >= fr->file_size) {
            complete_request(conn, queue_fd, state);
        }
    }
}

/**
 * Handles buffer-based response writing using vectored I/O.
 * @param queue_fd Event queue file descriptor.
 * @param conn Connection handling the response.
 * @param state Keep-alive state manager.
 */
INLINE void handle_buffer_write(int queue_fd, connection_t* conn, KeepAliveState* state) {
    response_t* res    = conn->response;
    BufferResponse* br = &res->state.buffer;

    while (1) {
        // Set up vectored I/O for remaining data
        struct iovec iov[3] = {// Status line remaining
                               {.iov_base = res->status_buf + res->retry.status_sent,
                                .iov_len  = res->status_len - res->retry.status_sent},
                               // Headers remaining
                               {.iov_base = res->headers_buf + res->retry.headers_sent,
                                .iov_len  = res->headers_len - res->retry.headers_sent},
                               // Body remaining
                               {.iov_base = (br->heap_allocated ? br->body.heap : br->body.stack) +
                                            res->retry.body_sent,
                                .iov_len = br->body_len - res->retry.body_sent}};

        ssize_t sent = writev(conn->client_fd, iov, 3);
        if (sent < 0) {
            handle_write_error(conn, "buffer write failed");
            return;
        }

        if (sent == 0) {
            return;  // Socket buffer full, wait for next write event
        }

        // Update retry counters based on what was actually sent
        update_retry_counters(res, (size_t)sent, iov[0].iov_len, iov[1].iov_len, iov[2].iov_len);

        // Check if all data has been sent
        bool complete = (res->retry.status_sent == res->status_len) &&
                        (res->retry.headers_sent == res->headers_len) &&
                        (res->retry.body_sent == br->body_len);

        conn->last_activity = time(NULL);

        if (complete) {
            complete_request(conn, queue_fd, state);
            return;
        }

        // Continue the loop to send remaining data
    }
}

/* ================================================================
 * Updated Worker Thread Functions
 * ================================================================ */

typedef struct {
    int queue_fd;
    int worker_id;
    int designated_core;
    KeepAliveState* keep_alive_state;
} WorkerData;

int pin_current_thread_to_core(int core_id) {
    // Get and validate core count
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores <= 0) num_cores = 1;

    if (core_id < 0 || core_id >= (int)num_cores) {
        fprintf(stderr, "Invalid core_id %d (available: 0-%ld)\n", core_id, num_cores - 1);
        return -1;
    }

#if defined(__linux__) || defined(__FreeBSD__)
/* Common implementation for Linux and FreeBSD */
#if defined(__linux__)
    cpu_set_t cpuset;
#else
    cpuset_t cpuset;
#endif

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) != 0) {
        perror("Failed to set CPU affinity");
        return -1;
    }

#elif defined(__APPLE__)
    /* macOS-specific implementation using exact API signature */
    thread_port_t thread                 = pthread_mach_thread_np(pthread_self());
    thread_affinity_policy_data_t policy = {core_id};
    kern_return_t ret = thread_policy_set(thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy,
                                          THREAD_AFFINITY_POLICY_COUNT);

    if (ret != KERN_SUCCESS) {
        mach_error("thread_policy_set failed:", ret);
        return -1;
    }
#else
#pragma message("CPU affinity not supported on this platform")
    return -1;
#endif

    return 0;
}

void* worker_thread(void* arg) {
    WorkerData* worker       = (WorkerData*)arg;
    int queue_fd             = worker->queue_fd;
    int worker_id            = worker->worker_id;
    int cpu_core             = worker->designated_core;
    KeepAliveState* ka_state = worker->keep_alive_state;

    pin_current_thread_to_core(cpu_core);

    if (event_add_server(queue_fd, server_fd) < 0) {
        perror("event_add_server");
        return NULL;
    }

    event_t events[MAX_EVENTS] = {0};
    long last_timeout_check    = 0;

    while (server_running) {
        // Check for Keep-Alive timeouts every 5 seconds.
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
        if (now.tv_sec - last_timeout_check >= 5) {
            CheckKeepAliveTimeouts(ka_state, worker_id, queue_fd);
            last_timeout_check = now.tv_sec;
        }

        int num_events = event_wait(queue_fd, events, MAX_EVENTS, 500);
        if (num_events == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("event_wait");
            continue;
        }

        // During graceful shutdown, don't accept new connections
        // but continue processing existing ones
        for (int i = 0; i < num_events; i++) {
            const event_t* event = &events[i];

            if (event_get_fd(event) == server_fd) {
                int client_fd = conn_accept(worker_id);
                if (client_fd > 0) {
                    add_connection_to_worker(queue_fd, client_fd);
                }
            } else {
                connection_t* conn = (connection_t*)event_get_data(event);
                if (!conn) continue;

                if (event_is_read(event)) {
                    handle_read(queue_fd, conn, ka_state);
                } else if (event_is_write(event)) {
                    switch (conn->response->type) {
                        case ResponseTypeBuffer:
                            handle_buffer_write(queue_fd, conn, ka_state);
                            break;
                        case ResponseTypeFile:
                            handle_file_write(queue_fd, conn, ka_state);
                            break;
                    }
                } else if (event_is_error(event)) {
                    conn->closing = true;
                }

                if (conn->closing) {
                    close_connection(queue_fd, conn, ka_state);
                }
            }
        }
    }

    // Remove server socket from event queue
    event_delete(queue_fd, server_fd);
    close(queue_fd);
    return NULL;
}

int pulsar_run(const char* addr, int port) {
    server_fd = create_server_socket(addr, port);
    set_nonblocking(server_fd);

    pthread_t workers[NUM_WORKERS]                = {0};
    WorkerData worker_data[NUM_WORKERS]           = {0};
    KeepAliveState keep_alive_states[NUM_WORKERS] = {0};

    install_signal_handler();
    sort_routes();
    init_mimetypes();

#if defined(__linux__)
    // Tune malloc.
    mallopt(M_MMAP_THRESHOLD, 128 * 1024);  // Larger allocations use mmap
    mallopt(M_TRIM_THRESHOLD, 128 * 1024);  // More aggressive trimming
#endif                                      /* PULSAR_H */

    // When creating worker threads
    int num_cores      = get_num_available_cores();
    int reserved_cores = 1;  // Leave one core free

    // Initialize worker data and create workers
    for (size_t i = 0; i < NUM_WORKERS; i++) {
        int queue_fd = event_queue_create();
        if (queue_fd == -1) {
            perror("event_queue_create");
            exit(EXIT_FAILURE);
        }

        worker_data[i].queue_fd         = queue_fd;
        worker_data[i].worker_id        = i;
        worker_data[i].designated_core  = i % ((size_t)(num_cores - reserved_cores));
        worker_data[i].keep_alive_state = &keep_alive_states[i];

        if (pthread_create(&workers[i], NULL, worker_thread, &worker_data[i])) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    const char* event_system = USE_EPOLL ? "epoll" : "kqueue";
    printf("\n\nStarting server with %d workers (%s)\n", NUM_WORKERS, event_system);
    printf("Listening on http://%s:%d\n", addr ? addr : "0.0.0.0", port);

    // Wait for all worker threads to exit.
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    // Close server socket
    close(server_fd);
    return 0;
}
