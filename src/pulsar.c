#include "../include/pulsar.h"
#include "../include/common.h"
#include "../include/events.h"

static int server_fd                                        = -1;    // Server socket file descriptor
volatile sig_atomic_t server_running                        = 1;     // Server running flag
static HttpHandler global_middleware[MAX_GLOBAL_MIDDLEWARE] = {0};   // Global middleware array
static size_t global_mw_count                               = 0;     // Global middleware count
static PulsarCallback LOGGER_CALLBACK                       = NULL;  // No logger callback by default.

typedef struct __attribute__((aligned(64))) KeepAliveState {
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
            printf("Worker %d: closing timeout connection: %p\n", worker_id, (void*)current);
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

INLINE response_t* create_response(Arena* arena) {
    response_t* resp = arena_alloc(arena, sizeof(response_t));
    if (!resp) return NULL;

    memset(resp, 0, sizeof(response_t));
    resp->heap_allocated = false;
    resp->body.stack[0]  = '\0';
    resp->body_capacity  = 0;
    resp->file_fd        = -1;
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

    if (resp->heap_allocated && resp->body.heap) {
        free(resp->body.heap);
        resp->body.heap = NULL;
    }
}

INLINE bool init_connection(connection_t* conn, Arena* arena, int client_fd) {
    conn->closing       = false;
    conn->client_fd     = client_fd;
    conn->keep_alive    = true;
    conn->in_keep_alive = false;
    conn->abort         = false;
    conn->last_activity = time(NULL);
    conn->response      = create_response(arena);
    conn->read_buf      = arena_alloc(arena, READ_BUFFER_SIZE);
    conn->request       = create_request(arena);
    conn->locals        = arena_alloc(arena, sizeof(Locals));
    if (conn->locals) {
        LocalsInit(conn->locals);
    }
    conn->arena = arena;
#if ENABLE_LOGGING
    clock_gettime(CLOCK_MONOTONIC, &conn->start);
#endif

    conn->next = NULL;
    conn->prev = NULL;
    return (conn->request && conn->response && conn->read_buf && conn->locals);
}

INLINE bool reset_connection(connection_t* conn) {
    conn->closing    = false;
    conn->keep_alive = true;    // Default to Keep-Alive
    conn->abort      = false;   // Connection not aborted
    free(conn->request->body);  // Free request body.

    // Reset response buffer before resetting arena.
    if (conn->response->heap_allocated) {
        free(conn->response->body.heap);
    }
    arena_reset(conn->arena);

#if ENABLE_LOGGING
    clock_gettime(CLOCK_MONOTONIC, &conn->start);
#endif
    conn->request  = create_request(conn->arena);
    conn->response = create_response(conn->arena);
    conn->read_buf = arena_alloc(conn->arena, READ_BUFFER_SIZE);
    LocalsReset(conn->locals);

    // Don't reset these fields if connection is in keep-alive list
    if (!conn->in_keep_alive) {
        conn->next = NULL;
        conn->prev = NULL;
    }
    return (conn->request && conn->response && conn->read_buf);
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

INLINE bool parse_request_headers(connection_t* restrict conn, HttpMethod method, size_t headers_len) {
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
        const char* const colon = (const char*)memchr(ptr, ':', end - ptr);
        if (!colon) break;

        const size_t name_len = colon - ptr;

        // Move to header value (combine pointer arithmetic)
        const char* value_start = colon + 1;
        while (value_start < end && *value_start == ' ')
            value_start++;

        // Parse header value
        const char* const eol = (const char*)memchr(value_start, '\r', end - value_start);
        if (!eol || eol + 1 >= end || eol[1] != '\n') break;

        const size_t value_len = eol - value_start;

        // Check for special headers with minimal branching
        if (name_len == 14 && !(flags & 1) && !is_safe) {
            // Check Content-Length (most common case first)
            if (strncasecmp(ptr, "Content-Length", 14) == 0) {
                bool content_len_valid;
                char temp_buf[32];  // Enough for max uint64_t
                if (value_len < sizeof(temp_buf)) {
                    memcpy(temp_buf, value_start, value_len);
                    temp_buf[value_len] = '\0';
                    req->content_length = parse_ulong(temp_buf, &content_len_valid);
                    if (!content_len_valid) {
                        return false;  // Simplified error handling
                    }
                    flags |= 1;  // Set content_length_set
                }
            }
        } else if (name_len == 10 && !(flags & 2)) {
            if (strncasecmp(ptr, "Connection", 10) == 0) {
                conn->keep_alive = !(value_len == 5 && strncasecmp(value_start, "close", 5) == 0);
                flags |= 2;  // Set connection_set
            }
        }

        // Allocate and store header (only if we still need to store it)
        char* const name = arena_strdup2(arena, ptr, name_len);
        if (unlikely(!name)) return false;

        char* const value = arena_strdup2(arena, value_start, value_len);
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
        body_received += count;
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

    int written = snprintf(res->status_buf, STATUS_LINE_SIZE, "HTTP/1.1 %hu %s\r\n", code, status->text);

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
    char* ptr       = strstr(buf, name);
    if (!ptr) return NULL;  // Header not found

    // move past name, colon and space
    ptr += (strlen(name) + 2);

    // Find the next \r\n.
    char* value_end = strstr(ptr, "\r\n");
    if (!value_end) return NULL;  // Invalid header.

    size_t value_len = value_end - ptr;
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
    char* ptr       = strstr(buf, name);
    if (!ptr) return NULL;  // Header not found

    // move past name, colon and space
    ptr += (strlen(name) + 2);

    // Find the next \r\n.
    char* value_end = strstr(ptr, "\r\n");
    if (!value_end) return NULL;  // Invalid header.

    size_t value_len = value_end - ptr;

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
    resp->headers_buf[resp->headers_len] = '\0';
}

void conn_writeheader_raw(connection_t* conn, const char* header, size_t length) {
    response_t* resp = conn->response;

    // Reserve 2 bytes for final \r\n and 1 for null terminator
    const size_t SAFETY_MARGIN = 3;
    size_t remaining           = HEADERS_BUF_SIZE - resp->headers_len - SAFETY_MARGIN;
    if (length > remaining) {
        conn->closing = true;  // Not enough space
        return;
    }

    memcpy(resp->headers_buf + resp->headers_len, header, length);
    resp->headers_len += length;
    resp->headers_buf[resp->headers_len] = '\0';
}

void conn_writeheaders_vec(connection_t* conn, const struct iovec* headers, size_t count) {
    response_t* resp = conn->response;

    // Calculate total length first
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++) {
        total_len += headers[i].iov_len;
    }

    // Reserve space for final \r\n and null terminator
    const size_t SAFETY_MARGIN = 3;
    size_t remaining           = HEADERS_BUF_SIZE - resp->headers_len - SAFETY_MARGIN;

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
    size_t body_len = res->body_len;
    size_t required = body_len + len;

    // Fast path: stack buffer without allocation
    if (likely(!res->heap_allocated)) {
        if (required <= STACK_BUFFER_SIZE) {
            memcpy(res->body.stack + body_len, data, len);
            res->body_len += len;
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
            memcpy(heap_buffer, res->body.stack, body_len);

            // Now safe to switch to heap mode
            res->heap_allocated = true;
            res->body_capacity  = heap_capacity;
            res->body.heap      = heap_buffer;
        }
    }

    // Heap path: ensure sufficient capacity
    if (required > res->body_capacity) {

        size_t new_capacity = res->body_capacity;
        while (new_capacity < required) {
            // Check for overflow before doubling
            if (new_capacity > SIZE_MAX / 2) {
                fprintf(stderr, "Memory requirement too large\n");
                return -1;
            }
            new_capacity *= 2;
        }

        uint8_t* new_buffer = realloc(res->body.heap, new_capacity);
        if (!new_buffer) {
            perror("realloc failed");
            return -1;
        }
        res->body.heap     = new_buffer;
        res->body_capacity = new_capacity;
    }

    memcpy(res->body.heap + body_len, data, len);
    res->body_len += len;
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

__attribute__((format(printf, 2, 3))) int conn_writef(connection_t* conn, const char* restrict fmt, ...) {
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
        return conn_write(conn, stack_buf, len);
    }

    // Need larger buffer - allocate exact size
    heap_buf = malloc(len + 1);
    if (!heap_buf) {
        perror("malloc");
        return 0;
    }

    va_start(args, fmt);
    vsnprintf(heap_buf, len + 1, fmt, args);
    va_end(args);

    result = conn_write(conn, heap_buf, len);
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

    response_t* resp           = conn->response;
    const size_t SAFETY_MARGIN = 3;  // For final \r\n and null terminator
    size_t location_len        = strlen(location);
    size_t required            = 10 + location_len + 2;  // "Location: " + location + "\r\n"

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
    resp->headers_buf[resp->headers_len] = '\0';
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
                iov[i].iov_len -= remaining;
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
    conn_writeheader_raw(conn, "Server: Pulsar/1.0'\r\n", 21);
    written = strftime(date_buf, sizeof(date_buf), "Date: %a, %d %b %Y %H:%M:%S GMT\r\n",
                       gmtime(&conn->last_activity));
    conn_writeheader_raw(conn, date_buf, written);
}

ssize_t conn_write_chunk(connection_t* conn, const void* data, size_t size) {
    struct iovec iov[6];  // increased to 6 to accommodate status line
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
        conn->response->headers_buf[HEADERS_BUF_SIZE - 1] = '\0';

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
#define FLUSH_IF_NEEDED(needed_space)                                                                        \
    do {                                                                                                     \
        if (batch_pos + (needed_space) > BATCH_SIZE) {                                                       \
            if (batch_pos > 0) {                                                                             \
                conn_write_chunk(conn, batch_buf, batch_pos);                                                \
                batch_pos = 0;                                                                               \
            }                                                                                                \
        }                                                                                                    \
    } while (0)

    // Send headers first if needed
    if (send_headers) {
        struct iovec iov[2];
        int iovcnt = 0;

        iov[iovcnt++] =
            (struct iovec){.iov_base = conn->response->status_buf, .iov_len = conn->response->status_len};
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

        batch_pos += snprintf(batch_buf + batch_pos, BATCH_SIZE - batch_pos, "event: %.*s\n",
                              (int)evt->event_len, evt->event);
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

        batch_pos +=
            snprintf(batch_buf + batch_pos, BATCH_SIZE - batch_pos, "data: %.*s\n", (int)line_len, data_ptr);

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

        batch_pos +=
            snprintf(batch_buf + batch_pos, BATCH_SIZE - batch_pos, "id: %.*s\n", (int)evt->id_len, evt->id);
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

// Parses the Range header and extracts start and end values
INLINE bool parse_range(const char* range_header, ssize_t* start, ssize_t* end, bool* has_end_range) {
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
        start_byte = file_size + start_byte;   // subtract from the file size
        end_byte   = start_byte + chunk_size;  // send the next chunk size (if not more than the file size)
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

// Write headers for the Content-Range and Accept-Ranges.
// Also sets the status code for partial content.
INLINE void send_range_headers(connection_t* conn, ssize_t start, ssize_t end, off64_t file_size) {
    response_t* resp           = conn->response;
    const size_t SAFETY_MARGIN = 3;
    size_t remaining           = HEADERS_BUF_SIZE - resp->headers_len - SAFETY_MARGIN;

    // Format for range headers.
    static const char header_fmt[] =
        "Accept-Ranges: bytes\r\n"
        "Content-Length: %ld\r\n"
        "Content-Range: bytes %ld-%ld/%ld\r\n";

    // Enough for all range headers
    if (remaining > 164) {
        char* dest = resp->headers_buf + resp->headers_len;
        int len    = snprintf(dest, remaining, header_fmt, end - start + 1, start, end, file_size);
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

    conn->response->file_fd     = fd;
    conn->response->file_size   = stat_buf.st_size;
    conn->response->file_offset = 0;

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
        conn->response->file_offset = start_offset;
        conn->response->file_size   = stat_buf.st_size;
        conn->response->max_range   = end_offset - start_offset + 1;
        SET_RANGE_REQUEST(conn->response->flags);
    }

    return true;
}

// Build the complete HTTP response
INLINE void finalize_response(connection_t* conn, HttpMethod method) {
    response_t* resp = conn->response;
    if (resp->status_len == 0) conn_set_status(conn, StatusOK);

    // If range request flag is not set, set content-length.
    if (likely(!HAS_RANGE_REQUEST(resp->flags))) {
        size_t content_length = resp->body_len;
        char content_length_str[32];

        // OPTIONS method does not have a body, so we set content length to 0.
        // But HEAD needs to have the same headers as GET.
        if (method != HTTP_OPTIONS) {
            // If we are serving a file, use the file size.
            if (resp->file_fd >= 0) {
                content_length = resp->file_size;
            }
        } else {
            content_length = 0;  // For OPTIONS method, we don't send a body
        }

        // Set Content-Length header
        snprintf(content_length_str, sizeof(content_length_str), "%zu", content_length);
        conn_writeheader(conn, "Content-Length", content_length_str);
    }

#if WRITE_SERVER_HEADERS
    write_server_headers(conn);
#endif

    assert(resp->headers_len < HEADERS_BUF_SIZE - 3);

    // Terminate headers.
    memcpy(resp->headers_buf + resp->headers_len, "\r\n", 2);
    resp->headers_len += 2;
    resp->headers_buf[HEADERS_BUF_SIZE - 1] = '\0';
}

void static_file_handler(connection_t* conn) {
    route_t* route = conn->request->route;
    ASSERT((route->flags & STATIC_ROUTE_FLAG) != 0 && route);

    const char* dirname = route->dirname;
    size_t dirlen       = strlen(dirname);
    const char* path    = conn->request->path;

    // Prevent directory traversal attacks
    if (is_malicious_path(path)) {
        conn_notfound(conn);
        return;
    }

    // Build the request static path
    const char* static_path = path + strlen(route->pattern);
    size_t static_path_len  = strlen(static_path);

    // Validate path lengths
    if (dirlen >= PATH_MAX || static_path_len >= PATH_MAX || (dirlen + static_path_len + 2) >= PATH_MAX) {
        goto path_toolong;
    }

    // Concatenate the dirname and the static path
    char filepath[PATH_MAX];
    int n = snprintf(filepath, PATH_MAX, "%.*s%.*s", (int)dirlen, dirname, (int)static_path_len, static_path);
    if (n < 0 || n >= PATH_MAX) {
        goto path_toolong;
    }

    const char* src = filepath;
    if (strstr(filepath, "%")) {
        url_percent_decode(src, filepath, PATH_MAX);
    }

    // Serve file if it exists
    if (path_exists(filepath)) {
        const char* web_ct = get_mimetype(filepath);
        conn_set_content_type(conn, web_ct);
        conn_servefile(conn, filepath);
        return;
    }

    // Check for index.html in directory
    if (is_dir(filepath)) {
        char index_file[PATH_MAX];
        n = snprintf(index_file, sizeof(index_file), "%s/index.html", filepath);
        if (n < 0 || n >= PATH_MAX) {
            goto path_toolong;
        }

        if (path_exists(index_file)) {
            conn_set_content_type(conn, "text/html");
            conn_servefile(conn, filepath);
        } else {
            conn_notfound(conn);
        }
        return;
    }

    // Nothing found
    conn_notfound(conn);
    return;

path_toolong:
    conn_set_status(conn, StatusRequestURITooLong);
    conn_set_content_type(conn, "text/html");
    conn_write_string(conn, "<h1>Path too long</h1>");
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
#define EXECUTE_MIDDLEWARE(mw, count)                                                                        \
    do {                                                                                                     \
        size_t index = 0;                                                                                    \
        if (count > 0) {                                                                                     \
            while (index < count) {                                                                          \
                mw[index++](conn);                                                                           \
                if (conn->abort) {                                                                           \
                    return;                                                                                  \
                }                                                                                            \
            }                                                                                                \
        }                                                                                                    \
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

bool pulsar_set_context_value(connection_t* conn, const char* key, void* value, ValueFreeFunc free_func) {
    return LocalsSetValue(conn->locals, key, value, free_func);
}

void* pulsar_get_context_value(connection_t* conn, const char* key) {
    return LocalsGetValue(conn->locals, key);
}

void pulsar_delete_context_value(connection_t* conn, const char* key) {
    LocalsRemove(conn->locals, key);
}

#if ENABLE_LOGGING
INLINE void request_complete(connection_t* conn) {
    if (LOGGER_CALLBACK) {
        struct timespec end;
        clock_gettime(CLOCK_MONOTONIC, &end);

        uint64_t start_ns   = (uint64_t)conn->start.tv_sec * 1000000000ULL + conn->start.tv_nsec;
        uint64_t end_ns     = (uint64_t)end.tv_sec * 1000000000ULL + end.tv_nsec;
        uint64_t latency_ns = end_ns - start_ns;
        LOGGER_CALLBACK(conn, latency_ns);
    }
}
#endif

// Support for dynamic sscanf string size.
#define FORMAT(S)   "%" #S "s"
#define RESOLVE(S)  FORMAT(S)
#define STATUS_LINE ("%7s" RESOLVE(MAX_PATH_LEN) "%15s")

INLINE void process_request(connection_t* conn, size_t read_bytes, KeepAliveState* state, int queue_fd) {
    char* end_of_headers = strstr(conn->read_buf, "\r\n\r\n");
    if (!end_of_headers) {
        send_error_response(conn, StatusBadRequest);
        return;
    }
    size_t headers_len = end_of_headers - conn->read_buf + 4;

    char http_protocol[16] = {0};
    if (sscanf(conn->read_buf, STATUS_LINE, conn->request->method, conn->request->path, http_protocol) != 3) {
        send_error_response(conn, StatusBadRequest);
        return;
    }

    // Validate HTTP version. We only support http 1.1
    if (strcmp(http_protocol, "HTTP/1.1") != 0) {
        send_error_response(conn, StatusHTTPVersionNotSupported);
        return;
    }

    conn->request->method_type = http_method_from_string(conn->request->method);
    if (!METHOD_VALID(conn->request->method_type)) {
        send_error_response(conn, StatusMethodNotAllowed);
        return;
    }

    if (!parse_query_params(conn)) {
        send_error_response(conn, StatusInternalServerError);
        return;
    }

    // We need to parse the headers even for 404.
    if (!parse_request_headers(conn, conn->request->method_type, headers_len)) {
        send_error_response(conn, StatusInternalServerError);
        return;
    };

    route_t* route = route_match(conn->request->path, conn->request->method_type);
    if (route) {
        conn->request->route = route;
        if (!parse_request_body(conn, headers_len, read_bytes)) {
            send_error_response(conn, StatusInternalServerError);
            return;
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
        conn_notfound(conn);
    }

    // Chunked transfer is handled by the handler directly outside event loop.
    if (unlikely(HAS_CHUNKED_TRANSFER(conn->response->flags))) {
        if (conn->keep_alive) {
            conn->last_activity = time(NULL);
            AddKeepAliveConnection(conn, state);

            if (reset_connection(conn)) {
                if (event_mod_read(queue_fd, conn->client_fd, conn) < 0) {
                    conn->closing = true;
                }
            } else {
                conn->closing = true;
            }
        }
#if ENABLE_LOGGING
        request_complete(conn);
#endif
    } else {
        finalize_response(conn, conn->request->method_type);
        conn->last_activity = time(NULL);
        // Switch to writing response.
    }
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

    // Set high-performance options
    int yes = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    // Linux-specific optimizations
#ifdef __linux__
    // Enable TCP Fast Open (if configured)
    setsockopt(client_fd, SOL_TCP, TCP_FASTOPEN, &yes, sizeof(yes));

    // Enable TCP Quick ACK
    setsockopt(client_fd, IPPROTO_TCP, TCP_QUICKACK, &yes, sizeof(yes));

    // Set maximum segment size
    int mss = 1460;  // Standard Ethernet MTU - headers
    setsockopt(client_fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));

    int bufsize = 1024 * 1024;  // 1MB buffer
    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    int defer_accept = 1;
    setsockopt(server_fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_accept, sizeof(defer_accept));
#endif

    // BSD/Darwin optimizations
#if defined(__APPLE__) || defined(__FreeBSD__)
    // Disable SIGPIPE generation
    setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));

    // Enable TCP_NOPUSH (similar to TCP_CORK)
    setsockopt(client_fd, IPPROTO_TCP, TCP_NOPUSH, &yes, sizeof(yes));
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

INLINE size_t MIN(size_t x, size_t y) {
    return x < y ? x : y;
}

INLINE size_t MAX(size_t x, size_t y) {
    return x > y ? x : y;
}

INLINE void handle_read(int queue_fd, connection_t* conn, KeepAliveState* state) {
    ssize_t bytes_read = read(conn->client_fd, conn->read_buf, READ_BUFFER_SIZE - 1);
    if (bytes_read == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            conn->closing = true;  // read: connection reset by peer.
        }
        return;
    } else if (bytes_read == 0) {
        conn->closing = true;  // Unexpected close.
        return;
    }
    conn->read_buf[bytes_read] = '\0';

    process_request(conn, bytes_read, state, queue_fd);

    // Switch to writing response.
    if (event_mod_write(queue_fd, conn->client_fd, conn) < 0) {
        perror("event_mod_write");
        conn->closing = true;
    }
}

INLINE void handle_write(int queue_fd, connection_t* conn, KeepAliveState* state) {
    __builtin_prefetch(conn->response, 0, 3);  // Read prefetch for response

    response_t* res         = conn->response;
    int client_fd           = conn->client_fd;
    const bool sending_file = res->file_fd > 0 && res->file_size > 0;

    while (1) {
        ssize_t sent  = 0;
        bool complete = false;

        if (sending_file) {
            if (!HAS_HEADERS_WRITTEN(res->flags)) {
                // Send headers.
                struct iovec iov[2];
                iov[0].iov_base = res->status_buf + res->status_sent;
                iov[0].iov_len  = res->status_len - res->status_sent;
                iov[1].iov_base = res->headers_buf + res->headers_sent;
                iov[1].iov_len  = res->headers_len - res->headers_sent;

                sent = writev(client_fd, iov, 2);
                if (unlikely(sent < 0)) goto handle_error;

                // Handle zero bytes sent (socket buffer full)
                if (unlikely(sent == 0)) {
                    // Socket buffer is full, wait for next write event
                    return;
                }

                // Branchless update of sent counts
                size_t status_part = MIN((size_t)sent, iov[0].iov_len);
                res->status_sent += status_part;
                res->headers_sent += sent - status_part;

                if (res->status_sent == res->status_len && res->headers_sent == res->headers_len) {
                    SET_HEADERS_WRITTEN(res->flags);
                }
                continue;
            }

            // File data transfer
            off_t remaining_file = res->file_size - res->file_offset;
            if (remaining_file <= 0) {
                complete = true;
            } else {
                off_t chunk_size =
                    HAS_RANGE_REQUEST(res->flags) ? (off_t)MIN(1 << 20, remaining_file) : remaining_file;

#if defined(__linux__)
                // Use zero-copy sendfile if available
                off_t offset = res->file_offset;
                sent         = sendfile(client_fd, res->file_fd, &offset, chunk_size);
                if (sent > 0) {
                    res->file_offset = offset;
                }
#elif defined(__APPLE__) || defined(__FreeBSD__)
                // BSD-style sendfile
                off_t len  = chunk_size;
                int result = sendfile(res->file_fd, client_fd, res->file_offset, &len, NULL, 0);
                if (result == 0 || (result == -1 && errno == EAGAIN)) {
                    sent = len;
                    res->file_offset += sent;
                } else {
                    sent = -1;
                }
#else
                // Fallback for other systems - need to read from file first
                static thread_local char file_buffer[1 << 20];  // 1MB buffer
                chunk_size = MIN(chunk_size, sizeof(file_buffer));

                ssize_t read_bytes = pread(res->file_fd, file_buffer, chunk_size, res->file_offset);
                if (read_bytes <= 0) {
                    sent  = -1;
                    errno = EIO;
                } else {
                    sent = write(client_fd, file_buffer, read_bytes);
                    if (sent > 0) {
                        res->file_offset += sent;
                    }
                }
#endif
                if (unlikely(sent < 0)) goto handle_error;

                // Handle zero bytes sent (socket buffer full)
                if (sent == 0) {
                    // Socket buffer is full, wait for next write event
                    return;
                }

                complete = (res->file_offset >= res->file_size);
            }
        } else {
            // Normal buffer mode with optimized iovec setup
            struct iovec iov[3];
            iov[0].iov_base = res->status_buf + res->status_sent;
            iov[0].iov_len  = res->status_len - res->status_sent;
            iov[1].iov_base = res->headers_buf + res->headers_sent;
            iov[1].iov_len  = res->headers_len - res->headers_sent;

            iov[2].iov_base = (res->heap_allocated ? res->body.heap : res->body.stack) + res->body_sent;
            iov[2].iov_len  = res->body_len - res->body_sent;

            sent = writev(client_fd, iov, 3);
            if (unlikely(sent < 0)) goto handle_error;

            // Handle zero bytes sent (socket buffer full)
            if (sent == 0) {
                // Socket buffer is full, wait for next write event
                return;
            }

            // Update sent counts.
            size_t remaining = sent;

            // Update status_sent
            if (remaining > 0) {
                size_t seg = MIN(remaining, iov[0].iov_len);
                res->status_sent += seg;
                remaining -= seg;
            }

            // Update headers_sent
            if (remaining > 0) {
                size_t seg = MIN(remaining, iov[1].iov_len);
                res->headers_sent += seg;
                remaining -= seg;
            }

            // Update body_sent
            if (remaining > 0) {
                size_t seg = MIN(remaining, iov[2].iov_len);
                res->body_sent += seg;
            }

            complete = (res->status_sent == res->status_len) && (res->headers_sent == res->headers_len) &&
                       (res->body_sent == res->body_len);
        }

        conn->last_activity = time(NULL);
        if (complete) {
#if ENABLE_LOGGING
            request_complete(conn);
#endif
            if (sending_file) {
                close(res->file_fd);
                res->file_fd = -1;
            }

            if (conn->keep_alive) {
                conn->last_activity = time(NULL);
                AddKeepAliveConnection(conn, state);

                if (reset_connection(conn)) {
                    if (event_mod_read(queue_fd, conn->client_fd, conn) < 0) {
                        conn->closing = true;
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
    if (sending_file) {
        close(res->file_fd);
        res->file_fd = -1;
    }

    // Only mark for closing if it's a persistent error, not just EAGAIN/EWOULDBLOCK
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        // Ignore EPIPE (broken pipe), which just means client disconnected
        if (errno != EPIPE) {
            perror("write failed");
        }
        conn->closing = true;
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
        clock_gettime(CLOCK_MONOTONIC, &now);
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
                    handle_write(queue_fd, conn, ka_state);
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
        worker_data[i].designated_core  = i % (num_cores - reserved_cores);
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
