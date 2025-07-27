#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <malloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>

#if defined(__FreeBSD__)
#include <sys/cpuset.h>
#include <sys/param.h>
#endif

#include "../include/method.h"
#include "../include/mimetype.h"
#include "../include/pulsar.h"

// Flag bit definitions
#define HTTP_CONTENT_TYPE_SET 0x01
#define HTTP_HEADERS_WRITTEN  0x02
#define HTTP_RANGE_REQUEST    0x04
#define HTTP_FILE_RESPONSE    0x08

// Buffer segment offsets (fixed positions)
#define STATUS_LINE_SIZE 64
#define HEADERS_BUF_SIZE 4096
#define CACHE_LINE_SIZE  64
#define ARENA_CAPACITY                                                                             \
    NEXT_POWER_OF_TWO(1024 + MAX_PATH_LEN + READ_BUFFER_SIZE + (HEADERS_CAPACITY * 16))

#define MAX_FREE_CONNECTIONS 4096  // Connections to put in GC per worker.
#define GC_INTERVAL_SEC      5     // Seconds before workers run GC.

// Getters - check if flag is set
#define HTTP_HAS_CONTENT_TYPE(flags)    (((flags) & HTTP_CONTENT_TYPE_SET) != 0)
#define HTTP_HAS_HEADERS_WRITTEN(flags) (((flags) & HTTP_HEADERS_WRITTEN) != 0)
#define HTTP_HAS_RANGE_REQUEST(flags)   (((flags) & HTTP_RANGE_REQUEST) != 0)
#define HTTP_HAS_FILE_RESPONSE(flags)   (((flags) & HTTP_FILE_RESPONSE) != 0)

// Setters - set flag bits
#define HTTP_SET_CONTENT_TYPE(flags)    ((flags) |= HTTP_CONTENT_TYPE_SET)
#define HTTP_SET_HEADERS_WRITTEN(flags) ((flags) |= HTTP_HEADERS_WRITTEN)
#define HTTP_SET_RANGE_REQUEST(flags)   ((flags) |= HTTP_RANGE_REQUEST)
#define HTTP_SET_FILE_RESPONSE(flags)   ((flags) |= HTTP_FILE_RESPONSE)

/* ================================================================
 * Data Structures and Type Definitions
 * ================================================================ */
const char* CRLF = "\r\n";

// HTTP Response structure
typedef struct response_t {
    http_status status_code;  // HTTP status code.
    char status_buf[128];     // Null-terminated buffer for status line.
    char headers_buf[4096];   // Null-terminated buffer for headers.
    uint8_t* body_buf;        // Dynamically allocated body buffer. (not null-terminated)
    uint32_t body_capacity;   // Capacity of body buffer.

    // Pre-computed lengths of status line, headers, body.
    uint32_t body_len;     // Actual length of body
    uint16_t headers_len;  // Actual length of headers
    uint8_t status_len;    // Actual length of status line
    uint8_t flags;         // 4 bytes for all flags.

    // EPOLL OUT retry state.
    uint32_t status_sent;   // Bytes of status line sent
    uint32_t headers_sent;  // Bytes of headers sent
    uint32_t body_sent;     // Bytes of body sent

    // File response state.
    uint32_t file_size;    // Size of file to send (if applicable)
    uint32_t file_offset;  // Offset in file for sendfile
    uint32_t max_range;    // Maximum range of requested bytes in range request.
    int file_fd;           // File descriptor for file to send (if applicable)
    int heap_allocated;    // If heap allocation is used.
} response_t;

// HTTP Request structure
typedef struct request_t {
    char* path;               // Request path (arena allocated)
    char method[8];           // HTTP method (GET, POST etc.)
    HttpMethod method_type;   // MethodType Enum
    char* body;               // Request body (dynamically allocated)
    size_t content_length;    // Content-Length header value
    headers_t* headers;       // Request headers
    headers_t* query_params;  // Query parameters
    struct route_t* route;    // Matched route (has static lifetime)
} request_t;

// Connection state structure
typedef struct connection_t {
    bool closing;               // Server closing because of an error.
    bool keep_alive;            // Keep-alive flag
    bool abort;                 // Abort handler/middleware processing
    bool in_keep_alive;         // Flag for a tracked connection
    char* read_buf;             // Buffer for incoming data.
    int client_fd;              // Client socket file descriptor
    time_t last_activity;       // Timestamp of last I/O activity
    response_t* response;       // HTTP response data (arena allocated)
    struct request_t* request;  // HTTP request data (arena allocated)
    Arena* arena;               // Memory arena for allocations
#if ENABLE_LOGGING
    struct timespec start;  // Timestamp of first request
#endif
    hashmap_t* locals;  // Per-request context variables set by the user.

    // Linked List nodes.
    connection_t* next;
    connection_t* prev;
} connection_t;

typedef struct KeepAliveState {
    connection_t* head;
    connection_t* tail;
    size_t count;
} KeepAliveState;

typedef struct {
    connection_t* free_connections[MAX_FREE_CONNECTIONS];
    size_t count;
    size_t worker_id;
} connection_freelist_t;

/* ================================================================
 * Global Variables and Constants
 * ================================================================ */
static int server_fd                                        = -1;  // Server socket file descriptor
static volatile sig_atomic_t server_running                 = 1;   // Server running flag
static HttpHandler global_middleware[MAX_GLOBAL_MIDDLEWARE] = {};  // Global middleware array
static size_t global_mw_count                               = 0;   // Global middleware count
static PulsarCallback LOGGER_CALLBACK = NULL;                      // No logger callback by default.

INLINE void finalize_response(connection_t* conn, HttpMethod method);
INLINE void close_connection(int epoll_fd, connection_t* conn, KeepAliveState* ka_state,
                             connection_freelist_t* freelist);

static inline int get_num_available_cores() {
    return sysconf(_SC_NPROCESSORS_ONLN);
}

INLINE bool conn_timedout(time_t now, time_t last_activity) {
    bool timed_out = (now - last_activity) > CONNECTION_TIMEOUT;

// Remove debug printf in production, or make it conditional
#ifdef DEBUG_TIMEOUTS
    printf("conn_timedout: now=%ld, last_activity=%ld, timeout=%d, timed_out=%d\n", now,
           last_activity, timeout_seconds, timed_out);
#endif
    return timed_out;
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

INLINE void CheckKeepAliveTimeouts(KeepAliveState* state, connection_freelist_t* freelist,
                                   int worker_id, int epoll_fd) {
    connection_t* current = state->head;
    time_t now            = time(NULL);
    while (current) {
        connection_t* next = current->next;
        if (conn_timedout(now, current->last_activity)) {
            printf("Worker %d: closing timeout connection: %p\n", worker_id, (void*)current);
            close_connection(epoll_fd, current, state, freelist);
        }
        current = next;
    }

    // Release memory to OS
    malloc_trim(0);
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

    // Initialize response structure.
    memset(resp, 0, sizeof(response_t));

    // Allocate buffer in arena
    resp->body_buf = aligned_alloc(CACHE_LINE_SIZE, WRITE_BUFFER_SIZE);
    if (!resp->body_buf) {
        return NULL;
    }
    resp->body_buf[0]   = '\0';
    resp->body_capacity = WRITE_BUFFER_SIZE;
    resp->file_fd       = -1;
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

// Free response buffer. response it-self is arena-allocated.
INLINE void free_response(response_t* resp) {
    if (!resp) return;

    if (resp->body_buf) {
        free(resp->body_buf);
        resp->body_buf = NULL;
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
    conn->arena         = arena;
#if ENABLE_LOGGING
    clock_gettime(CLOCK_MONOTONIC, &conn->start);
#endif
    conn->locals = hashmap_create();
    conn->next   = NULL;
    conn->prev   = NULL;
    return (conn->request && conn->response && conn->locals && conn->read_buf);
}

INLINE bool reset_connection(connection_t* conn) {
    conn->closing    = false;
    conn->keep_alive = true;    // Default to Keep-Alive
    conn->abort      = false;   // Connection not aborted
    free(conn->request->body);  // Free request body.

    // Reset response buffer before resetting arena.
    if (conn->response->body_buf) {
        free(conn->response->body_buf);
    }
    arena_reset(conn->arena);  // Reset arena and reuse.

#if ENABLE_LOGGING
    clock_gettime(CLOCK_MONOTONIC, &conn->start);
#endif
    conn->request  = create_request(conn->arena);
    conn->response = create_response(conn->arena);
    conn->read_buf = arena_alloc(conn->arena, READ_BUFFER_SIZE);

    hashmap_clear(conn->locals);

    // Don't reset these fields if connection is in keep-alive list
    if (!conn->in_keep_alive) {
        conn->next = NULL;
        conn->prev = NULL;
    }

    return (conn->request && conn->read_buf);
}

INLINE void free_connection_resources(connection_t* conn) {
    free_request(conn->request);
    free_response(conn->response);
    if (conn->arena) arena_destroy(conn->arena);
    if (conn->locals) hashmap_destroy(conn->locals);
    free(conn);
}

// Called in seperate thread to free connections.
void process_freelist(connection_freelist_t* freelist) {
    while (freelist->count > 0) {
        connection_t* conn = freelist->free_connections[--freelist->count];
        free_connection_resources(conn);
    }
}

INLINE void close_connection(int epoll_fd, connection_t* conn, KeepAliveState* ka_state,
                             connection_freelist_t* freelist) {
    if (!conn || conn->client_fd == -1) return;

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->client_fd, NULL);
    close(conn->client_fd);
    conn->client_fd = -1;

    RemoveKeepAliveConnection(conn, ka_state);

    // Add to free list if there's space, otherwise free immediately
    if (freelist->count < MAX_FREE_CONNECTIONS) {
        freelist->free_connections[freelist->count++] = conn;
    } else {
        free_connection_resources(conn);
    }
}

// Send an error response during request processing.
INLINE void send_error_response(connection_t* conn, http_status status) {
    const char* status_text = conn_set_status(conn, status);  // is non-NULL.
    conn_set_content_type(conn, CONTENT_TYPE_PLAIN);
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

INLINE void conn_writeheader_fast(connection_t* conn, const char* name, size_t name_len,
                                  const char* value, size_t value_len) {
    response_t* res           = conn->response;
    const size_t required_len = name_len + value_len + 4;  // ": \r\n"
    const size_t current_len  = res->headers_len;

    // make sure there is space for new header and \r\n terminator.
    if (unlikely(current_len + required_len >= HEADERS_BUF_SIZE - 2)) {
        return;  // No more space for new headers.
    }

    const size_t available = HEADERS_BUF_SIZE - required_len;
    int written = snprintf(res->headers_buf + current_len, available, "%s: %s\r\n", name, value);
    assert(written > 0 && (size_t)written < available);
    res->headers_len += required_len;
}

__attribute__((hot, flatten)) void conn_writeheader(connection_t* conn, const char* name,
                                                    const char* value) {
    size_t name_len  = strlen(name);
    size_t value_len = strlen(value);
    conn_writeheader_fast(conn, name, name_len, value, value_len);
}

void conn_set_content_type(connection_t* conn, const char* content_type) {
    if (HTTP_HAS_CONTENT_TYPE(conn->response->flags)) {
        return;
    }

    conn_writeheader(conn, "Content-Type", content_type);
    HTTP_SET_CONTENT_TYPE(conn->response->flags);
}

int conn_write(connection_t* conn, const void* data, size_t len) {
    response_t* res = conn->response;
    size_t body_len = res->body_len;
    size_t required = body_len + len;

    if (required > res->body_capacity) {
        size_t new_capacity = res->body_capacity;  // not-zero because its well initialized.
        while (res->body_capacity < required) {
            new_capacity *= 2;  // TODO: Limit memory to SIZE_MAX/2 to prevent overflow.
        }

        unsigned char* new_buffer = realloc(res->body_buf, new_capacity);
        if (!new_buffer) {
            perror("realloc");
            return 0;
        }
        res->body_buf      = new_buffer;
        res->body_capacity = new_capacity;
    }

    uint8_t* dst = res->body_buf + body_len;
    memcpy(dst, data, len);

    res->body_len += len;
    return len;
}

// Send a 404 response (StatusNotFound)
int conn_notfound(connection_t* conn) {
    conn_set_status(conn, StatusNotFound);
    conn_set_content_type(conn, CONTENT_TYPE_PLAIN);
    return conn_write(conn, "404 Not Found", 13);
}

int conn_write_string(connection_t* conn, const char* str) {
    return str ? conn_write(conn, str, strlen(str)) : 0;
}

__attribute__((format(printf, 2, 3))) int conn_writef(connection_t* conn, const char* restrict fmt,
                                                      ...) {
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (len <= 0) return 0;  // No data to write

    char* buffer = malloc(len + 1);
    if (!buffer) {
        perror("malloc");
        return 0;
    }

    va_start(args, fmt);
    vsnprintf(buffer, len + 1, fmt, args);
    va_end(args);

    int result = conn_write(conn, buffer, len);
    free(buffer);
    return result;
}

void conn_abort(connection_t* conn) {
    conn->abort = true;
}

void conn_send(connection_t* conn, http_status status, const void* data, size_t length) {
    conn_set_status(conn, status);
    conn_write(conn, data, length);
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

// Write headers for the Content-Range and Accept-Ranges.
// Also sets the status code for partial content.
INLINE void send_range_headers(connection_t* conn, ssize_t start, ssize_t end, off64_t file_size) {
    char content_length[128];
    char content_range[512];

    snprintf(content_length, sizeof(content_length), "%ld", end - start + 1);
    snprintf(content_range, sizeof(content_range), "bytes %ld-%ld/%ld", start, end, file_size);

    conn_writeheader_fast(conn, "Accept-Ranges", 13, "bytes", 5);
    conn_writeheader(conn, "Content-Length", content_length);
    conn_writeheader(conn, "Content-Range", content_range);
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
    if (!HTTP_HAS_CONTENT_TYPE(conn->response->flags)) {
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
        HTTP_SET_RANGE_REQUEST(conn->response->flags);
    }

    return true;
}

// Build the complete HTTP response
INLINE void finalize_response(connection_t* conn, HttpMethod method) {
    response_t* resp = conn->response;
    if (resp->status_len == 0) conn_set_status(conn, StatusOK);

    // If range request flag is not set, set content-length.
    if (likely(!HTTP_HAS_RANGE_REQUEST(resp->flags))) {
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

#if !WRITE_SERVER_HEADERS
    conn_writeheader_fast(conn, "Server", 6, "Pulsar/1.0", 10);
    char date_buf[64];
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&conn->last_activity));
    conn_writeheader(conn, "Date", date_buf);
#endif

    ASSERT(resp->headers_len < HEADERS_BUF_SIZE - 2);

    // Terminate headers with \r\n
    memcpy(resp->headers_buf + resp->headers_len, CRLF, 2);
    resp->headers_len += 2;
}

/* ================================================================
 * Static File Handling
 * ================================================================ */

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
    if (dirlen >= PATH_MAX || static_path_len >= PATH_MAX ||
        (dirlen + static_path_len + 2) >= PATH_MAX) {
        goto path_toolong;
    }

    // Concatenate the dirname and the static path
    char filepath[PATH_MAX];
    int n = snprintf(filepath, PATH_MAX, "%.*s%.*s", (int)dirlen, dirname, (int)static_path_len,
                     static_path);
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

/* ================================================================
 * Middleware Handling Functions
 * ================================================================ */

INLINE void execute_all_middleware(connection_t* conn, route_t* route) {
    // Execute global middleware
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
    if (count == 0) {
        return;
    }

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

// Set the context value by key.
void pulsar_set_context_value(connection_t* conn, const char* key, void* value) {
    if (!conn) return;
    hashmap_error_t code;
    code = hashmap_put(conn->locals, key, value);
    if (code != HASHMAP_OK) {
        fprintf(stderr, "pulsar_set_value failed: %s\n", hashmap_error_string(code));
    }
}

// Get a context value. The user controlled value is written to value.
// Its your responsibility to free it if no longer required.
void pulsar_get_context_value(connection_t* conn, const char* key, void** value) {
    if (!conn) return;

    hashmap_error_t code;
    code = hashmap_get(conn->locals, key, value);
    if (code != HASHMAP_OK) {
        fprintf(stderr, "pulsar_get_value failed: %s\n", hashmap_error_string(code));
    }
}

// Support for dynamic sscanf string size.
#define FORMAT(S)   "%" #S "s"
#define RESOLVE(S)  FORMAT(S)
#define STATUS_LINE ("%7s" RESOLVE(MAX_PATH_LEN) "%15s")

INLINE void process_request(connection_t* conn, size_t read_bytes) {
    char* end_of_headers = strstr(conn->read_buf, "\r\n\r\n");
    if (!end_of_headers) {
        send_error_response(conn, StatusBadRequest);
        return;
    }
    size_t headers_len = end_of_headers - conn->read_buf + 4;

    char http_protocol[16] = {};
    if (sscanf(conn->read_buf, STATUS_LINE, conn->request->method, conn->request->path,
               http_protocol) != 3) {
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
        __builtin_prefetch(conn->response, 0, 3);            // Read prefetch for response
        __builtin_prefetch(conn->response->body_buf, 1, 3);  // Write prefetch for buffer

        execute_all_middleware(conn, route);
        if (!conn->abort) {
            route->handler(conn);
        }
    } else {
        conn_notfound(conn);
    }

    finalize_response(conn, conn->request->method_type);

    // Switch to writing response.
    conn->last_activity = time(NULL);
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

INLINE void add_connection_to_worker(int epoll_fd, int client_fd) {
    connection_t* conn = malloc(sizeof(connection_t));
    if (!conn) {
        perror("malloc");
        close(client_fd);
        return;
    }

    Arena* arena = arena_create(ARENA_CAPACITY);
    if (!arena) {
        perror("arena_create failed");
        close(client_fd);
        free(conn);
        return;
    }
    init_connection(conn, arena, client_fd);

    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
    event.data.ptr = conn;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
        perror("epoll_ctl");
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

INLINE void handle_read(int epoll_fd, connection_t* conn) {
    char* read_buf     = conn->read_buf;
    ssize_t bytes_read = read(conn->client_fd, read_buf, READ_BUFFER_SIZE - 1);
    if (bytes_read == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            conn->closing = true;  // read: connection reset by peer.
        }
        return;
    } else if (bytes_read == 0) {
        conn->closing = true;  // Unexpected close.
        return;
    }
    read_buf[bytes_read] = '\0';

    process_request(conn, bytes_read);

    // Switch to writing response.
    struct epoll_event event;
    event.events   = EPOLLOUT | EPOLLET;
    event.data.ptr = conn;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->client_fd, &event) < 0) {
        perror("epoll_ctl mod to EPOLLOUT");
        conn->closing = true;
    }
}

#if ENABLE_LOGGING
INLINE void request_complete(connection_t* conn) {
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    uint64_t latency_ns =
        (end.tv_sec - conn->start.tv_sec) * 1000000000ULL + (end.tv_nsec - conn->start.tv_nsec);

    if (LOGGER_CALLBACK) {
        LOGGER_CALLBACK(conn, latency_ns);
    };
}
#endif

INLINE void handle_write(int epoll_fd, connection_t* conn, KeepAliveState* state) {
    response_t* res         = conn->response;
    const bool sending_file = res->file_fd > 0 && res->file_size > 0;
    int client_fd           = conn->client_fd;

    while (1) {
        ssize_t sent  = 0;
        bool complete = false;

        if (sending_file) {
            if (!HTTP_HAS_HEADERS_WRITTEN(res->flags)) {
                // Send headers.
                struct iovec iov[2];
                iov[0].iov_base = res->status_buf + res->status_sent;
                iov[0].iov_len  = res->status_len - res->status_sent;
                iov[1].iov_base = res->headers_buf + res->headers_sent;
                iov[1].iov_len  = res->headers_len - res->headers_sent;

                sent = writev(client_fd, iov, 2);
                if (unlikely(sent < 0)) goto handle_error;

                // Branchless update of sent counts
                size_t status_part = MIN((size_t)sent, iov[0].iov_len);
                res->status_sent += status_part;
                res->headers_sent += sent - status_part;

                if (res->status_sent == res->status_len && res->headers_sent == res->headers_len) {
                    HTTP_SET_HEADERS_WRITTEN(res->flags);
                }
                continue;
            }

            // File data transfer
            off_t chunk_size = HTTP_HAS_RANGE_REQUEST(res->flags)
                                   ? MIN(1 << 20, res->max_range)
                                   : res->file_size - res->file_offset;

#ifdef __linux__
            // Use zero-copy sendfile if available
            sent = sendfile(client_fd, res->file_fd, (off_t*)&res->file_offset, chunk_size);
#else
            // Fallback for non-Linux systems
            sent = write(conn->client_fd, res->buffer + res->file_offset, chunk_size);
            if (sent > 0) res->file_offset += sent;
#endif
            if (unlikely(sent < 0)) goto handle_error;

            complete = (res->file_offset == res->file_size);
        } else {
            // Normal buffer mode with optimized iovec setup
            struct iovec iov[3];
            iov[0].iov_base = res->status_buf + res->status_sent;
            iov[0].iov_len  = res->status_len - res->status_sent;
            iov[1].iov_base = res->headers_buf + res->headers_sent;
            iov[1].iov_len  = res->headers_len - res->headers_sent;
            iov[2].iov_base = res->body_buf + res->body_sent;
            iov[2].iov_len  = res->body_len - res->body_sent;

            sent = writev(client_fd, iov, 3);
            if (unlikely(sent < 0)) goto handle_error;

            // Update sent counts.
            size_t remaining = sent;
            for (int i = 0; i < 3 && remaining > 0; i++) {
                size_t seg = MIN(remaining, iov[i].iov_len);
                *(i == 0   ? &res->status_sent
                  : i == 1 ? &res->headers_sent
                           : &res->body_sent) += seg;
                remaining -= seg;
            }

            complete = (res->status_sent == res->status_len) &&
                       (res->headers_sent == res->headers_len) && (res->body_sent == res->body_len);
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
                    struct epoll_event event = {.events   = EPOLLIN | EPOLLET | EPOLLRDHUP,
                                                .data.ptr = conn};
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->client_fd, &event) < 0) {
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
 * Worker Thread Functions
 * ================================================================ */

// Returns 0 on success, -1 on failure
int pin_current_thread_to_core(int core_id) {
    // Get and validate core count
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores <= 0) num_cores = 1;

    if (core_id < 0 || core_id >= (int)num_cores) {
        fprintf(stderr, "Invalid core_id %d (available: 0-%ld)\n", core_id, num_cores - 1);
        return -1;
    }

    // Check if core is online (Linux only)
#ifdef __linux__
    char path[256];
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/online", core_id);
    FILE* f = fopen(path, "r");
    if (f) {
        int online;
        if (fscanf(f, "%d", &online) == 1 && online != 1) {
            fclose(f);
            fprintf(stderr, "CPU core %d is offline\n", core_id);
            return -1;
        }
        fclose(f);
    }
#endif

    // Set CPU affinity
#if defined(__linux__)
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    pthread_t thread = pthread_self();
    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset) != 0) {
        if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) != 0) {
            perror("Failed to set CPU affinity");
            return -1;
        }
    }

#elif defined(__FreeBSD__)
    cpuset_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset_t), &cpuset) != 0) {
        perror("Failed to set CPU affinity");
        return -1;
    }

#else
    fprintf(stderr, "CPU affinity not supported on this platform\n");
    return -1;
#endif

    // Attempt real-time scheduling (best effort)
    struct sched_param param;
    int policies[] = {SCHED_FIFO, SCHED_RR};

    for (size_t i = 0; i < sizeof(policies) / sizeof(policies[0]); i++) {
        int max_prio = sched_get_priority_max(policies[i]);
        if (max_prio > 0) {
            param.sched_priority = max_prio;
            if (pthread_setschedparam(pthread_self(), policies[i], &param) == 0) {
                break;  // Success with real-time scheduling
            }
        }
    }

    // Real-time scheduling failure is non-fatal
    return 0;
}

typedef struct {
    int epoll_fd;
    int worker_id;
    int designated_core;
    KeepAliveState* keep_alive_state;
    connection_freelist_t* freelist;
} WorkerData;

void* worker_thread(void* arg) {
    WorkerData* worker              = (WorkerData*)arg;
    int epoll_fd                    = worker->epoll_fd;
    int worker_id                   = worker->worker_id;
    int cpu_core                    = worker->designated_core;
    KeepAliveState* ka_state        = worker->keep_alive_state;
    connection_freelist_t* freelist = worker->freelist;

    pin_current_thread_to_core(cpu_core);

    struct epoll_event server_event;
    server_event.events  = EPOLLIN | EPOLLEXCLUSIVE;
    server_event.data.fd = server_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &server_event) < 0) {
        perror("epoll_ctl for server socket");
        return NULL;
    }

    struct epoll_event events[MAX_EVENTS] = {};
    long last_timeout_check               = 0;
    uint32_t hangup_mask                  = EPOLLHUP | EPOLLERR | EPOLLRDHUP;

    while (server_running) {
        // Check for Keep-Alive timeouts 5 seconds.
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - last_timeout_check >= 5) {
            CheckKeepAliveTimeouts(ka_state, freelist, worker_id, epoll_fd);
            last_timeout_check = now.tv_sec;
        }

        int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, 500);
        if (num_events == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait");
            continue;
        }

        // During graceful shutdown, don't accept new connections
        // but continue processing existing ones
        for (int i = 0; i < num_events; i++) {
            if (events[i].data.fd == server_fd) {
                int client_fd = conn_accept(worker_id);
                if (client_fd > 0) {
                    add_connection_to_worker(epoll_fd, client_fd);
                }
            } else {
                connection_t* conn        = (connection_t*)events[i].data.ptr;
                const uint32_t event_mask = events[i].events;
                if (event_mask & EPOLLIN) {
                    // Prefetch conn->read_buf and the first cache line of the buffer itself
                    __builtin_prefetch(&conn->read_buf, 0, 1);  // 0=read, 1=moderate locality
                    __builtin_prefetch(conn->read_buf, 0, 3);
                    handle_read(epoll_fd, conn);
                } else if (event_mask & EPOLLOUT) {
                    handle_write(epoll_fd, conn, ka_state);
                } else if (event_mask && hangup_mask) {
                    conn->closing = true;
                }

                if (conn->closing) {
                    close_connection(epoll_fd, conn, ka_state, freelist);
                }
            }
        }
    }

    // Remove server socket from epoll
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, server_fd, NULL) < 0) {
        perror("epoll_ctl DEL for server socket");
    }

    close(epoll_fd);
    return NULL;
}

void* gc_thread_handler(void* arg) {
    connection_freelist_t* freelist = (connection_freelist_t*)arg;
    struct timespec last_check;
    clock_gettime(CLOCK_MONOTONIC, &last_check);

    while (server_running) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        // Check every GC_INTERVAL_SEC seconds.
        if ((now.tv_sec - last_check.tv_sec) >= GC_INTERVAL_SEC) {
            process_freelist(freelist);
            // printf("Worker %lu: Running GC\n", freelist->worker_id);
            last_check = now;
        }

        // Sleep to prevent busy waiting
        struct timespec sleep_time = {
            .tv_sec  = 0,
            .tv_nsec = 500000000  // 500ms
        };
        nanosleep(&sleep_time, NULL);
    }

    // Final cleanup on shutdown
    process_freelist(freelist);
    return NULL;
}

int pulsar_run(const char* addr, int port) {
    server_fd = create_server_socket(addr, port);
    set_nonblocking(server_fd);

    pthread_t workers[NUM_WORKERS]                = {};
    pthread_t gc_threads[NUM_WORKERS]             = {};
    WorkerData worker_data[NUM_WORKERS]           = {};
    KeepAliveState keep_alive_states[NUM_WORKERS] = {};
    connection_freelist_t freelists[NUM_WORKERS]  = {};

    install_signal_handler();
    sort_routes();
    init_mimetypes();

    // Tune malloc.
    mallopt(M_MMAP_THRESHOLD, 128 * 1024);  // Larger allocations use mmap
    mallopt(M_TRIM_THRESHOLD, 128 * 1024);  // More aggressive trimming

    // When creating worker threads
    int num_cores      = get_num_available_cores();
    int reserved_cores = 1;  // Leave one core free

    // Initialize worker data and create workers
    for (size_t i = 0; i < NUM_WORKERS; i++) {
        int epoll_fd = epoll_create1(0);
        if (epoll_fd == -1) {
            perror("epoll_create1");
            exit(EXIT_FAILURE);
        }

        worker_data[i].epoll_fd            = epoll_fd;
        worker_data[i].worker_id           = i;
        worker_data[i].designated_core     = i % (num_cores - reserved_cores);
        worker_data[i].keep_alive_state    = &keep_alive_states[i];
        worker_data[i].freelist            = &freelists[i];
        worker_data[i].freelist->worker_id = i;

        if (pthread_create(&workers[i], NULL, worker_thread, &worker_data[i])) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    // Start the GC threads
    for (int i = 0; i < NUM_WORKERS; i++) {
        if (pthread_create(&gc_threads[i], NULL, gc_thread_handler, &freelists[i])) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    usleep(1000);  // Give workers time to start
    printf("\n\nServer with %d workers listening on http://%s:%d\n", NUM_WORKERS,
           addr ? addr : "0.0.0.0", port);
    printf("Press Ctrl+C once for graceful shutdown, twice for immediate shutdown\n");

    // Join all worker threads
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    // Wait for GC threads.
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(gc_threads[i], NULL);
    }

    // Close server socket
    close(server_fd);
    return 0;
}
