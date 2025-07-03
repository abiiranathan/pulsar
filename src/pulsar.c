#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../include/method.h"
#include "../include/mimetype.h"
#include "../include/pulsar.h"

// Buffer segment offsets (fixed positions)
#define BUFFER_STATUS_OFFSET 0
#define BUFFER_HEADERS_OFFSET 64                               // Reserve 64B for status line
#define BUFFER_BODY_OFFSET (BUFFER_HEADERS_OFFSET + 4096 + 2)  // Reserve 4096 for headers+\r\n
#define RESPONSE_HEADER_CAPACITY (BUFFER_BODY_OFFSET - BUFFER_HEADERS_OFFSET - 2)  // -2 \r\n
#define RESPONSE_STATUS_CAPACITY BUFFER_HEADERS_OFFSET

/* ================================================================
 * Data Structures and Type Definitions
 * ================================================================ */
const char* CRLF = "\r\n";

// HTTP Response structure
typedef struct response_t {
    http_status status_code;  // HTTP status code

    // Buffer segments and sizes.
    uint8_t* buffer;     // Single response buffer: [STATUS | HEADERS | BODY]
    size_t buffer_size;  // Total size of the response buffer
    size_t status_len;   // Actual length of status line
    size_t headers_len;  // Actual length of headers
    size_t body_len;     // Actual length of body

    // Buffer offsets for writing the response with retries(each EPOLLOUT event).
    size_t status_sent;   // Bytes of status line sent
    size_t headers_sent;  // Bytes of headers sent
    size_t body_sent;     // Bytes of body sent

    // File transfer state
    size_t file_size;   // Size of file to send (if applicable)
    off_t file_offset;  // Offset in file for sendfile
    off_t max_range;    // Maximum range of requested bytes in range request.
    int file_fd;        // File descriptor for file to send (if applicable)

    // Flags
    bool content_type_set;  // Flag to indicate if Content-Type header is set
    bool headers_written;   // Flag to indicate if headers have been written
    bool range_request;     // Has header "Range"
} response_t;

// HTTP Request structure
typedef struct request_t {
    char method[8];           // HTTP method (GET, POST etc.)
    HttpMethod method_type;   // MethodType Enum
    char* path;               // Requested path (arena allocated)
    char* body;               // Request body (dynamically allocated)
    size_t content_length;    // Content-Length header value
    headers_t* headers;       // Request headers
    headers_t* query_params;  // Query parameters
    struct route_t* route;    // Matched route (has static lifetime)
} request_t;

// Connection state structure
typedef struct connection_t {
    enum {
        STATE_READING_REQUEST,
        STATE_WRITING_RESPONSE,
        STATE_CLOSING,
    } state;                                 // Connection state
    int client_fd;                           // Client socket file descriptor
    time_t last_activity;                    // Timestamp of last I/O activity
    bool keep_alive;                         // Keep-alive flag
    bool abort;                              // Abort handler/middleware processing
    struct request_t* request;               // HTTP request data (arena allocated)
    response_t* response;                    // HTTP response data (arena allocated)
    Arena* arena;                            // Memory arena for allocations
    void* user_data;                         // User data pointer per connection
    void (*user_data_free_func)(void* ptr);  // Function to free user-data after request
} connection_t;

/* ================================================================
 * Global Variables and Constants
 * ================================================================ */
static int server_fd                                        = -1;  // Server socket file descriptor
static volatile sig_atomic_t server_running                 = 1;   // Server running flag
static volatile sig_atomic_t graceful_shutdown              = 0;   // Graceful shutdown flag
static volatile sig_atomic_t force_shutdown                 = 0;   // Force shutdown flag
static pthread_mutex_t shutdown_mutex                       = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t shutdown_cond                         = PTHREAD_COND_INITIALIZER;
static size_t active_connections                            = 0;   // Number of active connections
static volatile sig_atomic_t workers_shutdown               = 0;   // Flag to signal workers to shutdown
static HttpHandler global_middleware[MAX_GLOBAL_MIDDLEWARE] = {};  // Global middleware array
static size_t global_mw_count                               = 0;   // Global middleware count

static void finalize_response(connection_t* conn, HttpMethod method);

// Signal handler for graceful shutdown.
void handle_sigint(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        pthread_mutex_lock(&shutdown_mutex);

        if (!graceful_shutdown) {
            // First signal - initiate graceful shutdown
            printf("\nInitiating graceful shutdown... (Active connections: %zu)\n", active_connections);
            graceful_shutdown = 1;

            // Don't set server_running to 0 yet - let workers finish naturally
            pthread_cond_broadcast(&shutdown_cond);  // Wake up any waiting threads
        } else if (!force_shutdown) {
            // Second signal - force immediate shutdown
            printf("\nForcing immediate shutdown...\n");
            force_shutdown = 1;
            server_running = 0;
            pthread_cond_broadcast(&shutdown_cond);
        } else {
            // Third signal - hard exit
            printf("\nHard exit...\n");
            exit(EXIT_FAILURE);
        }
        pthread_mutex_unlock(&shutdown_mutex);
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
    request_t* req = arena_alloc(arena, sizeof(request_t));
    if (unlikely(!req))
        return NULL;

    // Initialize request structure
    memset(req, 0, sizeof(request_t));

    req->headers = headers_new(arena);
    if (unlikely(!req->headers))
        return NULL;

    req->query_params = NULL;          // No query params initially
    req->method_type  = HTTP_INVALID;  // Initial method is not valid
    return req;
}

INLINE response_t* create_response() {
    response_t* resp = calloc(1, sizeof(response_t));
    if (unlikely(!resp))
        return NULL;

    // Allocate a a resizble buffer for the response.
    resp->buffer = calloc(1, WRITE_BUFFER_SIZE);
    if (unlikely(!resp->buffer)) {
        free(resp);
        return NULL;
    }

    resp->buffer_size = WRITE_BUFFER_SIZE;
    resp->file_fd     = -1;
    return resp;
}

// Free request body. (Request structure is arena-allocated.)
INLINE void free_request(request_t* req) {
    if (unlikely(!req))
        return;

    if (unlikely(req->body)) {
        free(req->body);
    }
}

// Free response buffer and dynmically allocated response itself.
INLINE void free_response(response_t* resp) {
    if (!resp)
        return;

    if (likely(resp->buffer)) {
        free(resp->buffer);
    }
    free(resp);
}

INLINE void reset_response(response_t* resp) {
    // get a reference to the buffer and its size before calling memset.
    size_t buffer_size    = resp->buffer_size;
    unsigned char* buffer = resp->buffer;

    // Reset the buffer.
    memset(buffer, 0, buffer_size);

    // Reset the structure.
    memset(resp, 0, sizeof(response_t));

    // Reset response state.
    resp->buffer      = buffer;
    resp->file_fd     = -1;
    resp->status_code = 0;
    resp->buffer_size = buffer_size;
}

INLINE bool reset_connection(connection_t* conn) {
    conn->state               = STATE_READING_REQUEST;
    conn->keep_alive          = true;
    conn->user_data           = NULL;
    conn->user_data_free_func = NULL;

    // Free request body before resetting arena.
    free_request(conn->request);

    // Allocate a response if NULL or reset the buffer.
    if (likely(conn->response)) {
        reset_response(conn->response);
    } else {
        conn->response = create_response();
    }

    if (unlikely(!conn->arena)) {
        conn->arena = arena_create(ARENA_CAPACITY);
        if (unlikely(!conn->arena))
            return false;
    } else {
        arena_reset(conn->arena);
    }

    // Create a new request in arena(after reset)
    conn->request = create_request(conn->arena);

    return (conn->request && conn->response);
}

INLINE void close_connection(int epoll_fd, connection_t* conn) {
    if (unlikely(!conn))
        return;

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->client_fd, NULL);
    close(conn->client_fd);

    free_request(conn->request);
    free_response(conn->response);

    if (likely(conn->arena)) {
        arena_destroy(conn->arena);
    }

    pthread_mutex_lock(&shutdown_mutex);
    if (active_connections > 0) {
        active_connections--;
        // Signal main thread if this was the last connection during shutdown
        if (graceful_shutdown && active_connections == 0) {
            pthread_cond_signal(&shutdown_cond);
        }
    }
    pthread_mutex_unlock(&shutdown_mutex);
    free(conn);
}

// Send an error response during request processing.
INLINE void send_error_response(connection_t* conn, http_status status) {
    conn_set_status(conn, status);
    conn_set_content_type(conn, CT_PLAIN);

    // use resp status code as it might have already been set.
    const char* msg = http_status_text(conn->response->status_code);
    conn_write_string(conn, msg);
    finalize_response(conn, conn->request->method_type);

    // Switch to writing the response.
    conn->state         = STATE_WRITING_RESPONSE;
    conn->last_activity = time(NULL);
}

/* ================================================================
 * Request Parsing Functions
 * ================================================================ */

INLINE bool parse_request_headers(connection_t* conn, HttpMethod method, char* read_buf, size_t headers_len) {
    const char* ptr = read_buf;
    const char* end = ptr + headers_len;

    bool content_len_set = false;
    bool keepalive_set   = false;
    bool is_safe         = (method == HTTP_GET || method == HTTP_OPTIONS);

    while (ptr < end) {
        // Parse header name
        const char* colon = (const char*)memchr(ptr, ':', end - ptr);
        if (!colon)
            break;  // We are done with headers.

        size_t name_len = colon - ptr;
        char* name      = arena_alloc(conn->arena, name_len + 1);
        if (unlikely(!name))
            return false;

        memcpy(name, ptr, name_len);
        name[name_len] = '\0';

        // Move to header value
        ptr = colon + 1;
        while (ptr < end && *ptr == ' ')
            ptr++;

        // Parse header value
        const char* eol = (const char*)memchr(ptr, '\r', end - ptr);
        if (!eol || eol + 1 >= end || eol[1] != '\n')
            break;

        size_t value_len = eol - ptr;
        char* value      = arena_alloc(conn->arena, value_len + 1);
        if (unlikely(!value))
            return false;

        memcpy(value, ptr, value_len);
        value[value_len] = '\0';

        // Set content length
        if (!content_len_set && !is_safe && strncasecmp(name, "Content-Length", 14) == 0) {
            bool valid;
            conn->request->content_length = parse_ulong(value, &valid);
            if (unlikely(!valid)) {
                fprintf(stderr, "Invalid content-length header\n");
                return false;
            }
            content_len_set = true;
        }

        if (!keepalive_set && strcasecmp(name, "Connection") == 0) {
            conn->keep_alive = strncmp(value, "close", 5) != 0;
            keepalive_set    = true;
        }

        if (!headers_set(conn->request->headers, name, value)) {
            return false;
        }

        ptr = eol + 2;  // Skip CRLF
    }

    return true;
}

INLINE bool parse_query_params(connection_t* conn) {
    char* path  = conn->request->path;
    char* query = strchr(path, '?');
    if (!query)
        return true;

    *query = '\0';
    query++;

    conn->request->query_params = headers_new(conn->arena);
    if (!conn->request->query_params)
        return false;

    char* save_ptr1 = NULL;
    char* save_ptr2 = NULL;
    char* pair      = strtok_r(query, "&", &save_ptr1);

    while (pair) {
        char* key   = strtok_r(pair, "=", &save_ptr2);
        char* value = strtok_r(NULL, "", &save_ptr2);

        if (key) {
            char* key_ptr   = arena_strdup(conn->arena, key);
            char* value_ptr = arena_strdup(conn->arena, value ? value : "");
            if (!key_ptr || !value_ptr)
                return false;
            headers_set(conn->request->query_params, key_ptr, value_ptr);
        }
        pair = strtok_r(NULL, "&", &save_ptr1);
    }
    return true;
}

static bool parse_request_body(connection_t* conn, size_t headers_len, char* read_buf, size_t read_bytes) {
    if (conn->request->content_length == 0)
        return true;

    request_t* req        = conn->request;
    size_t content_length = req->content_length;
    size_t body_available = read_bytes - headers_len;
    assert(body_available <= content_length);

    if (content_length > MAX_BODY_SIZE) {
        conn_set_status(conn, StatusRequestEntityTooLarge);
        return false;
    }

    // Allocate full request body (+ null byte for safety).
    req->body = malloc(content_length + 1);
    if (!req->body) {
        perror("malloc body");
        return false;
    }

    memcpy(req->body, read_buf + headers_len, body_available);
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
    if (!conn->request->query_params)
        return NULL;  // no query params.
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

// Set HTTP status code and message
void conn_set_status(connection_t* conn, http_status code) {
    static_assert(RESPONSE_STATUS_CAPACITY >= 64, "Response status buffer must be at least 64 bytes");

    // Validate the status code.
    if (code < StatusContinue || code > StatusNetworkAuthenticationRequired) {
        fprintf(stderr, "Invalid HTTP status code: %d\n", code);
        exit(EXIT_FAILURE);  // Invalid status code, abort the program.
    }

    // Status line: // "HTTP/1.1 <code> <status text>\r\n"
    //                [8 bytes ][1 B][3B][1B][32 B max][2 bytes] = 47 bytes max
    response_t* res  = conn->response;
    res->status_code = code;

    // Clear only the status line segment if it was already set
    if (res->status_len > 0) {
        memset(res->buffer + BUFFER_STATUS_OFFSET, 0, res->status_len);
        res->status_len = 0;
    }

    // Write directly to status segment
    unsigned char* dest = res->buffer + BUFFER_STATUS_OFFSET;
    size_t i            = 0;

    // Write "HTTP/1.1 "
    memcpy(dest + i, "HTTP/1.1 ", 9);
    i += 9;

    // Write 3-digit status code
    dest[i++] = (code / 100) % 10 + '0';
    dest[i++] = (code / 10) % 10 + '0';
    dest[i++] = (code % 10) + '0';
    dest[i++] = ' ';

    // status text is guaranteed to be null-terminated and less than 32 bytes.
    const char* status_text = http_status_text(code);
    while (*status_text && i < RESPONSE_STATUS_CAPACITY - 2) {  // -2 for \r\n
        dest[i++] = (unsigned char)*status_text++;
    }

    // Write \r\n
    dest[i++] = '\r';
    dest[i++] = '\n';

    res->status_len = i;
}

INLINE bool res_header_exists(response_t* res, const char* name, size_t name_len) {
    unsigned char* headers_start = res->buffer + BUFFER_HEADERS_OFFSET;
    return pulsar_memmem(headers_start, res->headers_len, name, name_len);
}

// Get the value of a response header. Returns a dynamically allocated char* pointer or NULL
// If header does not exist or malloc fails.
char* res_header_get(connection_t* conn, const char* name) {
    response_t* res              = conn->response;
    unsigned char* headers_start = res->buffer + BUFFER_HEADERS_OFFSET;

    char* ptr = memmem(headers_start, res->headers_len, name, strlen(name));
    if (!ptr) {
        return NULL;  // Header not found
    }

    // move past name, colon and space
    ptr += (strlen(name) + 2);

    // Find the next \r\n to get the response value.
    char* value_end = memmem(ptr, res->headers_len - (ptr - (char*)headers_start), "\r\n", 2);
    if (!value_end)
        return NULL;

    size_t len   = value_end - ptr;
    char* header = malloc(len + 1);
    if (!header)
        return NULL;

    memcpy(header, ptr, len);
    header[len] = '\0';
    return header;
}

// Get the value of a response header, copying it into the buffer of size dest_size.
// Returns true on success or false if buffer is very small or header not found.
bool res_header_get_buf(connection_t* conn, const char* name, char* dest, size_t dest_size) {
    // Check if header already exists in the buffer
    response_t* res              = conn->response;
    unsigned char* headers_start = res->buffer + BUFFER_HEADERS_OFFSET;

    char* ptr = memmem(headers_start, res->headers_len, name, strlen(name));
    if (!ptr) {
        return NULL;  // Header not found
    }

    // move past name, colon and space
    ptr += (strlen(name) + 2);

    // Find the next \r\n to get the response value.
    char* value_end = memmem(ptr, res->headers_len - (ptr - (char*)headers_start), "\r\n", 2);
    if (!value_end)
        return NULL;

    size_t len = value_end - ptr;

    // Destination buffer is too small.
    if (dest_size <= len + 1) {
        return false;
    }

    memcpy(dest, ptr, len);
    dest[len] = '\0';
    return dest;
}

void conn_writeheader(connection_t* conn, const char* name, const char* value) {
    assert(name && value);

    response_t* res     = conn->response;
    size_t name_len     = strlen(name);
    size_t value_len    = strlen(value);
    size_t required_len = name_len + value_len + 4;  // ": \r\n"

#if DETECT_DUPLICATE_RES_HEADERS
    if (res_header_exists(res, name, name_len) && strcasecmp(name, "Set-Cookie") != 0)
        return;
#endif

    if (res->headers_len + required_len > RESPONSE_HEADER_CAPACITY)
        return;

    unsigned char* dest = res->buffer + BUFFER_HEADERS_OFFSET + res->headers_len;

    // copy name + ": "
    memcpy(dest, name, name_len);
    dest += name_len;
    *dest++ = ':';
    *dest++ = ' ';

    // copy value
    memcpy(dest, value, value_len);
    dest += value_len;

    // Terminate with CRLF
    *dest++ = '\r';
    *dest++ = '\n';

    res->headers_len += required_len;
}

void conn_set_content_type(connection_t* conn, const char* content_type) {
    if (conn->response->content_type_set)
        return;
    conn_writeheader(conn, "Content-Type", content_type);
    conn->response->content_type_set = true;
}

static inline size_t grow_buffer(size_t current_size, size_t required) {
    static const size_t kInitialSize = 1024;
    static const size_t kThreshold   = 1024 * 1024;   // 1MB
    static const size_t kMaxSize     = SIZE_MAX / 2;  // Safety cap

    if (required > kMaxSize) {
        return 0;  // Buffer growth would overflow
    }

    size_t new_size = current_size > 0 ? current_size : kInitialSize;
    while (new_size < required) {
        if (new_size < kThreshold) {
            if (new_size > kMaxSize / 2) {
                return 0;  // Buffer growth would overflow (doubling)
            }
            new_size *= 2;  // exponential growth
        } else {
            if (new_size > kMaxSize - kThreshold) {
                return 0;  // Buffer growth would overflow (linear)
            }
            new_size += kThreshold;  // linear growth
        }
    }
    return new_size;
}

int conn_write(connection_t* conn, const void* data, size_t len) {
    response_t* res = conn->response;
    size_t required = BUFFER_BODY_OFFSET + res->body_len + len;

    if (required > res->buffer_size) {
        size_t new_size = grow_buffer(res->buffer_size, required);
        if (new_size == 0) {
            fprintf(stderr, "Failed to grow response buffer\n");
            return 0;  // Failed to allocate more memory
        }

        unsigned char* new_buffer = realloc(res->buffer, new_size);
        if (!new_buffer) {
            perror("realloc");
            return 0;
        }

        res->buffer      = new_buffer;
        res->buffer_size = new_size;
    }

    // Append data
    memcpy(res->buffer + BUFFER_BODY_OFFSET + res->body_len, data, len);
    res->body_len += len;
    return len;
}

// Send a 404 response (StatusNotFound)
int conn_notfound(connection_t* conn) {
    conn_set_status(conn, StatusNotFound);
    conn_set_content_type(conn, CT_PLAIN);
    return conn_write(conn, "404 Not Found", 13);
}

// Send a 405 response (StatusMethodNotAllowed)
int conn_method_not_allowed(connection_t* conn) {
    conn_set_status(conn, StatusMethodNotAllowed);
    conn_set_content_type(conn, CT_PLAIN);
    return conn_write(conn, "405 Method Not Found", 20);
}

int conn_write_string(connection_t* conn, const char* str) {
    return str ? conn_write(conn, str, strlen(str)) : 0;
}

__attribute__((format(printf, 2, 3))) int conn_writef(connection_t* conn, const char* restrict fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (len <= 0)
        return 0;  // No data to write

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
bool validate_range(bool has_end_range, ssize_t* start, ssize_t* end, off64_t file_size) {
    if (!start || !end)
        return false;

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
    char content_length[128];
    char content_range[512];

    snprintf(content_length, sizeof(content_length), "%ld", end - start + 1);
    snprintf(content_range, sizeof(content_range), "bytes %ld-%ld/%ld", start, end, file_size);

    conn_writeheader(conn, "Accept-Ranges", "bytes");
    conn_writeheader(conn, "Content-Length", content_length);
    conn_writeheader(conn, "Content-Range", content_range);
}

bool conn_servefile(connection_t* conn, const char* filename) {
    if (!filename)
        return false;

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
    if (!conn->response->content_type_set) {
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
        conn->response->file_offset   = start_offset;
        conn->response->file_size     = stat_buf.st_size;
        conn->response->range_request = true;
        conn->response->max_range     = end_offset - start_offset + 1;
    }

    return true;
}

// Build the complete HTTP response
INLINE void finalize_response(connection_t* conn, HttpMethod method) {
    response_t* resp = conn->response;
    if (resp->status_len == 0)
        conn_set_status(conn, StatusOK);

    if (likely(!resp->range_request)) {
        // Default content length is the body length
        size_t content_length = resp->body_len;
        char content_length_str[32];

        // OPTIONS method does not have a body, so we set content length to 0.
        // But HEAD needs to have the same headers as GET.
        if (method != HTTP_OPTIONS) {
            // If we are serving a file, use the file size.
            if (resp->file_fd >= 0) {
                content_length = resp->file_size;  // Use file size if serving a file
            }
        } else {
            content_length = 0;  // For OPTIONS method, we don't send a body
        }

        // Set Content-Length header
        snprintf(content_length_str, sizeof(content_length_str), "%zu", content_length);
        conn_writeheader(conn, "Content-Length", content_length_str);
    }

    // Set server headers.
    conn_writeheader(conn, "Server", "Pulsar/1.0");
    char date_buf[64];
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&conn->last_activity));
    conn_writeheader(conn, "Date", date_buf);

    // This suffices because
    // RESPONSE_HEADER_CAPACITY = (BUFFER_BODY_OFFSET - BUFFER_HEADERS_OFFSET - 2)
    // So we can safely write \r\n at the end.
    assert(resp->headers_len <= RESPONSE_HEADER_CAPACITY);

    // Terminate headers with \r\n
    memcpy(resp->buffer + BUFFER_HEADERS_OFFSET + resp->headers_len, CRLF, 2);
    resp->headers_len += 2;
}

/* ================================================================
 * Static File Handling
 * ================================================================ */

void static_file_handler(connection_t* conn) {
    route_t* route = conn->request->route;
    assert((route->flags & STATIC_ROUTE_FLAG) != 0 && route);

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

/* ================================================================
 * User Data and Route Parameter Functions
 * ================================================================ */

void set_userdata(connection_t* conn, void* ptr, void (*free_func)(void* ptr)) {
    assert(conn && ptr);
    conn->user_data           = ptr;
    conn->user_data_free_func = free_func;
}

void* get_userdata(connection_t* conn) {
    return conn ? conn->user_data : NULL;
}

const char* get_path_param(connection_t* conn, const char* name) {
    if (!name)
        return NULL;
    route_t* route = conn->request->route;
    if (!route)
        return NULL;

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
    size_t index = 0;
    if (global_mw_count > 0) {
        while (index < global_mw_count) {
            global_middleware[index++](conn);
            if (conn->abort) {
                return;
            }
        }
    }

    // Execute route specific middleware.
    index = 0;
    if (route->mw_count > 0) {
        while (index < route->mw_count) {
            route->middleware[index++](conn);
            if (conn->abort) {
                return;
            }
        }
    }
}

void use_global_middleware(HttpHandler* middleware, size_t count) {
    if (count == 0) {
        return;
    }

    assert(count + global_mw_count <= MAX_GLOBAL_MIDDLEWARE);

    for (size_t i = 0; i < count; i++) {
        global_middleware[global_mw_count++] = middleware[i];
    }
}

void use_route_middleware(route_t* route, HttpHandler* middleware, size_t count) {
    if (count == 0)
        return;
    assert(route->mw_count + count <= MAX_ROUTE_MIDDLEWARE);

    for (size_t i = 0; i < count; i++) {
        route->middleware[route->mw_count++] = middleware[i];
    }
}

/* ================================================================
 * Request Processing Functions
 * ================================================================ */

static void process_request(connection_t* conn, char* read_buf, size_t read_bytes) {
    char* end_of_headers = strstr(read_buf, "\r\n\r\n");
    if (!end_of_headers) {
        send_error_response(conn, StatusBadRequest);
        return;
    }

    size_t headers_len = end_of_headers - read_buf + 4;

    char path[1024];
    char http_protocol[16];

    // Parse method, path and HTTP version
    if (sscanf(read_buf, "%7s %1023s %15s", conn->request->method, path, http_protocol) != 3) {
        send_error_response(conn, StatusBadRequest);
        return;
    }

    // Validate HTTP version
    if (strncmp(http_protocol, "HTTP/1.", 7) != 0) {
        send_error_response(conn, StatusHTTPVersionNotSupported);
        return;
    }

    // Check the minor version character
    char minor_version = http_protocol[7];
    if (minor_version != '0' && minor_version != '1') {
        send_error_response(conn, StatusHTTPVersionNotSupported);
        return;
    }

    conn->request->path = arena_strdup(conn->arena, path);
    if (!conn->request->path) {
        send_error_response(conn, StatusInternalServerError);
        return;
    }

    if (!parse_query_params(conn)) {
        send_error_response(conn, StatusInternalServerError);
        return;
    }

    HttpMethod method = http_method_from_string(conn->request->method);
    if (!http_method_valid(method)) {
        send_error_response(conn, StatusMethodNotAllowed);
        return;
    }

    conn->request->method_type = method;

    route_t* route = route_match(conn->request->path, method);
    if (route) {
        conn->request->route = route;

        if (!parse_request_headers(conn, method, read_buf, headers_len)) {
            send_error_response(conn, StatusInternalServerError);
            return;
        };

        if (!parse_request_body(conn, headers_len, read_buf, read_bytes)) {
            send_error_response(conn, StatusInternalServerError);
            return;
        }
    }

    if (route) {
        execute_all_middleware(conn, route);
        if (!conn->abort) {
            route->handler(conn);
        }
    } else {
        conn_notfound(conn);
    }

    finalize_response(conn, method);

    if (conn->user_data && conn->user_data_free_func) {
        conn->user_data_free_func(conn->user_data);
    }

    // Switch to writing response.
    conn->state         = STATE_WRITING_RESPONSE;
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

static int create_server_socket(int port) {
    int fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
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
        perror("calloc");
        close(client_fd);
        return;
    }

    // Zero all fields.
    memset(conn, 0, sizeof(connection_t));
    conn->client_fd = client_fd;

    if (!reset_connection(conn)) {
        fprintf(stderr, "Error in reset_connection\n");
        conn->state = STATE_CLOSING;
        return;
    }

    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
    event.data.ptr = conn;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
        perror("epoll_ctl");
        conn->state = STATE_CLOSING;
        return;
    }

    pthread_mutex_lock(&shutdown_mutex);
    active_connections++;
    pthread_mutex_unlock(&shutdown_mutex);
}

INLINE void handle_read(int epoll_fd, connection_t* conn) {
    char read_buf[READ_BUFFER_SIZE];
    ssize_t bytes_read = read(conn->client_fd, read_buf, READ_BUFFER_SIZE - 1);
    if (bytes_read == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            conn->state = STATE_CLOSING;  // read: connection reset by peer.
        }
        return;
    } else if (bytes_read == 0) {
        conn->state = STATE_CLOSING;  // Unexpected close.
        return;
    }

    conn->last_activity  = time(NULL);
    read_buf[bytes_read] = '\0';

    process_request(conn, read_buf, bytes_read);

    if (conn->state == STATE_WRITING_RESPONSE) {
        struct epoll_event event;
        event.events   = EPOLLOUT | EPOLLET;
        event.data.ptr = conn;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->client_fd, &event) < 0) {
            perror("epoll_ctl mod to EPOLLOUT");
            conn->state = STATE_CLOSING;
        }
    }
}

static void handle_write(int epoll_fd, connection_t* conn) {
    response_t* res   = conn->response;
    bool sending_file = res->file_fd > 0 && res->file_size > 0;

    while (1) {
        ssize_t sent = 0;

        if (sending_file) {
            /* File transfer mode */
            if (!res->headers_written) {
                // Send headers (status + headers)
                struct iovec iov[2] = {
                    {res->buffer + BUFFER_STATUS_OFFSET + res->status_sent,
                     res->status_len - res->status_sent},
                    {res->buffer + BUFFER_HEADERS_OFFSET + res->headers_sent,
                     res->headers_len - res->headers_sent},
                };

                errno = 0;  // Reset errno before writev
                sent  = writev(conn->client_fd, iov, 2);
                if (sent < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        return;  // Will retry on next EPOLLOUT
                    }
                    goto write_error;
                }

                // Update sent counts
                if ((size_t)sent <= iov[0].iov_len) {
                    res->status_sent += sent;
                } else {
                    res->status_sent = res->status_len;
                    res->headers_sent += (sent - iov[0].iov_len);
                }

                if (res->status_sent == res->status_len && res->headers_sent == res->headers_len) {
                    res->headers_written = true;
                }
                continue;
            }

            /* Send file data directly */
            off_t buffer_size;
            if (res->range_request) {
                // send file will handle position based on offset.
                buffer_size = 1 << 20;
                buffer_size = res->max_range < buffer_size ? res->max_range : buffer_size;
            } else {
                // Send appropriate position of file.
                buffer_size = res->file_size - res->file_offset;  // remaining bytes.
                lseek(res->file_fd, 0, SEEK_SET);
            }

            sent = sendfile(conn->client_fd, res->file_fd, &res->file_offset, buffer_size);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return;  // Will retry on next EPOLLOUT
                }
                perror("sendfile");
                goto write_error;
            } else if (sent == 0) {
                // Client disconnected or no more data to send.
                if ((size_t)res->file_offset < res->file_size) {
                    fprintf(stderr, "sendfile: client disconnected before completing file transfer\n");
                    goto write_error;
                }
                // Assume we have reached EOF.
                res->file_offset = res->file_size;  // Mark file transfer as complete
            }
        } else {
            /* Normal buffer mode */
            struct iovec iov[3] = {
                {res->buffer + BUFFER_STATUS_OFFSET + res->status_sent, res->status_len - res->status_sent},
                {res->buffer + BUFFER_HEADERS_OFFSET + res->headers_sent,
                 res->headers_len - res->headers_sent},
                {res->buffer + BUFFER_BODY_OFFSET + res->body_sent, res->body_len - res->body_sent},
            };

            sent = writev(conn->client_fd, iov, 3);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return;  // Will retry on next EPOLLOUT
                }
                goto write_error;
            }

            // Update sent counts
            size_t remaining = sent;
            for (int i = 0; i < 3 && remaining > 0; i++) {
                size_t segment_sent = (remaining < iov[i].iov_len) ? remaining : iov[i].iov_len;
                if (i == 0)
                    res->status_sent += segment_sent;
                else if (i == 1)
                    res->headers_sent += segment_sent;
                else
                    res->body_sent += segment_sent;
                remaining -= segment_sent;
            }
        }

        // Check completion
        bool complete =
            (res->status_sent == res->status_len) && (res->headers_sent == res->headers_len) &&
            (sending_file ? ((size_t)res->file_offset == res->file_size) : (res->body_sent == res->body_len));

        if (complete) {
            if (sending_file) {
                close(res->file_fd);
                res->file_fd = -1;
            }

            if (conn->keep_alive) {
                reset_connection(conn);
                struct epoll_event event = {.events = EPOLLIN | EPOLLET | EPOLLRDHUP, .data.ptr = conn};
                if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->client_fd, &event) < 0) {
                    perror("epoll_ctl mod to EPOLLIN");
                    conn->state = STATE_CLOSING;
                }
            } else {
                conn->state = STATE_CLOSING;
            }
            return;  // we are done.
        }
    }

write_error:
    if (sending_file) {
        close(res->file_fd);
        res->file_fd = -1;
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        perror("writev/sendfile");
        conn->state = STATE_CLOSING;
    }
}

/* ================================================================
 * Worker Thread Functions
 * ================================================================ */

typedef struct {
    int epoll_fd;
    int worker_id;
} WorkerData;

void* worker_thread(void* arg) {
    WorkerData* worker = (WorkerData*)arg;
    int epoll_fd       = worker->epoll_fd;
    int worker_id      = worker->worker_id;

    struct epoll_event server_event;
    server_event.events  = EPOLLIN | EPOLLEXCLUSIVE;
    server_event.data.fd = server_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &server_event) < 0) {
        perror("epoll_ctl for server socket");
        return NULL;
    }

    struct epoll_event events[MAX_EVENTS] = {};

    printf("Worker %d started\n", worker_id);

    while (server_running) {
        if (force_shutdown) {
            break;
        }

        int timeout    = graceful_shutdown ? 500 : 1000;  // Shorter timeout during shutdown
        int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, timeout);

        if (num_events == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait");
            continue;
        }

        // During graceful shutdown, don't accept new connections
        // but continue processing existing ones
        bool accept_new_connections = !graceful_shutdown;

        for (int i = 0; i < num_events; i++) {
            // prefetch next event to improve cache locality.
            if (i + 1 < num_events) {
                __builtin_prefetch(events[i + 1].data.ptr, 0, 3);
            }

            if (events[i].data.fd == server_fd) {
                if (accept_new_connections) {
                    // Accept new connection
                    int client_fd = conn_accept(worker_id);
                    if (client_fd >= 0) {
                        add_connection_to_worker(epoll_fd, client_fd);
                    }
                } else {
                    // During shutdown: accept and immediately close to prevent connection backlog
                    int client_fd = accept(server_fd, NULL, NULL);
                    if (client_fd >= 0) {
                        // Send a simple shutdown message
                        const char* shutdown_msg =
                            "HTTP/1.1 503 Service Unavailable\r\n"
                            "Content-Length: 23\r\n"
                            "Connection: close\r\n\r\n"
                            "Server is shutting down";
                        write(client_fd, shutdown_msg, strlen(shutdown_msg));
                        close(client_fd);
                    }
                }
            } else {
                connection_t* conn = (connection_t*)events[i].data.ptr;

                // Check for connection errors or hangups
                if (events[i].events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
                    conn->state = STATE_CLOSING;
                } else {
                    switch (conn->state) {
                        case STATE_READING_REQUEST:
                            if (events[i].events & EPOLLIN) {
                                handle_read(epoll_fd, conn);
                            }
                            break;
                        case STATE_WRITING_RESPONSE:
                            if (events[i].events & EPOLLOUT) {
                                handle_write(epoll_fd, conn);
                            }
                            break;
                        default:
                            break;
                    }
                }

                // Check timeouts (shorter timeout during shutdown)
                time_t now          = time(NULL);
                int timeout_seconds = graceful_shutdown ? 5 : CONNECTION_TIMEOUT;
                if (now - conn->last_activity > timeout_seconds) {
                    conn->state = STATE_CLOSING;
                }

                if (conn->state == STATE_CLOSING) {
                    close_connection(epoll_fd, conn);
                }
            }
        }

        // During graceful shutdown, check if we should exit
        if (graceful_shutdown && num_events == 0) {
            pthread_mutex_lock(&shutdown_mutex);
            bool no_connections = (active_connections == 0);
            pthread_mutex_unlock(&shutdown_mutex);

            if (no_connections) {
                break;
            }
        }
    }

    // Remove server socket from epoll
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, server_fd, NULL) < 0) {
        perror("epoll_ctl DEL for server socket");
    }

    // Force close any remaining connections
    struct epoll_event evs[MAX_EVENTS];
    int num_events = epoll_wait(epoll_fd, evs, MAX_EVENTS, 0);  // Non-blocking
    for (int i = 0; i < num_events; i++) {
        if (evs[i].data.fd != server_fd) {
            connection_t* conn = (connection_t*)evs[i].data.ptr;
            if (conn) {
                close_connection(epoll_fd, conn);
            }
        }
    }

    close(epoll_fd);

    // Signal that this worker has shut down
    pthread_mutex_lock(&shutdown_mutex);
    workers_shutdown++;
    pthread_cond_signal(&shutdown_cond);
    pthread_mutex_unlock(&shutdown_mutex);
    return NULL;
}

// Wait for all workers to shut down gracefully or forcefully.
void wait_for_workers_shutdown(pthread_t* workers, int timeout_seconds) {
    // Main server loop - wait for shutdown conditions
    pthread_mutex_lock(&shutdown_mutex);
    while (server_running) {
        if (graceful_shutdown) {
            // Wait for either all connections to close or force shutdown
            while (active_connections > 0 && !force_shutdown) {
                struct timespec timeout;
                clock_gettime(CLOCK_REALTIME, &timeout);
                timeout.tv_sec += timeout_seconds;  // Wait up to timeout seconds

                int result = pthread_cond_timedwait(&shutdown_cond, &shutdown_mutex, &timeout);
                if (result == ETIMEDOUT) {
                    printf("Shutdown timeout... Active connections: %zu\n", active_connections);
                    break;
                }
            }

            if (active_connections > 0) {
                printf("Forcing shutdown with %zu active connections\n", active_connections);
            }
            server_running = 0;  // Signal workers to stop
            break;
        }

        // Wait for shutdown signal
        pthread_cond_wait(&shutdown_cond, &shutdown_mutex);
    }
    pthread_mutex_unlock(&shutdown_mutex);

    // Wait for all workers to shut down
    pthread_mutex_lock(&shutdown_mutex);
    while (workers_shutdown < NUM_WORKERS) {
        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 10;  // 10 second timeout

        if (pthread_cond_timedwait(&shutdown_cond, &shutdown_mutex, &timeout) == ETIMEDOUT) {
            printf("Timeout waiting for workers, forcing shutdown\n");
            break;
        }
    }
    pthread_mutex_unlock(&shutdown_mutex);

    // Join all worker threads
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }
}

int pulsar_run(int port) {
    server_fd = create_server_socket(port);
    set_nonblocking(server_fd);

    pthread_t workers[NUM_WORKERS];
    WorkerData worker_data[NUM_WORKERS];

    install_signal_handler();
    sort_routes();
    init_mimetypes();

    // Initialize worker data and create workers
    for (int i = 0; i < NUM_WORKERS; i++) {
        int epoll_fd = epoll_create1(0);
        if (epoll_fd == -1) {
            perror("epoll_create1");
            exit(EXIT_FAILURE);
        }

        worker_data[i].epoll_fd  = epoll_fd;
        worker_data[i].worker_id = i;

        if (pthread_create(&workers[i], NULL, worker_thread, &worker_data[i])) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    usleep(1000);  // Give workers time to start
    printf("Server with %d workers listening on port %d\n", NUM_WORKERS, port);
    printf("Press Ctrl+C once for graceful shutdown, twice for immediate shutdown\n");

    wait_for_workers_shutdown(workers, SHUTDOWN_TIMEOUT_SECONDS);

    // Close server socket
    close(server_fd);

    // Cleanup the mutext and condition variable
    pthread_mutex_destroy(&shutdown_mutex);
    pthread_cond_destroy(&shutdown_cond);
    return 0;
}
