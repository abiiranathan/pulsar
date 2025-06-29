#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>

#include "../include/method.h"
#include "../include/mimetype.h"
#include "../include/pulsar.h"

/* ================================================================
 * Data Structures and Type Definitions
 * ================================================================ */

// HTTP Response structure
typedef struct response_t {
    http_status status_code;  // HTTP status code
    char status_message[40];  // HTTP status message
    headers_t* headers;       // Custom headers map data structure.

    char* buffer;          // Buffer for outgoing data
    size_t bytes_to_send;  // Total bytes to write
    size_t bytes_sent;     // Bytes already sent
    size_t buffer_size;    // Bytes allocated for buffer

    char* body_data;       // Response body data (written to be conn_write, etc...)
    size_t body_size;      // Current body size (current length of body data)
    size_t body_capacity;  // Body buffer capacity. Determines realloc trigger.

    bool headers_written;   // Flag to track if headers are already written
    bool content_type_set;  // Track whether content-type has already been set

    // File serving with sendfile
    int file_fd;       // If a file_fd != -1, we are serving a file
    size_t file_size;  // The size of the file being sent
} response_t;

// HTTP Request structure
typedef struct request_t {
    char method[8];           // HTTP method (GET, POST etc.)
    HttpMethod method_type;   // MethodType Enum
    char* path;               // Requested path (arena allocated)
    char* body;               // Request body (dynamically allocated)
    size_t content_length;    // Content-Length header value
    size_t body_received;     // Bytes of body received
    size_t headers_len;       // Length of headers text in connection buffer
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

// Middleware context types
typedef enum { MW_TYPE_GLOBAL = 1, MW_TYPE_LOCAL } MW_TYPE;

// Context for middleware functions
typedef struct MiddlewareContext {
    union {
        struct {
            // Global middleware context
            size_t g_count;             // Number of global middleware functions
            size_t g_index;             // Current index in the global middleware array
            HttpHandler* g_middleware;  // Array of global middleware functions
        } Global;
        struct {
            size_t r_count;             // Number of route middleware functions
            size_t r_index;             // Current index in the route middleware array
            HttpHandler* r_middleware;  // Array of route middleware functions
        } Local;
    } ctx;
    MW_TYPE ctx_type;
} MiddlewareContext;

/* ================================================================
 * Global Variables and Constants
 * ================================================================ */

// Global flag to keep all workers running
static volatile sig_atomic_t server_running = 1;

// Global middleware
static HttpHandler global_mw[MAX_GLOBAL_MIDDLEWARE] = {};  // Global middleware array
static size_t global_mw_count                       = 0;   // Global middleware count

static void finalize_response(connection_t* conn, HttpMethod method);

/* ================================================================
 * Signal Handling Functions
 * ================================================================ */

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

static request_t* create_request(Arena* arena) {
    request_t* req = arena_alloc(arena, sizeof(request_t));
    if (!req)
        return NULL;

    memset(req, 0, sizeof(request_t));
    req->headers = headers_new(arena);
    if (!req->headers)
        return NULL;
    return req;
}

static response_t* create_response(Arena* arena) {
    response_t* resp = arena_alloc(arena, sizeof(response_t));
    if (!resp)
        return NULL;

    memset(resp, 0, sizeof(response_t));
    resp->file_fd = -1;
    resp->headers = headers_new(arena);

    return resp;
}

static inline void free_request(request_t* req) {
    if (req && req->body)
        free(req->body);
}

static inline void free_response(response_t* resp) {
    if (!resp)
        return;

    if (resp->buffer)
        free(resp->buffer);
    if (resp->body_data)
        free(resp->body_data);
}

static bool reset_connection(connection_t* conn) {
    conn->state               = STATE_READING_REQUEST;
    conn->keep_alive          = true;
    conn->user_data           = NULL;
    conn->user_data_free_func = NULL;

    free_request(conn->request);
    free_response(conn->response);

    if (!conn->arena) {
        conn->arena = arena_create(ARENA_CAPACITY);
        if (!conn->arena)
            return false;
    } else {
        arena_reset(conn->arena);
    }

    conn->request  = create_request(conn->arena);
    conn->response = create_response(conn->arena);
    return (conn->request && conn->response);
}

void close_connection(int epoll_fd, connection_t* conn) {
    if (!conn)
        return;

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->client_fd, NULL);
    close(conn->client_fd);

    free_request(conn->request);
    free_response(conn->response);

    if (conn->arena)
        arena_destroy(conn->arena);

    free(conn);
}

// Send an error response during request processing.
static void send_error_response(connection_t* conn, http_status status) {
    conn_set_status(conn, status);
    conn_set_content_type(conn, CT_PLAIN);

    // use resp status code as it might have already been set.
    const char* msg = http_status_text(conn->response->status_code);
    conn_write_string(conn, msg);
    finalize_response(conn, conn->request->method_type);

    if (conn->response->buffer) {
        conn->state = STATE_WRITING_RESPONSE;
    } else {
        conn->state = STATE_CLOSING;
    }
}

/* ================================================================
 * Request Parsing Functions
 * ================================================================ */

static bool parse_request_headers(connection_t* conn, HttpMethod method, char* read_buf) {
    const char* ptr = read_buf;
    const char* end = ptr + conn->request->headers_len;

    bool clset         = false;
    bool keepalive_set = false;
    bool is_safe       = (method == HTTP_GET || method == HTTP_OPTIONS);

    while (ptr < end) {
        // Parse header name
        const char* colon = (const char*)memchr(ptr, ':', end - ptr);
        if (!colon)
            break;

        size_t name_len = colon - ptr;
        char* name      = arena_alloc(conn->arena, name_len + 1);
        if (!name)
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
        if (!value)
            return false;

        memcpy(value, ptr, value_len);
        value[value_len] = '\0';

        // Set content length
        if (!clset && !is_safe && strncasecmp(name, "Content-Length", 14) == 0) {
            bool valid;
            conn->request->content_length = parse_ulong(value, &valid);
            if (!valid) {
                fprintf(stderr, "Invalid content-length header\n");
                return false;
            }
            clset = true;
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

static bool parse_query_params(connection_t* conn) {
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

    req->body = malloc(content_length + 1);
    if (!req->body) {
        perror("malloc body");
        return false;
    }

    memcpy(req->body, read_buf + headers_len, body_available);
    req->body_received        = body_available;
    req->body[body_available] = '\0';

    while (req->body_received < content_length) {
        size_t remaining = content_length - req->body_received;
        ssize_t count    = read(conn->client_fd, req->body + req->body_received, remaining);

        if (count == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            perror("read");
            return false;
        } else if (count == 0) {
            return false;
        }
        req->body_received += count;
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

const char* res_header_get(connection_t* conn, const char* name) {
    return headers_get(conn->response->headers, name);
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
    response_t* res = conn->response;
    if (res->status_code > 0)
        return;  // Indempotent

    if (code >= StatusContinue && code <= StatusNetworkAuthenticationRequired) {
        res->status_code = code;
        strlcpy(res->status_message, http_status_text(code), sizeof(res->status_message));
    }
}

// Add a custom header
void conn_writeheader(connection_t* conn, const char* name, const char* value) {
    assert(name && value);

    char* name_ptr  = arena_strdup(conn->arena, name);
    char* value_ptr = arena_strdup(conn->arena, value);
    if (!name_ptr || !value_ptr) {
        fprintf(stderr, "conn_writeheader: arena_strdup failed\n");
        return;
    }
    headers_set(conn->response->headers, name_ptr, value_ptr);
}

void conn_set_content_type(connection_t* conn, const char* content_type) {
    if (conn->response->content_type_set)
        return;
    conn_writeheader(conn, "Content-Type", content_type);
}

// Write data to response body
int conn_write(connection_t* conn, const void* data, size_t len) {
    if (unlikely(!data || len == 0))
        return 0;

    response_t* resp     = conn->response;
    size_t required_size = resp->body_size + len;
    if (required_size > resp->body_capacity) {
        size_t new_capacity = resp->body_capacity ? resp->body_capacity * 2 : 1024;
        while (new_capacity < required_size)
            new_capacity *= 2;

        char* new_buffer = realloc(resp->body_data, new_capacity);
        if (!new_buffer) {
            perror("realloc");
            return 0;
        }

        resp->body_data     = new_buffer;
        resp->body_capacity = new_capacity;
    }

    memcpy(resp->body_data + resp->body_size, data, len);
    resp->body_size += len;
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
    return str ? conn_write(conn, str, strlen(str)) : -1;
}

__attribute__((format(printf, 2, 3))) int conn_writef(connection_t* conn, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (len <= 0)
        return -1;

    char* buffer = malloc(len + 1);
    if (!buffer) {
        perror("malloc");
        return -1;
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
    conn->response->file_fd   = fd;
    conn->response->file_size = stat_buf.st_size;
    return true;
}

// Build the complete HTTP response
static void finalize_response(connection_t* conn, HttpMethod method) {
    response_t* resp = conn->response;
    if (resp->headers_written)
        return;

    // Make sure we have a response and headers
    assert(conn->response && conn->response->headers);

    // Set server headers.
    conn_writeheader(conn, "Server", "Pulsar/1.0");
    char date_buf[64];
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&conn->last_activity));
    conn_writeheader(conn, "Date", date_buf);

    // Set default status if not set
    if (resp->status_code <= 0) {
        resp->status_code = StatusOK;
        strlcpy(resp->status_message, "OK", sizeof(resp->status_message));
    }

    // Calculate total response size
    size_t header_size = 512;  // Base headers

    // Calculate space needed for headers
    header_entry* entry;
    headers_foreach(resp->headers, entry) {
        header_size += strlen(entry->name) + strlen(entry->value) + 4;
    }
    size_t content_length = resp->body_size;
    size_t buffer_size    = header_size + content_length;
    bool sending_file     = resp->file_fd > 0 && resp->file_size > 0;

    if (sending_file) {
        content_length = resp->file_size;
        buffer_size    = header_size;
    }

    // Skip body for HEAD / OPTIONS
    if (method == HTTP_OPTIONS || method == HTTP_HEAD) {
        buffer_size = header_size;

        // Override content-length if it only options
        // Without this the client will hang!
        if (method == HTTP_OPTIONS) {
            content_length = 0;  // don't expect body!
        }
    }

    resp->buffer = malloc(buffer_size);
    if (!resp->buffer) {
        perror("malloc");
        conn->state = STATE_CLOSING;
        return;
    }
    resp->buffer_size = buffer_size;

    // Build headers
    int offset = snprintf(resp->buffer, header_size,  // header_size is always <= buffer_size.
                          "HTTP/1.1 %d %s\r\n"
                          "Connection: %s\r\n"
                          "Content-Length: %zu\r\n",
                          resp->status_code, resp->status_message, conn->keep_alive ? "keep-alive" : "close",
                          content_length);

    // Check for header truncation
    if (offset < 0 || offset >= (int)header_size) {
        fprintf(stderr, "Header truncation during write\n");
        conn->state = STATE_CLOSING;
        return;
    }

    // Add custom headers
    headers_foreach(resp->headers, entry) {
        offset +=
            snprintf(resp->buffer + offset, header_size - offset, "%s: %s\r\n", entry->name, entry->value);
    }

    // End headers
    offset += snprintf(resp->buffer + offset, header_size - offset, "\r\n");

    // Add body if present and not a file
    if (!(method == HTTP_OPTIONS || method == HTTP_HEAD) && !sending_file && resp->body_size > 0 &&
        resp->body_data) {
        memcpy(resp->buffer + offset, resp->body_data, resp->body_size);
        offset += content_length;
    }

    resp->bytes_to_send   = offset;
    resp->bytes_sent      = 0;
    resp->headers_written = true;
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

static inline void execute_middleware_chain(connection_t* conn, const MiddlewareContext* mw_ctx) {
    if (conn->abort)
        return;

    HttpHandler* middlewares;
    size_t count, index;

    switch (mw_ctx->ctx_type) {
        case MW_TYPE_GLOBAL:
            middlewares = mw_ctx->ctx.Global.g_middleware;
            count       = mw_ctx->ctx.Global.g_count;
            index       = mw_ctx->ctx.Global.g_index;
            break;
        case MW_TYPE_LOCAL:
            middlewares = mw_ctx->ctx.Local.r_middleware;
            count       = mw_ctx->ctx.Local.r_count;
            index       = mw_ctx->ctx.Local.r_index;
            break;
        default:
            assert(0 && "Unknown middleware type");
    }

    if (!middlewares || count == 0)
        return;

    while (index < count) {
        middlewares[index++](conn);
        if (conn->abort)
            break;
    }
}

static inline void execute_all_middleware(connection_t* conn, route_t* route) {
    // Execute global middleware
    if (global_mw_count > 0) {
        MiddlewareContext mw_ctx = {
            .ctx_type = MW_TYPE_GLOBAL,
            .ctx      = {.Global = {.g_count = global_mw_count, .g_index = 0, .g_middleware = global_mw}},
        };
        execute_middleware_chain(conn, &mw_ctx);

        // If request was aborted, skip route middleware.
        if (conn->abort) {
            return;
        }
    }

    // Execute route specific middleware.
    if (route->mw_count > 0) {
        MiddlewareContext mw_ctx = {
            .ctx_type = MW_TYPE_LOCAL,
            .ctx      = {.Local = {.r_count = route->mw_count, .r_index = 0, .r_middleware = route->mw}},
        };
        execute_middleware_chain(conn, &mw_ctx);
    }
}

void use_global_middleware(HttpHandler* middleware, size_t count) {
    if (count == 0)
        return;
    assert(count + global_mw_count <= MAX_GLOBAL_MIDDLEWARE);

    for (size_t i = 0; i < count; i++) {
        global_mw[global_mw_count++] = middleware[i];
    }
}

void use_route_middleware(route_t* route, HttpHandler* middleware, size_t count) {
    if (count == 0)
        return;
    assert(route->mw_count + count <= MAX_ROUTE_MIDDLEWARE);

    for (size_t i = 0; i < count; i++) {
        route->mw[route->mw_count++] = middleware[i];
    }
}

/* ================================================================
 * Request Processing Functions
 * ================================================================ */

static void process_request(connection_t* conn, char* read_buf, size_t read_bytes) {
    char* end_of_headers = strstr(read_buf, "\r\n\r\n");
    if (!end_of_headers) {
        send_error_response(conn, StatusBadRequest);  // Invalid Http payload.
        return;
    }

    conn->request->headers_len = end_of_headers - read_buf + 4;

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

        if (!parse_request_headers(conn, method, read_buf)) {
            send_error_response(conn, StatusInternalServerError);
            return;
        };

        if (!parse_request_body(conn, conn->request->headers_len, read_buf, read_bytes)) {
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

    if (conn->response->buffer) {
        conn->state         = STATE_WRITING_RESPONSE;
        conn->last_activity = time(NULL);
    } else {
        conn->state = STATE_CLOSING;
    }
}

/* ================================================================
 * Socket and Connection I/O Functions
 * ================================================================ */

static void set_nonblocking(int fd) {
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

static int conn_accept(int server_fd, int worker_id) {
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

void add_connection_to_worker(int epoll_fd, int client_fd) {
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
}

static void handle_read(int epoll_fd, connection_t* conn) {
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

static ssize_t conn_sendfile(connection_t* conn) {
    off_t size   = (off_t)conn->response->file_size;
    off_t offset = 0;
    ssize_t sent;
    ssize_t total_sent = 0;

    while (offset < size) {
        sent = sendfile(conn->client_fd, conn->response->file_fd, &offset, size - offset);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            close(conn->response->file_fd);
            return -1;
        } else if (sent == 0) {
            close(conn->response->file_fd);
            return -1;
        }
        total_sent += sent;
    }

    close(conn->response->file_fd);
    return total_sent;
}

static void handle_write(int epoll_fd, connection_t* conn) {
    response_t* res   = conn->response;
    bool sending_file = res->file_fd > 0 && res->file_size > 0;
    size_t remaining  = res->bytes_to_send - res->bytes_sent;

    // Send headers and contents (except file contents)
    while (remaining > 0) {
        ssize_t count = write(conn->client_fd, res->buffer + res->bytes_sent, remaining);
        if (count <= 1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("write");
                conn->state = STATE_CLOSING;
                return;
            } else if (count == 0) {
                perror("write");
                conn->state = STATE_CLOSING;
                return;
            }
        }
        res->bytes_sent += count;
        remaining -= count;
    }

    if (sending_file) {
        res->bytes_to_send += res->file_size;
        ssize_t sent = conn_sendfile(conn);
        if (sent <= 0) {
            conn->state = STATE_CLOSING;
            return;
        }
        res->bytes_sent += sent;
    }

    if (conn->keep_alive) {
        reset_connection(conn);

        struct epoll_event event;
        event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
        event.data.ptr = conn;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->client_fd, &event) < 0) {
            perror("epoll_ctl mod to EPOLLIN");
            conn->state = STATE_CLOSING;
        }
    } else {
        conn->state = STATE_CLOSING;
    }
}

/* ================================================================
 * Worker Thread Functions
 * ================================================================ */

typedef struct {
    int epoll_fd;
    int worker_id;
    int server_fd;
} WorkerData;

void* worker_thread(void* arg) {
    WorkerData* worker = (WorkerData*)arg;
    int epoll_fd       = worker->epoll_fd;
    int worker_id      = worker->worker_id;
    int server_fd      = worker->server_fd;
    struct epoll_event server_event;
    server_event.events  = EPOLLIN | EPOLLEXCLUSIVE;
    server_event.data.fd = server_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &server_event) < 0) {
        perror("epoll_ctl for server socket");
        return NULL;
    }

    struct epoll_event events[MAX_EVENTS];
    while (server_running) {
        int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (num_events == -1) {
            perror("epoll_wait");
            continue;
        }

        for (int i = 0; i < num_events; i++) {
            // Simple prefetch
            if (i + 1 < num_events) {
                __builtin_prefetch(events[i + 1].data.ptr, 0, 3);
            }

            if (events[i].data.fd == server_fd) {
                int client_fd = conn_accept(server_fd, worker_id);
                if (client_fd >= 0) {
                    add_connection_to_worker(epoll_fd, client_fd);
                }
            } else {
                connection_t* conn = (connection_t*)events[i].data.ptr;
                int state          = conn->state;
                uint32_t ev        = events[i].events;

                switch (state) {
                    case STATE_READING_REQUEST:
                        if (ev & EPOLLIN) {
                            handle_read(epoll_fd, conn);
                        }
                        break;
                    case STATE_WRITING_RESPONSE:
                        if (ev & EPOLLOUT) {
                            handle_write(epoll_fd, conn);
                        }
                        break;
                    default:
                        break;
                }

                // Check timeouts
                time_t now = time(NULL);
                if (now - conn->last_activity > CONNECTION_TIMEOUT) {
                    state = STATE_CLOSING;
                }

                if (state == STATE_CLOSING) {
                    close_connection(epoll_fd, conn);
                }
            }
        }
    }
    return NULL;
}

int pulsar_run(int port) {
    int server_fd = create_server_socket(port);
    set_nonblocking(server_fd);

    pthread_t workers[NUM_WORKERS];
    WorkerData worker_data[NUM_WORKERS];

    install_signal_handler();
    sort_routes();

    for (int i = 0; i < NUM_WORKERS; i++) {
        int epoll_fd = epoll_create1(0);
        if (epoll_fd == -1) {
            perror("epoll_create1");
            exit(EXIT_FAILURE);
        }

        worker_data[i].epoll_fd  = epoll_fd;
        worker_data[i].worker_id = i;
        worker_data[i].server_fd = server_fd;

        if (pthread_create(&workers[i], NULL, worker_thread, &worker_data[i])) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    printf("Server with %d workers listening on port %d\n", NUM_WORKERS, port);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    close(server_fd);
    return 0;
}
