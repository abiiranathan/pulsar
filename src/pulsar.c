#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "../include/pulsar.h"

// Worker thread data
typedef struct {
    int epoll_fd;
    int worker_id;
    int server_fd;
} worker_data_t;

// Path parameter.
typedef struct {
    char* name;   // Parameter name
    char* value;  // Parameter value from the URL
} PathParam;

// Array structure for path parameters.
typedef struct PathParams {
    PathParam* params;    // Array of matched parameters
    size_t match_count;   // Number of matched parameters from request path.
    size_t total_params;  // Total parameters counted at startup.
} PathParams;

// HTTP Response structure
typedef struct response_t {
    char* buffer;          // Buffer for outgoing data
    size_t bytes_to_send;  // Total bytes to write
    size_t bytes_sent;     // Bytes already sent
    size_t buffer_size;    // Bytes allocated for buffer

    http_status status_code;  // HTTP status code
    char status_message[40];  // HTTP status message
    headers_t* headers;       // Custom headers

    char* body_data;       // Response body data
    size_t body_size;      // Current body size
    size_t body_capacity;  // Body buffer capacity

    bool headers_written;   // Flag to track if headers are written
    bool content_type_set;  // Track whether content-type has been set

    // File serving with sendfile.
    int file_fd;       // If a file_fd != -1, we are serving a file.
    size_t file_size;  // The size of the file being sent.
} response_t;

typedef struct __attribute__((aligned(64))) connection_t {
    char* read_buf;             // Buffer for incoming data of size READ_BUFFER_SIZE (arena allocated)
    struct request_t* request;  // HTTP request data
    response_t* response;       // HTTP response data
    Arena* arena;               // Memory arena for allocations

    // 4-byte fields
    int fd;                // Client socket file descriptor
    time_t last_activity;  // Timestamp of last I/O activity
    size_t read_bytes;     // Bytes currently in read buffer

    // Small fields (1-2 bytes)
    enum {
        STATE_READING_REQUEST,
        STATE_WRITING_RESPONSE,
        STATE_CLOSING,
    } state;  // Current connection state (enum, likely 1-4 bytes)

    bool keep_alive;  // Keep-alive flag (bool, 1 byte)
    bool abort;       // Abort middleware processing

    // User data.
    void* user_data;                         // User data pointer per connection.
    void (*user_data_free_func)(void* ptr);  // Function to free user-data after request
} connection_t;

// HTTP Request structure
typedef struct request_t {
    char method[8];           // HTTP method (GET, POST etc.)
    char* path;               // Requested path
    char* body;               // Request body
    size_t content_length;    // Content-Length header value
    size_t body_received;     // Bytes of body received
    size_t headers_len;       // Length of headers text in connection buffer. ie offset
    headers_t* headers;       // Request headers
    headers_t* query_params;  // Query parameters
    struct route_t* route;    // Matched route.
} request_t;

typedef struct route_t {
    int flags;                             // Bit mask for route type. NormalRoute | StaticRoute
    char* pattern;                         // dynamically allocated route pattern
    char* dirname;                         // Directory name (for static routes)
    HttpMethod method;                     // Http method.
    HttpHandler handler;                   // Handler function pointer
    PathParams* path_params;               // Path parameters
    HttpHandler mw[MAX_ROUTE_MIDDLEWARE];  // Array of middleware
    size_t mw_count;                       // Number of middleware
} route_t;

typedef enum { MwGlobal = 1, MwLocal } MwCtxType;

// Context for middleware functions.
typedef struct MiddlewareContext {
    union {
        struct {
            // Global middleware context
            size_t g_count;             // Number of middleware golabl mw functions
            size_t g_index;             // Current index in the global middleware array
            HttpHandler* g_middleware;  // Array of global middleware functions
        } Global;
        struct {
            size_t r_count;             // Number of route middleware functions
            size_t r_index;             // Current index in the route middleware array
            HttpHandler* r_middleware;  // Array of route middleware functions
        } Local;
    } ctx;
    MwCtxType ctx_type;
} MiddlewareContext;

// Global flag to keep all workers running.
static volatile sig_atomic_t server_running = 1;

// Global routes
static route_t global_routes[MAX_ROUTES];
static size_t global_count = 0;

// Global middleware
static HttpHandler global_mw[MAX_GLOBAL_MIDDLEWARE] = {};  // Global middleware array.
static size_t global_mw_count                       = 0;   // Global middleware count

// ================== Signal handler    ========================
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

    // See man 2 sigaction for more information.
    sigaction(SIGINT, &sa, NULL);

    // Ignore SIGPIPE signal when writing to a closed socket or pipe.
    // Potential causes:
    // https://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
    signal(SIGPIPE, SIG_IGN);
}

// =================== New API Functions ========================

// Set HTTP status code and message
void conn_set_status(connection_t* conn, http_status code) {
    response_t* res = conn->response;
    if (res->status_code > 0)
        return;  // Status already set( Makes it Indempotent)

    // Only set valid status codes.
    if (code >= StatusContinue && code <= StatusNetworkAuthenticationRequired) {
        res->status_code = code;
        strlcpy(res->status_message, http_status_text(code), sizeof(res->status_message));
    }
}

// Add a custom header
bool conn_writeheader(connection_t* conn, const char* name, const char* value) {
    assert(name);
    assert(value);

    char* name_ptr  = arena_strdup(conn->arena, name);
    char* value_ptr = arena_strdup(conn->arena, value);
    if (!name_ptr || !value_ptr) {
        return false;
    }
    return headers_set(conn->arena, conn->response->headers, name_ptr, value_ptr);
}

bool conn_set_content_type(connection_t* conn, const char* content_type) {
    response_t* res = conn->response;
    if (res->content_type_set)
        return true;
    res->content_type_set = conn_writeheader(conn, "Content-Type", content_type);
    return res->content_type_set;
}

// Write data to response body
int conn_write(connection_t* conn, const void* data, size_t len) {
    if (!data || len == 0)
        return 0;

    response_t* resp = conn->response;

    // Ensure we have enough capacity
    size_t required_size = resp->body_size + len;
    if (required_size > resp->body_capacity) {
        size_t new_capacity = resp->body_capacity == 0 ? 1024 : resp->body_capacity;
        while (new_capacity < required_size) {
            new_capacity *= 2;
        }

        char* new_buffer = realloc(resp->body_data, new_capacity);
        if (!new_buffer) {
            return 0;  // Failed to allocate memory
        }

        resp->body_data     = new_buffer;
        resp->body_capacity = new_capacity;
    }

    // Copy data to body buffer
    memcpy(resp->body_data + resp->body_size, data, len);
    resp->body_size += len;

    return len;
}

// Send a 404 response.
int serve_404(connection_t* conn) {
    conn_set_status(conn, StatusNotFound);
    conn_set_content_type(conn, "text/plain");
    return conn_write(conn, "404 Not Found", 13);
}

// Write a NULL terminated string.
int conn_write_string(connection_t* conn, const char* str) {
    if (!str)
        return -1;
    return conn_write(conn, str, strlen(str));
}

__attribute__((format(printf, 2, 3))) int conn_writef(connection_t* conn, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char* buffer = NULL;
    int len      = vsnprintf(buffer, 0, fmt, args);  // Determine the required buffer size
    va_end(args);

    if (len <= 0)
        return -1;  // there was an error in formatting the string

    // Allocate a buffer of the required size
    buffer = (char*)malloc(len + 1);  // +1 for the null terminator
    if (!buffer) {
        perror("malloc");
        return -1;
    }

    // Format the string into the allocated buffer
    va_start(args, fmt);
    len = vsnprintf(buffer, len + 1, fmt, args);
    va_end(args);
    if (len < 0) {
        free(buffer);
        perror("vsnprintf");
        return -1;
    }

    // Send the response
    ssize_t result = conn_write(conn, buffer, len);
    free(buffer);
    return result;
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

    conn->response->file_fd   = fd;
    conn->response->file_size = stat_buf.st_size;
    return true;
}

// Build the complete HTTP response
static void finalize_response(connection_t* conn) {
    response_t* resp = conn->response;
    if (resp->headers_written)
        return;

    // Set default status if not set
    if (resp->status_code == 0) {
        resp->status_code = StatusOK;
        strcpy(resp->status_message, "OK");
    }

    // Calculate total response size
    size_t header_size = 512;  // Base headers

    // Iterate through all the headers.
    headers_foreach(resp->headers, hdr) {
        // +4, reserve for \r\n and colon and space.
        header_size += strlen(hdr->name) + strlen(hdr->value) + 4;
    }

    size_t content_length = resp->body_size;               // Conent-Length
    size_t buffer_size    = header_size + content_length;  // Memory to malloc for buffer.
    bool sending_file     = conn->response->file_fd > 0 && conn->response->file_size > 0;
    if (sending_file) {
        content_length = conn->response->file_size;
        buffer_size    = header_size;
    }

    resp->buffer = malloc(buffer_size);
    if (!resp->buffer) {
        perror("malloc");
        conn->state = STATE_CLOSING;
        return;
    }
    resp->buffer_size = buffer_size;

    // Build headers
    int offset = snprintf(resp->buffer, header_size,
                          "HTTP/1.1 %d %s\r\n"
                          "Connection: %s\r\n"
                          "Content-Length: %zu\r\n",
                          resp->status_code, resp->status_message, conn->keep_alive ? "keep-alive" : "close",
                          content_length);

    // Add custom headers
    headers_foreach(resp->headers, hdr) {
        // +4, reserve for \r\n and colon and space.
        offset += snprintf(resp->buffer + offset, header_size - offset, "%s: %s\r\n", hdr->name, hdr->value);
    }

    // End headers
    offset += snprintf(resp->buffer + offset, header_size - offset, "\r\n");

    // Add body if present and not a file.
    if (!sending_file && resp->body_size > 0 && resp->body_data) {
        memcpy(resp->buffer + offset, resp->body_data, resp->body_size);
        offset += content_length;
    }

    resp->bytes_to_send   = offset;  // includes not file contents
    resp->bytes_sent      = 0;
    resp->headers_written = true;
}

// =================== Routing ========================
static inline bool http_method_valid(HttpMethod method) {
    return method > HTTP_INVALID && method <= HTTP_DELETE;
}

const char* http_method_to_string(const HttpMethod method) {
    switch (method) {
        case HTTP_GET:
            return "GET";
        case HTTP_POST:
            return "POST";
        case HTTP_PUT:
            return "PUT";
        case HTTP_PATCH:
            return "PATCH";
        case HTTP_OPTIONS:
            return "OPTIONS";
        case HTTP_DELETE:
            return "DELETE";
        default:
            return "";
    }
}

HttpMethod http_method_from_string(const char* method) {
    if (!method)
        return HTTP_INVALID;
    if (strcmp(method, "GET") == 0)
        return HTTP_GET;
    if (strcmp(method, "POST") == 0)
        return HTTP_POST;
    if (strcmp(method, "PUT") == 0)
        return HTTP_PUT;
    if (strcmp(method, "PATCH") == 0)
        return HTTP_PATCH;
    if (strcmp(method, "DELETE") == 0)
        return HTTP_DELETE;
    if (strcmp(method, "OPTIONS") == 0)
        return HTTP_OPTIONS;
    return HTTP_INVALID;
}

// Count the number of path parameters in pattern.
// If there is an invalid (unterminated) parameter, valid is updated to false.
static inline size_t count_path_params(const char* pattern, bool* valid) {
    assert(valid != NULL);
    assert(pattern != NULL);

    const char* ptr = pattern;
    size_t count    = 0;
    *valid          = true;

    while (*ptr) {
        if (*ptr == '{') {
            // Check for nested/unmatched '{'
            const char* end = ptr + 1;
            while (*end && *end != '}') {
                if (*end == '{') {
                    *valid = false;  // Nested braces
                    return 0;
                }
                end++;
            }

            if (*end == '}') {
                count++;
                ptr = end + 1;  // Skip past '}'
            } else {
                *valid = false;  // Unterminated brace
                return 0;
            }
        } else if (*ptr == '}') {
            *valid = false;  // Unmatched closing brace
            return 0;
        } else {
            ptr++;
        }
    }
    return count;
}

#define STATIC_ROUTE_FLAG 0x01  // 1 << 0
#define NORMAL_ROUTE_FLAG 0x02  // 1 << 2

route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler) {
    assert(global_count < MAX_ROUTES && http_method_valid(method) && pattern && handler);

    route_t* r = &global_routes[global_count];
    r->pattern = strdup(pattern);
    assert(r->pattern);

    r->method      = method;
    r->handler     = handler;
    r->path_params = malloc(sizeof(PathParams));
    assert(r->path_params);

    bool valid;
    size_t nparams = count_path_params(pattern, &valid);
    if (!valid) {
        fprintf(stderr, "Invalid path parameter in pattern: %s\n", pattern);
    }
    assert(valid);

    r->path_params->match_count  = 0;        // Init the match count
    r->path_params->total_params = nparams;  // Set the expected path parameters
    r->path_params->params       = NULL;
    if (nparams > 0) {
        r->path_params->params = calloc(nparams, sizeof(PathParam));
        assert(r->path_params->params);
    }

    // default to normal route.
    r->flags   = NORMAL_ROUTE_FLAG;
    r->dirname = NULL;

    // Initialize route middleware
    r->mw_count = 0;
    memset(r->mw, 0, sizeof(r->mw));

    // Increment global count
    global_count++;
    return r;
}

// Comparison function for sorting by method then pattern
static int compare_routes(const void* a, const void* b) {
    const route_t* ra = (const route_t*)a;
    const route_t* rb = (const route_t*)b;

    // First sort by method
    if (ra->method < rb->method)
        return -1;
    if (ra->method > rb->method)
        return 1;

    // Then sort by pattern length (longer patterns first)
    size_t len_a = strlen(ra->pattern);
    size_t len_b = strlen(rb->pattern);
    if (len_a > len_b)
        return -1;
    if (len_a < len_b)
        return 1;

    // Finally sort alphabetically
    return strcmp(ra->pattern, rb->pattern);
}

static int global_sort_state = 0;
void routes_sort_if_needed(void) {
    if (global_sort_state == 0 && global_count > 0) {
        qsort(global_routes, global_count, sizeof(route_t), compare_routes);
        global_sort_state = 1;
    }
}

/**
 * Check if path is a directory
 * Returns true if path exists AND is a directory, false otherwise
 */
static inline bool is_dir(const char* path) {
    if (!path || !*path) {  // Handle NULL or empty string
        errno = EINVAL;
        return false;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return false;  // stat failed (errno is set)
    }
    return S_ISDIR(st.st_mode);
}

/**
 * Check if a path exists (file or directory)
 * Returns true if path exists, false otherwise (and sets errno)
 */
static inline bool path_exists(const char* path) {
    if (!path || !*path) {  // Handle NULL or empty string
        errno = EINVAL;
        return false;
    }
    return access(path, F_OK) == 0;
}

static inline void url_percent_decode(const char* src, char* dst, size_t dst_size) {
    char a, b;
    size_t written = 0;
    size_t src_len = strlen(src);

    while (*src && written + 1 < dst_size) {
        if (*src == '+') {
            *dst++ = ' ';
            src++;
            written++;
        } else if ((*src == '%') && (src_len >= 2) && ((a = src[1]) && (b = src[2])) &&
                   (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a')
                a -= 'a' - 'A';
            if (a >= 'A')
                a -= 'A' - 10;
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a' - 'A';
            if (b >= 'A')
                b -= 'A' - 10;
            else
                b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
            written++;
        } else {
            *dst++ = *src++;
            written++;
        }
    }

    // Null-terminate the destination buffer
    *dst = '\0';
}

static inline bool is_malicious_path(const char* path) {
    // List of dangerous patterns
    const char* patterns[] = {"../",     // Directory traversal
                              "/./",     // Current directory reference
                              "//",      // Multiple slashes
                              "/~",      // User home directories
                              "%2e%2e",  // URL-encoded ..
                              NULL};

    for (int i = 0; patterns[i]; i++) {
        if (strstr(path, patterns[i])) {
            return true;
        }
    }

    // Check for URL-encoded characters(\\x).
    if (strstr(path, "\\x")) {
        return true;
    }

    return false;
}

static bool static_file_handler(connection_t* conn) {
    route_t* route = conn->request->route;
    assert((route->flags & STATIC_ROUTE_FLAG) != 0);

    const char* dirname = route->dirname;
    size_t dirlen       = strlen(dirname);
    const char* path    = conn->request->path;

    // Prevent directory traversal attacks and reject NULL byte.
    if (is_malicious_path(path)) {
        return serve_404(conn);
    }

    // Build the request static path
    const char* static_path = path + strlen(route->pattern);

    size_t static_path_len = strlen(static_path);

    // Validate path lengths before processing
    if (dirlen >= PATH_MAX || static_path_len >= PATH_MAX || (dirlen + static_path_len + 2) >= PATH_MAX) {
        goto path_toolong;
    }

    // Concatenate the dirname and the static path
    char filepath[PATH_MAX];  // Uninitialized for performance;
    int n = snprintf(filepath, PATH_MAX, "%.*s%.*s", (int)dirlen, dirname, (int)static_path_len, static_path);
    if (n < 0 || n >= PATH_MAX) {
        goto path_toolong;
    }

    const char* src = filepath;
    if (strstr(filepath, "%")) {
        // percent-decode the path if required.
        url_percent_decode(src, filepath, PATH_MAX);
    }

    // Serve file if it exists.
    if (path_exists(filepath)) {
        const char* web_ct = get_mimetype(filepath);
        conn_set_content_type(conn, web_ct);
        return conn_servefile(conn, filepath);
    }

    // Check for index.html in directory.
    if (is_dir(filepath)) {
        char index_file[PATH_MAX];
        n = snprintf(index_file, sizeof(index_file), "%s/index.html", filepath);
        if (n < 0 || n >= PATH_MAX) {
            goto path_toolong;
        }

        // No index.html in directory.
        if (path_exists(index_file)) {
            conn_set_content_type(conn, "text/html");
            return conn_servefile(conn, filepath);
        } else {
            return serve_404(conn) > 0;
        }
    }

    // Nothing found, serve 404.
    return serve_404(conn);

path_toolong:
    conn_set_status(conn, StatusRequestURITooLong);
    conn_set_content_type(conn, "text/html");
    conn_write_string(conn, "<h1>Path too long</h1>");
    return true;
}

void set_userdata(connection_t* conn, void* ptr, void (*free_func)(void* ptr)) {
    assert(conn && ptr && free_func);

    conn->user_data           = ptr;
    conn->user_data_free_func = free_func;
}

// Returns the void* ptr, set with set_userdata function or NULL.
void* get_userdata(connection_t* conn) {
    if (!conn)
        return NULL;
    return conn->user_data;
}

route_t* register_static_route(const char* pattern, const char* dir) {
    assert(pattern && dir);  // validate inputs

    if (strcmp(".", dir) == 0)
        dir = "./";
    if (strcmp("..", dir) == 0)
        dir = "../";
    size_t dirlen = strlen(dir);
    assert(dirlen + 1 < PATH_MAX);

    char* dirname = NULL;  // will be malloc'd
    if ((dirname = realpath(dir, NULL)) == NULL) {
        fprintf(stderr, "Unable to resolve path: %s\n", dir);
        exit(1);
    }

    // We must have a valid directory
    assert(is_dir(dirname));

    if (dirname[dirlen - 1] == '/') {
        dirname[dirlen - 1] = '\0';  // Remove trailing slash
    }

    route_t* r = route_register(pattern, HTTP_GET, static_file_handler);
    r->flags   = STATIC_ROUTE_FLAG;
    r->dirname = dirname;
    return r;
}

/**
 * match_path_parameters compares the pattern with the URL and extracts the parameters.
 * The pattern can contain parameters in the form of {name}.
 *
 * @param pattern: The pattern to match
 * @param url_path: The URL path to match
 * @param pathParams: The PathParams struct to store the matched parameters
 * @return true if the pattern and URL match, false otherwise
 */
static bool match_path_parameters(Arena* arena, const char* pattern, const char* url_path,
                                  PathParams* path_params) {
    if (!path_params || !pattern || !url_path)
        return false;

    const char* pat          = pattern;
    const char* url          = url_path;
    size_t nparams           = 0;
    path_params->match_count = 0;

    // Fast path: exact match when no parameters were allocated.
    if (path_params->params == NULL) {
        while (*pat && *url && *pat == *url) {
            pat++;
            url++;
        }
        // Skip trailing slashes
        while (*pat == '/')
            pat++;
        while (*url == '/')
            url++;
        return (*pat == '\0' && *url == '\0');
    }

    // Now, we have parameters
    while (*pat && *url && nparams < path_params->total_params) {
        if (*pat == '{') {
            // Bounds check
            PathParam* param = &path_params->params[nparams++];

            // Extract parameter name
            pat++;  // Skip '{'
            const char* name_start = pat;
            while (*pat && *pat != '}')
                pat++;
            if (*pat != '}')
                return false;

            size_t name_len = pat - name_start;

            param->name = arena_alloc(arena, name_len + 1);
            if (param->name == NULL) {
                fprintf(stderr, "arena_alloc failed to allocate path parameter name\n");
                return false;
            }
            memcpy(param->name, name_start, name_len);
            param->name[name_len] = '\0';
            pat++;  // Skip '}'

            // Extract parameter value
            const char* val_start = url;
            while (*url && *url != '/' && *url != *pat)
                url++;
            size_t val_len = url - val_start;

            param->value = arena_alloc(arena, val_len + 1);
            if (param->value == NULL) {
                fprintf(stderr, "arena_alloc failed to allocate path parameter value\n");
                return false;
            }
            memcpy(param->value, val_start, val_len);
            param->value[val_len] = '\0';
        } else {
            if (*pat != *url)
                return false;
            pat++;
            url++;
        }
    }

    // Skip trailing slashes
    while (*pat == '/')
        pat++;
    while (*url == '/')
        url++;

    path_params->match_count = nparams;
    return (*pat == '\0' && *url == '\0' && path_params->total_params == path_params->match_count);
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

static route_t* route_match(connection_t* conn, HttpMethod method) {
    // Binary search to find the first route with matching method
    // We can do binary search because our routes are sorted by method, then pattern
    size_t low         = 0;
    size_t high        = global_count;
    size_t first_match = global_count;  // Initialize to invalid index

    while (low < high) {
        size_t mid            = low + (high - low) / 2;
        HttpMethod mid_method = global_routes[mid].method;
        if (mid_method >= method) {
            high = mid;
            if (mid_method == method) {
                first_match = mid;
            }
        } else {
            low = mid + 1;
        }
    }

    // If no routes for this method, return early
    if (first_match == global_count) {
        return NULL;
    }

    // Linear search through routes of the matching method
    const char* url   = conn->request->path;
    size_t url_length = strlen(url);

    // Prefetch the first few route patterns
    for (size_t i = first_match; i < first_match + 4 && i < global_count; i++) {
        if (global_routes[i].method == method) {
            __builtin_prefetch(global_routes[i].pattern, 0, 1);
        } else {
            break;  // Methods are sorted, so we can stop
        }
    }

    for (size_t i = first_match; i < global_count && global_routes[i].method == method; i++) {
        route_t* current = &global_routes[i];

        // Prefetch next route's pattern
        if (i + 4 < global_count && global_routes[i + 4].method == method) {
            __builtin_prefetch(global_routes[i + 4].pattern, 0, 1);
        }

        if ((current->flags & NORMAL_ROUTE_FLAG) != 0) {
            if (match_path_parameters(conn->arena, current->pattern, url, current->path_params)) {
                return current;
            }
        } else if ((current->flags & STATIC_ROUTE_FLAG) != 0) {
            size_t pat_length = strlen(current->pattern);
            if (pat_length <= url_length && memcmp(current->pattern, url, pat_length) == 0) {
                return current;
            }
        }
    }

    return NULL;
}

static inline bool execute_middleware_chain(connection_t* conn, const MiddlewareContext* mw_ctx) {
    HttpHandler* middleware;
    size_t count, index;
    bool success;

    switch (mw_ctx->ctx_type) {
        case MwGlobal:
            middleware = mw_ctx->ctx.Global.g_middleware;
            count      = mw_ctx->ctx.Global.g_count;
            index      = mw_ctx->ctx.Global.g_index;
            break;
        case MwLocal:
            middleware = mw_ctx->ctx.Local.r_middleware;
            count      = mw_ctx->ctx.Local.r_count;
            index      = mw_ctx->ctx.Local.r_index;
            break;
        default:
            unreachable();
    }

    while (index < count) {
        success = middleware[index++](conn);
        if (!success) {
            conn->abort = true;
            return false;
        }

        if (conn->abort) {
            break;
        }
    }

    return true;
}

// Register one or more global middleware.
void use_global_middleware(size_t count, ...) {
    size_t new_count = count + global_mw_count;
    assert(new_count <= MAX_GLOBAL_MIDDLEWARE && "Exceeded maximum global middleware count");

    va_list args;
    va_start(args, count);
    for (size_t i = global_mw_count; i < new_count; i++) {
        global_mw[i] = va_arg(args, HttpHandler);
    }
    va_end(args);

    global_mw_count += count;
}

// Register one or more middleware for this route.
void use_route_middleware(route_t* route, size_t count, ...) {
    if (count == 0)
        return;
    size_t new_count = route->mw_count + count;
    assert(new_count <= MAX_ROUTE_MIDDLEWARE && "route middleware count > MAX_ROUTE_MIDDLEWARE");

    // Append the new middleware to the route middleware
    va_list args;
    va_start(args, count);
    for (size_t i = route->mw_count; i < new_count; i++) {
        route->mw[i] = va_arg(args, HttpHandler);
    }
    va_end(args);

    route->mw_count = new_count;
}

// ====================================================================

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

static request_t* create_request(Arena* arena) {
    request_t* req = arena_alloc(arena, sizeof(request_t));
    if (!req)
        return NULL;

    req->body           = NULL;
    req->body_received  = 0;
    req->content_length = 0;
    req->path           = NULL;
    req->route          = NULL;
    req->query_params   = NULL;
    memset(req->method, 0, sizeof(req->method));

    // Allocate headers
    req->headers = headers_new(arena);
    if (!req->headers) {
        return NULL;
    }
    req->headers_len = 0;

    return req;
}

static response_t* create_response(Arena* arena) {
    response_t* resp = arena_alloc(arena, sizeof(response_t));
    if (!resp)
        return NULL;

    memset(resp, 0, sizeof(response_t));
    resp->file_fd = -1;

    resp->headers = headers_new(arena);
    if (!resp->headers) {
        return NULL;
    }
    return resp;
}

static inline void free_request(request_t* req) {
    if (!req)
        return;
    if (req->body)
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
    conn->read_bytes          = 0;
    conn->last_activity       = time(NULL);
    conn->keep_alive          = true;
    conn->user_data           = NULL;
    conn->user_data_free_func = NULL;

    if (conn->request)
        free_request(conn->request);
    if (conn->response)
        free_response(conn->response);
    if (conn->arena) {
        arena_reset(conn->arena);
    } else {
        conn->arena = arena_create(ARENA_CAPACITY);
        if (!conn->arena)
            return false;
    }
    conn->request  = create_request(conn->arena);
    conn->response = create_response(conn->arena);
    return (conn->request && conn->response);
}

void close_connection(int epoll_fd, connection_t* conn) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);

    if (conn->request)
        free_request(conn->request);
    if (conn->response)
        free_response(conn->response);
    if (conn->arena)
        arena_destroy(conn->arena);
    if (conn->read_buf)
        free(conn->read_buf);
    free(conn);
}

static int conn_accept(int server_fd, int worker_id) {
    (void)worker_id;  // might need it later for logging

    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("accept");
        }
        return -1;
    }

    set_nonblocking(client_fd);
    return client_fd;
}

void add_connection_to_worker(int epoll_fd, int client_fd) {
    connection_t* conn = calloc(1, sizeof(connection_t));
    if (!conn) {
        perror("calloc");
        close(client_fd);
        return;
    }
    conn->fd = client_fd;

    char* read_buf = calloc(1, READ_BUFFER_SIZE);
    if (!read_buf) {
        perror("malloc read_buf");
        conn->state = STATE_CLOSING;
        return;
    }
    conn->read_buf = read_buf;

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

static bool parse_request_headers(connection_t* conn, HttpMethod method) {
    const char* ptr = conn->read_buf;
    const char* end = ptr + conn->request->headers_len;

    bool clset         = false;
    bool keepalive_set = false;
    bool is_safe       = (method == HTTP_GET || method == HTTP_OPTIONS);

    while (ptr < end) {
        // Parse header name
        const char* colon = (const char*)memchr(ptr, ':', end - ptr);
        if (!colon)
            break;  // no more headers

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
            // Default to Keep-Alive, unless a client explicitly wants to close the connection.
            conn->keep_alive = strncmp(value, "close", 5) != 0;
            keepalive_set    = true;
        }

        if (!headers_set(conn->arena, conn->request->headers, name, value)) {
            return false;
        }

        ptr = eol + 2;  // Skip CRLF
    }

    return true;
}

static bool parse_query_params(connection_t* conn) {
    char* path  = conn->request->path;
    char* query = strchr(path, '?');  // find first occurence of ?
    if (query == NULL)
        return true;  // No Query parameters
    *query = '\0';    // Trim query from the path and NULL terminate path
    query++;          // move past ?

    // allocate memory in arena.
    conn->request->query_params = headers_new(conn->arena);
    if (!conn->request->query_params)
        return false;

    char* save_ptr1 = NULL;
    char* save_ptr2 = NULL;
    char* pair      = strtok_r(query, "&", &save_ptr1);

    while (pair != NULL) {
        // Split into key and value
        char* key   = strtok_r(pair, "=", &save_ptr2);
        char* value = strtok_r(NULL, "", &save_ptr2);  // Get rest of string after first '='

        if (key != NULL) {
            char* key_ptr   = arena_strdup(conn->arena, key);
            char* value_ptr = arena_strdup(conn->arena, value ? value : "");
            if (!key_ptr || !value_ptr)
                return false;
            headers_set(conn->arena, conn->request->query_params, key_ptr, value_ptr);
        }
        pair = strtok_r(NULL, "&", &save_ptr1);
    }
    return true;
}

// Get value for a query parameter if present or NULL.
const char* query_get(connection_t* conn, const char* name) {
    if (!conn->request->query_params)
        return NULL;  // no query params.
    return headers_get(conn->request->query_params, name);
}

// Returns the Query parameters.
headers_t* query_params(connection_t* conn) {
    return conn->request->query_params;
}

// Get a request header.(Possibly NULL)
const char* req_header_get(connection_t* conn, const char* name) {
    return headers_get(conn->request->headers, name);
}

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

// Returns request body size. (Content-Length).
size_t req_content_len(connection_t* conn) {
    return conn->request->content_length;
}

// Get a response header.(Possibly NULL)
const char* res_header_get(connection_t* conn, const char* name) {
    return headers_get(conn->response->headers, name);
}

static bool parse_request_body(connection_t* conn, size_t headers_len) {
    if (conn->request->content_length == 0) {
        return true;
    }

    request_t* req        = conn->request;
    size_t content_length = req->content_length;
    size_t body_available = conn->read_bytes - headers_len;
    assert(body_available <= content_length && "Can not read more than content-length");

    // Check body size.
    if (content_length > MAX_BODY_SIZE) {
        conn->response->status_code = StatusRequestEntityTooLarge;
        return false;
    }

    req->body = malloc(content_length + 1);
    if (!req->body) {
        perror("malloc body");
        return false;
    }

    // Copy body read together with headers.
    memcpy(req->body, conn->read_buf + headers_len, body_available);
    req->body_received        = body_available;
    req->body[body_available] = '\0';

    // Read complete body.
    while (req->body_received < content_length) {
        size_t remaining = content_length - req->body_received;
        ssize_t count    = read(conn->fd, req->body + req->body_received, remaining);
        if (count == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;  // try again
            } else {
                perror("read");  // real error.
                return false;
            }
        } else if (count == 0) {
            return false;  // Client closed connection unexpectedly.
        }
        req->body_received += count;
    }
    return true;
}

static inline void execute_all_middleware(connection_t* conn, route_t* route) {
    // Execute global middleware
    if (global_mw_count > 0) {
        MiddlewareContext mw_ctx = {
            .ctx_type = MwGlobal,
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
            .ctx_type = MwLocal,
            .ctx      = {.Local = {.r_count = route->mw_count, .r_index = 0, .r_middleware = route->mw}},
        };
        execute_middleware_chain(conn, &mw_ctx);
    }
}

static void process_request(connection_t* conn) {
    char* end_of_headers = strstr(conn->read_buf, "\r\n\r\n");
    if (!end_of_headers)
        return;  // still reading headers

    size_t headers_len         = end_of_headers - conn->read_buf + 4;
    conn->request->headers_len = headers_len;

    char path[1024];
    if (sscanf(conn->read_buf, "%7s %1023s", conn->request->method, path) != 2) {
        fprintf(stderr, "Failed to parse method and path\n");
        conn->state = STATE_CLOSING;
        return;
    }

    conn->request->path = arena_strdup(conn->arena, path);
    if (!conn->request->path) {
        conn->state = STATE_CLOSING;
        return;
    }

    // If we have query parameters, process them and truncate the path.
    if (!parse_query_params(conn)) {
        fprintf(stderr, "Failed to parse query parameters\n");
        conn->state = STATE_CLOSING;
        return;
    }

    // try to first match request before even parsing headers, query params
    // content-length and reading the body.
    HttpMethod method = http_method_from_string(conn->request->method);
    route_t* route    = route_match(conn, method);
    if (route) {
        // Set the route to request.
        conn->request->route = route;

        // Parse headers.
        if (!parse_request_headers(conn, method)) {
            fprintf(stderr, "error parsing request headers\n");
            conn->state = STATE_CLOSING;
            return;
        };

        // Read request body.
        if (!parse_request_body(conn, headers_len)) {
            conn->state = STATE_CLOSING;
            return;
        }
    }

    bool handler_success = true;
    if (route) {
        // Directly execute the handler if no middleware
        if (route->mw_count == 0 && global_mw_count == 0) {
            handler_success = route->handler(conn);
            goto post_handler;
        }

        // Execute all middleware
        execute_all_middleware(conn, route);

        // Execute the handler after the mw.
        if (!conn->abort) {
            handler_success = route->handler(conn);
        }
    }

post_handler:
    if (!handler_success || !route) {
        // Handle error or 404
        if (!route) {
            serve_404(conn);
        } else {
            // Set 500 status code if not already set inside handler.
            conn_set_status(conn, StatusInternalServerError);
            conn_set_content_type(conn, "text/plain");
            if (conn->response->body_size == 0) {
                conn_write(conn, "500 Internal Server Error", 25);
            }
        }
    }

    // Finalize response after handler completes
    finalize_response(conn);

    // free user data.
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

static void handle_read(int epoll_fd, connection_t* conn) {
    ssize_t count =
        read(conn->fd, conn->read_buf + conn->read_bytes, READ_BUFFER_SIZE - conn->read_bytes - 1);
    if (count == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read");
            conn->state = STATE_CLOSING;
        }
        return;
    } else if (count == 0) {
        // Unexpected close.
        conn->state = STATE_CLOSING;
        return;
    }

    conn->last_activity = time(NULL);
    conn->read_bytes += count;
    conn->read_buf[conn->read_bytes] = '\0';

    process_request(conn);

    if (conn->state == STATE_WRITING_RESPONSE) {
        struct epoll_event event;
        event.events   = EPOLLOUT | EPOLLET | EPOLLRDHUP;
        event.data.ptr = conn;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &event) < 0) {
            perror("epoll_ctl mod to EPOLLOUT");
            conn->state = STATE_CLOSING;
        }
        return;
    }
}

// Use sendfile for zero-copy transfer
static ssize_t conn_sendfile(connection_t* conn) {
    off_t size   = (off_t)conn->response->file_size;
    off_t offset = 0;
    ssize_t sent;
    ssize_t total_sent = 0;

    while (offset < size) {
        sent = sendfile(conn->fd, conn->response->file_fd, &offset, size - offset);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);  // sleep a bit and retry
                continue;
            }
            close(conn->response->file_fd);
            return -1;  // Return error
        } else if (sent == 0) {
            // EOF reached unexpectedly
            close(conn->response->file_fd);
            return -1;
        }
        total_sent += sent;
    }

    close(conn->response->file_fd);
    return total_sent;
}

void handle_write(int epoll_fd, connection_t* conn) {
    response_t* res   = conn->response;
    bool sending_file = res->file_fd > 0 && res->file_size > 0;
    size_t remaining  = res->bytes_to_send - res->bytes_sent;

    // Send headers and contents(except file contents)
    while (remaining > 0) {
        ssize_t count = write(conn->fd, res->buffer + res->bytes_sent, remaining);
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
        size_t sent = conn_sendfile(conn);
        if (sent <= 0) {
            conn->state = STATE_CLOSING;
            return;
        }
        res->bytes_sent += sent;
    }

    conn->last_activity = time(NULL);
    if (conn->keep_alive) {
        reset_connection(conn);

        struct epoll_event event;
        event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
        event.data.ptr = conn;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &event) < 0) {
            perror("epoll_ctl mod to EPOLLIN");
            conn->state = STATE_CLOSING;
        }
    } else {
        conn->state = STATE_CLOSING;
    }
}

// Check for timeouts on keep-alive connection, closing the connection
// If it exceeds CONNECTION_TIMEOUT seconds.
void check_timeouts(connection_t* conn) {
    time_t now = time(NULL);
    if (now - conn->last_activity > CONNECTION_TIMEOUT) {
        conn->state = STATE_CLOSING;
    }
}

void* worker_thread(void* arg) {
    worker_data_t* worker = (worker_data_t*)arg;
    int epoll_fd          = worker->epoll_fd;
    int worker_id         = worker->worker_id;
    int server_fd         = worker->server_fd;

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
            if (events[i].data.fd == server_fd) {
                int client_fd = conn_accept(server_fd, worker_id);
                if (client_fd >= 0) {
                    add_connection_to_worker(epoll_fd, client_fd);
                }
            } else {
                connection_t* conn = (connection_t*)events[i].data.ptr;

                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    conn->state = STATE_CLOSING;
                }

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

                check_timeouts(conn);

                if (conn->state == STATE_CLOSING) {
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
    worker_data_t worker_data[NUM_WORKERS];

    install_signal_handler();
    routes_sort_if_needed();

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
    printf("Terminated server gracefully\n");
    return 0;
}

__attribute__((destructor())) void cleanup(void) {
    for (size_t i = 0; i < global_count; i++) {
        route_t* r = &global_routes[i];
        free(r->pattern);

        if (r->dirname) {
            free(r->dirname);
        }

        if (r->path_params) {
            free(r->path_params->params);
            free(r->path_params);
        }
    }
}
