#include <assert.h>
#include <ctype.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <pwd.h>

// Include status codes
#include "status_code.h"
#include "mimetype.h"

#define NUM_WORKERS        8          // Number of workers.
#define MAX_EVENTS         2048       // Maximum events for epoll->ready queue.
#define READ_BUFFER_SIZE   4096       // Buffer size for incoming data.
#define CONNECTION_TIMEOUT 30         // Keep-Alive connection timeout in seconds
#define MAX_BODY_SIZE      (2 << 20)  // Max Request body allowed.
#define ARENA_CAPACITY     8 * 1024   // Memory per connection.
#define MAX_ROUTES         64         // Maximum number of routes
#define MAX_HEADERS        32         // Maximum req/res headers.

// Enable directory browsing for static assets.
#define DIRECTRORY_BROWSING_ON 1

// Connection states
typedef enum { STATE_READING_REQUEST, STATE_WRITING_RESPONSE, STATE_CLOSING } connection_state;

typedef struct {
    char* name;
    char* value;
} header_t;

typedef struct {
    header_t items[MAX_HEADERS];
    size_t count;
} headers_t;

typedef struct {
    char* name;   // Parameter name
    char* value;  // Parameter value from the URL
} PathParam;

typedef struct PathParams {
    PathParam* params;    // Array of matched parameters
    size_t match_count;   // Number of matched parameters from request path.
    size_t total_params;  // Total parameters counted at startup.
} PathParams;

// HTTP Response structure
typedef struct {
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

typedef enum {
    HTTP_INVALID = -1,
    HTTP_OPTIONS,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_PATCH,
    HTTP_DELETE,
} HttpMethod;

typedef struct {
    uint8_t* memory;   // Arena memory
    size_t allocated;  // Allocated memory
    size_t capacity;   // Capacity of the arena
} Arena;

// Connection structure
typedef struct connection_t {
    int fd;                           // Client socket file descriptor
    connection_state state;           // Current connection state
    time_t last_activity;             // Timestamp of last I/O activity
    int keep_alive;                   // Keep-alive flag
    char read_buf[READ_BUFFER_SIZE];  // Buffer for incoming data
    size_t read_bytes;                // Bytes currently in read buffer
    struct request_t* request;        // HTTP request data
    response_t* response;             // HTTP response data
    Arena* arena;                     // Connection arena.
} connection_t;

// HTTP Request structure
typedef struct request_t {
    char method[8];         // HTTP method (GET, POST etc.)
    char* path;             // Requested path
    char* body;             // Request body
    size_t content_length;  // Content-Length header value
    size_t body_received;   // Bytes of body received
    size_t headers_len;     // Length of headers text in connection buffer. ie offset
    headers_t* headers;     // Request headers
    struct route_t* route;  // Matched route.
} request_t;

typedef bool (*HttpHandler)(connection_t* conn);

typedef struct route_t {
    int flags;                // Bit mask for route type. NormalRoute | StaticRoute
    char* pattern;            // dynamically allocated route pattern
    char* dirname;            // Directory name (for static routes)
    HttpMethod method;        // Http method.
    HttpHandler handler;      // Handler function pointer
    PathParams* path_params;  // Path parameters
} route_t;

// Worker thread data
typedef struct {
    int epoll_fd;
    int worker_id;
    int server_fd;
} worker_data_t;

// Global flag to keep all workers running.
static volatile sig_atomic_t server_running = 1;

static route_t global_routes[MAX_ROUTES];
static size_t global_count = 0;

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

// =================== Arena functions   ========================
Arena* arena_create(size_t capacity) {
    assert(capacity > 0);
    Arena* arena = malloc(sizeof(Arena));
    if (!arena) {
        return NULL;
    }

    arena->memory = calloc(1, capacity);
    if (!arena->memory) {
        free(arena);
        return NULL;
    }
    arena->allocated = 0;
    arena->capacity  = capacity;
    return arena;
}

void arena_destroy(Arena* arena) {
    if (!arena) return;
    free(arena->memory);
    free(arena);
}

void* arena_alloc(Arena* arena, size_t size) {
    if (arena->allocated + size > arena->capacity) {
        fprintf(stderr, "Arena out of memory\n");
        return NULL;
    }

    void* ptr = &arena->memory[arena->allocated];
    arena->allocated += size;
    return ptr;
}

char* arena_strdup(Arena* arena, const char* str) {
    size_t cap = strlen(str) + 1;
    char* dst  = arena_alloc(arena, cap);
    if (!dst) {
        return NULL;
    }

    // copy string including NULL terminator.
    (void)strlcpy(dst, str, cap);
    return dst;
}

static inline void arena_reset(Arena* arena) {
    assert(arena->capacity > 0);
    arena->allocated = 0;
}

// ==================== Header API functions ===================
headers_t* headers_new(Arena* arena) {
    headers_t* headers = arena_alloc(arena, sizeof(headers_t));
    if (!headers) return NULL;
    headers->count = 0;
    return headers;
}

bool headers_append(Arena* arena, headers_t* headers, const char* name, const char* value) {
    // Check if header already exists.
    int index = -1;
    for (size_t i = 0; i < headers->count; i++) {
        if (strcasecmp(name, headers->items[i].name) == 0) {
            index = i;
            break;
        }
    }

    // if its a new header and no space for it, bail
    if (headers->count >= MAX_HEADERS && index == -1) return false;

    header_t hdr = {
        .name  = arena_strdup(arena, name),
        .value = arena_strdup(arena, value),
    };

    if (!hdr.name || !hdr.value) return false;

    // Insert in correct position
    size_t pos = (index != -1) ? index : headers->count;

    // Increment counter if new header.
    if (index == -1) headers->count++;

    headers->items[pos] = hdr;
    return true;
}

// =================== New API Functions ========================

// Set HTTP status code and message
void conn_set_status(connection_t* conn, http_status code) {
    if (conn->response->status_code > 0) return;  // Status already set( Makes it Indempotent)

    conn->response->status_code = code;
    strlcpy(conn->response->status_message, http_status_text(code), sizeof(conn->response->status_message));
}

// Add a custom header
bool conn_writeheader(connection_t* conn, const char* name, const char* value) {
    if (!name || !value) return false;
    return headers_append(conn->arena, conn->response->headers, name, value);
}

bool conn_set_content_type(connection_t* conn, const char* content_type) {
    if (conn->response->content_type_set) return true;
    conn->response->content_type_set = conn_writeheader(conn, "Content-Type", content_type);
    return conn->response->content_type_set;
}

// Write data to response body
int conn_write(connection_t* conn, const void* data, size_t len) {
    if (!data || len == 0) return 0;

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
    if (!str) return -1;
    return conn_write(conn, str, strlen(str));
}

// Simple file serving.
// Proper file serving implementation
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

    conn->response->file_fd   = fd;
    conn->response->file_size = stat_buf.st_size;
    return true;
}

// Build the complete HTTP response
void finalize_response(connection_t* conn) {
    response_t* resp    = conn->response;
    header_t* headers   = (header_t*)&resp->headers->items;
    size_t header_count = resp->headers->count;

    if (resp->headers_written) return;

    // Set default status if not set
    if (resp->status_code == 0) {
        resp->status_code = StatusOK;
        strcpy(resp->status_message, "OK");
    }

    // Calculate total response size
    size_t header_size = 512;  // Base headers
    for (size_t i = 0; i < header_count; i++) {
        // +4, reserve for \r\n and colon and space.
        header_size += strlen(headers[i].name) + strlen(headers[i].value) + 4;
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
    int offset =
        snprintf(resp->buffer, header_size,
                 "HTTP/1.1 %d %s\r\n"
                 "Connection: %s\r\n"
                 "Content-Length: %zu\r\n",
                 resp->status_code, resp->status_message, conn->keep_alive ? "keep-alive" : "close", content_length);

    // Add custom headers
    for (size_t i = 0; i < header_count; i++) {
        offset +=
            snprintf(resp->buffer + offset, header_size - offset, "%s: %s\r\n", headers[i].name, headers[i].value);
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
bool http_method_valid(HttpMethod method) {
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
    if (!method) return HTTP_INVALID;
    if (strcmp(method, "GET") == 0) return HTTP_GET;
    if (strcmp(method, "POST") == 0) return HTTP_POST;
    if (strcmp(method, "PUT") == 0) return HTTP_PUT;
    if (strcmp(method, "PATCH") == 0) return HTTP_PATCH;
    if (strcmp(method, "DELETE") == 0) return HTTP_DELETE;
    if (strcmp(method, "OPTIONS") == 0) return HTTP_OPTIONS;
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

    r->method  = method;
    r->handler = handler;

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

    // Increment global count
    global_count++;
    return r;
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
        } else if ((*src == '%') && (src_len >= 2) && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= 'A' - 10;
            else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= 'A' - 10;
            else b -= '0';
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

static void serve_directory_listing(connection_t* conn, const char* filepath, const char* prefix) {
    (void)conn;
    (void)filepath;
    (void)prefix;
    conn_write_string(conn, "<h1>Directory Listsing Not Supported</h1>");
}

static bool static_file_handler(connection_t* conn) {
    route_t* route = conn->request->route;
    assert((route->flags & STATIC_ROUTE_FLAG) != 0);

    const char* dirname = route->dirname;

    size_t dirlen    = strlen(dirname);
    const char* path = conn->request->path;

    // Build the request static path
    const char* static_path = path + strlen(route->pattern);
    size_t static_path_len  = strlen(static_path);

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

    // TODO: Prevent directory traversal attempts
    if (is_dir(filepath)) {
        size_t filepath_len = strlen(filepath);
        // remove the trailing slash if present
        if (filepath_len > 1 && filepath[filepath_len - 1] == '/') {
            filepath[filepath_len - 1] = '\0';
            filepath_len--;
        }

        char index_file[PATH_MAX];  // uninitialized for performance
        n = snprintf(index_file, sizeof(index_file), "%s/index.html", filepath);
        if (n < 0 || n >= PATH_MAX) {
            goto path_toolong;
        }

        if (!path_exists(index_file)) {
            if (DIRECTRORY_BROWSING_ON) {
                char prefix[PATH_MAX];
                snprintf(prefix, sizeof(prefix), "%s%s", route->pattern, static_path);
                serve_directory_listing(conn, filepath, prefix);
            } else {
                conn_set_content_type(conn, "text/html");
                conn_set_status(conn, StatusForbidden);
                conn_write_string(conn, "<h1>Directory listing is disabled</h1>");
            }
            return true;
        } else {
            // Check we have enough space for "/index.html" (11 chars + null)
            if (filepath_len + 11 >= PATH_MAX) {
                goto path_toolong;
            }
            strlcat(filepath, "/index.html", sizeof(filepath));
        }
    }

    if (path_exists(filepath)) {
        const char* web_ct = get_mimetype(filepath);
        conn_set_content_type(conn, web_ct);
        return conn_servefile(conn, filepath);
    }
    return serve_404(conn);

path_toolong:
    conn_set_status(conn, StatusRequestURITooLong);
    conn_set_content_type(conn, "text/html");
    conn_write_string(conn, "<h1>Path too long</h1>");
    return true;
}

route_t* register_static_route(const char* pattern, const char* dir) {
    assert(pattern && dir);  // validate inputs

    if (strcmp(".", dir) == 0) {
        dir = "./";
    }

    if (strcmp("..", dir) == 0) {
        dir = "../";
    }

    size_t dirlen = strlen(dir);
    assert(dirlen + 1 < PATH_MAX);

    // Expand user home dir.
    char* dirname = NULL;
    if ((dirname = realpath(dir, NULL)) == NULL) {
        fprintf(stderr, "Unable to resolve path: %s\n", dir);
        exit(1);
    }

    assert(is_dir(dirname));

    // Todo: Detect directory traversal here...

    if (dirname[dirlen - 1] == '/') {
        dirname[dirlen - 1] = '\0';  // Remove trailing slash
    }

    route_t* r = route_register(pattern, HTTP_GET, static_file_handler);
    r->flags   = STATIC_ROUTE_FLAG;
    r->dirname = dirname;
    printf("Registering directory: %s\n", dirname);
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
bool match_path_parameters(Arena* arena, const char* pattern, const char* url_path, PathParams* path_params) {
    if (!path_params || !pattern || !url_path) return false;

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
            if (*pat != '}') return false;

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
            if (*pat != *url) return false;
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

const char* get_path_param(const PathParams* params, const char* name) {
    if (!params || !name) return NULL;

    for (size_t i = 0; i < params->match_count; i++) {
        if (strcmp(params->params[i].name, name) == 0) {
            return params->params[i].value;
        }
    }
    return NULL;
}

route_t* route_match(connection_t* conn, HttpMethod method) {
    route_t* current  = global_routes;
    route_t* end      = global_routes + global_count;
    const char* url   = conn->request->path;
    size_t url_length = strlen(url);

    // TODO: Handle MethodNotAllowed
    // TODO: Optimize this with pre-sorted routes by method so we can have early exit.
    // TODO: Optionally implement a Bloom Filter.

    while (current < end) {
        __builtin_prefetch(current + 4, 0, 1);

        if (method == current->method) {
            if ((current->flags & NORMAL_ROUTE_FLAG) != 0) {
                if (match_path_parameters(conn->arena, current->pattern, url, current->path_params)) {
                    return current;
                }
            } else if ((current->flags & STATIC_ROUTE_FLAG) != 0) {
                size_t pat_length = strlen(current->pattern);

                // Compare only the prefix, for the static files
                if (pat_length <= url_length) {
                    if (memcmp(current->pattern, url, pat_length) == 0) {
                        return current;
                    }
                }
            }
        }
        current++;
    }

    return NULL;
}

// ====================================================================

void set_nonblocking(int fd) {
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

int create_server_socket(int port) {
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

request_t* create_request(Arena* arena) {
    request_t* req = arena_alloc(arena, sizeof(request_t));
    if (!req) return NULL;
    memset(req, 0, sizeof(request_t));

    req->headers = headers_new(arena);
    if (!req->headers) {
        return NULL;
    }

    return req;
}

response_t* create_response(Arena* arena) {
    response_t* resp = arena_alloc(arena, sizeof(response_t));
    if (!resp) return NULL;

    memset(resp, 0, sizeof(response_t));
    resp->file_fd = -1;

    resp->headers = headers_new(arena);
    if (!resp->headers) {
        return NULL;
    }
    return resp;
}

void free_request(request_t* req) {
    if (!req) return;
    if (req->body) free(req->body);
}

void free_response(response_t* resp) {
    if (!resp) return;

    if (resp->buffer) free(resp->buffer);
    if (resp->body_data) free(resp->body_data);
}

bool reset_connection(connection_t* conn) {
    conn->state         = STATE_READING_REQUEST;
    conn->read_bytes    = 0;
    conn->last_activity = time(NULL);
    conn->keep_alive    = 1;

    // Omitted for performance
    // memset(conn->read_buf, 0, READ_BUFFER_SIZE);

    if (conn->request) {
        free_request(conn->request);
    }

    if (conn->response) {
        free_response(conn->response);
    }

    // If we have an arena, reset the memory.
    if (conn->arena) {
        arena_reset(conn->arena);
    } else {
        // Create the and initialize arena.
        conn->arena = arena_create(ARENA_CAPACITY);
        if (!conn->arena) return false;
    }

    conn->request  = create_request(conn->arena);
    conn->response = create_response(conn->arena);
    return (conn->request && conn->response);
}

int should_keep_alive(const char* request) {
    char* connection_hdr = strstr(request, "Connection:");
    if (!connection_hdr) {
        return 1;
    }

    char* value = connection_hdr + strlen("Connection:");
    while (*value == ' ' || *value == '\t')
        value++;

    if (strncasecmp(value, "close", 5) == 0) {
        return 0;
    }

    return 1;
}

int conn_accept(int server_fd, int worker_id) {
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
    connection_t* conn = malloc(sizeof(connection_t));
    if (!conn) {
        perror("malloc");
        close(client_fd);
        return;
    }

    memset(conn, 0, sizeof(connection_t));
    conn->fd = client_fd;

    if (!reset_connection(conn)) {
        fprintf(stderr, "Error in reset_connection\n");
        goto error;
    }

    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
    event.data.ptr = conn;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
        perror("epoll_ctl");
        goto error;
    }
    return;

error:
    if (conn->arena) arena_destroy(conn->arena);
    free(conn);
    close(client_fd);
}

static void copy_bodyfrom_buf(connection_t* conn) {
    if (conn->state == STATE_READING_REQUEST && conn->request->body &&
        conn->request->body_received < conn->request->content_length && conn->request->headers_len > 0) {
        size_t new_body = conn->read_bytes - conn->request->headers_len - conn->request->body_received;
        if (new_body > 0) {
            size_t copy_len = ((conn->request->body_received + new_body) > conn->request->content_length)
                                  ? conn->request->content_length - conn->request->body_received
                                  : new_body;

            // Copy partial body read in initial recv.
            memcpy(conn->request->body + conn->request->body_received,
                   conn->read_buf + conn->request->headers_len + conn->request->body_received, copy_len);
            conn->request->body_received += copy_len;
            conn->request->body[conn->request->body_received] = '\0';
        }
    }
}

static bool parse_request_headers(connection_t* conn) {
    const char* ptr = conn->read_buf;
    const char* end = ptr + conn->request->headers_len;

    while (ptr < end) {
        // Parse header name
        const char* colon = (const char*)memchr(ptr, ':', end - ptr);
        if (!colon) break;  // no more headers

        size_t name_len = colon - ptr;
        char* name      = arena_alloc(conn->arena, name_len + 1);
        if (!name) return false;

        memcpy(name, ptr, name_len);
        name[name_len] = '\0';

        // Move to header value
        ptr = colon + 1;
        while (ptr < end && *ptr == ' ')
            ptr++;

        // Parse header value
        const char* eol = (const char*)memchr(ptr, '\r', end - ptr);
        if (!eol || eol + 1 >= end || eol[1] != '\n') break;

        size_t value_len = eol - ptr;
        char* value      = arena_alloc(conn->arena, value_len + 1);
        if (!value) return false;

        memcpy(value, ptr, value_len);
        value[value_len] = '\0';

        if (!headers_append(conn->arena, conn->request->headers, name, value)) {
            return false;
        }

        ptr = eol + 2;  // Skip CRLF
    }

    return true;
}

static inline bool parse_content_length(connection_t* conn) {
    size_t length = conn->request->headers_len;
    char* ptr     = strcasestr(conn->read_buf, "Content-Length:");
    if (ptr) {
        // cl_ptr += strlen("Content-Length:");
        ptr += 15;  // move after colon.

        // Trim white space, keeping within blounds.
        while ((*ptr == ' ' || *ptr == '\t') && ptr < conn->read_buf + length)
            ptr++;

        // Parse content length into number
        conn->request->content_length = strtoul(ptr, NULL, 10);

        // Must be within allowed body size.
        if (conn->request->content_length > MAX_BODY_SIZE) {
            fprintf(stderr, "Body exceeds maximum allowed size: %lu bytes", (size_t)MAX_BODY_SIZE);
            return false;
        }
    }

    return true;
}

static bool parse_request_body(connection_t* conn, size_t headers_len) {
    size_t body_available = conn->read_bytes - headers_len;

    if (conn->request->content_length > 0) {
        conn->request->body = malloc(conn->request->content_length + 1);
        if (!conn->request->body) {
            perror("malloc body");
            return false;
        }

        size_t copy_len =
            (body_available > conn->request->content_length) ? conn->request->content_length : body_available;
        memcpy(conn->request->body, conn->read_buf + headers_len, copy_len);
        conn->request->body_received  = copy_len;
        conn->request->body[copy_len] = '\0';

        // copy part of body read with headers.
        copy_bodyfrom_buf(conn);

        // Read complete body.
        while (conn->request->body_received < conn->request->content_length) {
            size_t remaining = conn->request->content_length - conn->request->body_received;
            ssize_t count    = read(conn->fd, conn->request->body + conn->request->body_received, remaining);
            if (count == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    usleep(1000);
                    continue;  // try again
                } else {
                    perror("read");
                    return false;
                }
            } else if (count == 0) {
                perror("read");
                return false;
            }
            conn->request->body_received += count;
        }
    }
    return true;
}

void process_request(connection_t* conn) {
    char* end_of_headers = strstr(conn->read_buf, "\r\n\r\n");
    if (!end_of_headers) return;  // still reading headers

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

    conn->keep_alive = should_keep_alive(conn->read_buf);

    // try to first match request before even parsing headers, query params
    // content-length and reading the body.
    HttpMethod method = http_method_from_string(conn->request->method);
    route_t* route    = route_match(conn, method);
    if (route) {
        // Set the route to request.
        conn->request->route = route;

        // Parse headers.
        if (!parse_request_headers(conn)) {
            fprintf(stderr, "error parsing request headers\n");
            conn->state = STATE_CLOSING;
            return;
        };

        // Parse content length.
        if (!parse_content_length(conn)) {
            fprintf(stderr, "error parsing content length\n");
            conn->state = STATE_CLOSING;
            return;
        }

        // Read request body.
        if (!parse_request_body(conn, headers_len)) {
            fprintf(stderr, "error parsing request body\n");
            conn->state = STATE_CLOSING;
            return;
        }
    }

    bool handler_success = true;
    if (route) {
        handler_success = route->handler(conn);
    }

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

    if (conn->response->buffer) {
        conn->state         = STATE_WRITING_RESPONSE;
        conn->last_activity = time(NULL);
    } else {
        conn->state = STATE_CLOSING;
    }
}

void handle_read(int epoll_fd, connection_t* conn) {
    ssize_t count = read(conn->fd, conn->read_buf + conn->read_bytes, READ_BUFFER_SIZE - conn->read_bytes - 1);
    if (count == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read");
            conn->state = STATE_CLOSING;
        }
        return;
    } else if (count == 0) {
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
ssize_t conn_sendfile(connection_t* conn) {
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

void close_connection(int epoll_fd, connection_t* conn, int worker_id) {
    (void)worker_id;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);

    if (conn->request) free_request(conn->request);
    if (conn->response) free_response(conn->response);
    if (conn->arena) arena_destroy(conn->arena);
    free(conn);
}

void check_timeouts(connection_t* conn, int worker_id) {
    time_t now = time(NULL);
    if (now - conn->last_activity > CONNECTION_TIMEOUT) {
        printf("Worker %d: Connection fd %d timed out\n", worker_id, conn->fd);
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

                check_timeouts(conn, worker_id);

                if (conn->state == STATE_CLOSING) {
                    close_connection(epoll_fd, conn, worker_id);
                }
            }
        }
    }

    return NULL;
}

int run(int port) {
    int server_fd = create_server_socket(port);
    set_nonblocking(server_fd);

    pthread_t workers[NUM_WORKERS];
    worker_data_t worker_data[NUM_WORKERS];

    install_signal_handler();

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

// =================== Example Handlers Using New API ========================

bool hello_world_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, "text/plain");
    conn_write(conn, "Hello, World!", 13);
    return true;
}

bool json_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, "application/json");

    const char* json = "{\"message\": \"Hello from JSON API\", \"status\": \"success\"}";
    conn_write(conn, json, strlen(json));
    return true;
}

bool echo_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, "text/plain");

    // Echo request method and path
    conn_write(conn, "Method: ", 8);
    conn_write(conn, conn->request->method, strlen(conn->request->method));
    conn_write(conn, "\nPath: ", 7);
    conn_write(conn, conn->request->path, strlen(conn->request->path));

    // Echo body if present
    if (conn->request->body && conn->request->body_received > 0) {
        conn_write(conn, "\nBody: ", 7);
        conn_write(conn, conn->request->body, conn->request->body_received);
    }

    return true;
}

__attribute__((destructor())) void cleanup(void) {
    for (size_t i = 0; i < global_count; i++) {
        route_t* r = &global_routes[i];
        free(r->pattern);

        if (r->dirname) {
            free(r->dirname);
        }
    }
}

int main() {
    // Register routes using the new API
    route_register("/", HTTP_GET, hello_world_handler);
    route_register("/hello", HTTP_GET, hello_world_handler);
    route_register("/json", HTTP_GET, json_handler);
    route_register("/echo", HTTP_GET, echo_handler);
    route_register("/echo", HTTP_POST, echo_handler);

    register_static_route("/static", "./");

    return run(8080);
}
