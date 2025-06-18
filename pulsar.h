#ifndef PULSAR_H
#define PULSAR_H

#include <limits.h>
#include <signal.h>
#include <stdarg.h>
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
#include <inttypes.h>

// Internal Libs.
#include "arena.h"
#include "status_code.h"
#include "mimetype.h"
#include "headers.h"

#define NUM_WORKERS        8          // Number of workers.
#define MAX_EVENTS         2048       // Maximum events for epoll->ready queue.
#define READ_BUFFER_SIZE   2048       // Buffer size for incoming statusline + headers.
#define CONNECTION_TIMEOUT 30         // Keep-Alive connection timeout in seconds
#define MAX_BODY_SIZE      (2 << 20)  // Max Request body allowed.
#define ARENA_CAPACITY     8 * 1024   // Arena memory per connection(8KB). Expand to 16 KB if required.
#define MAX_ROUTES         64         // Maximum number of routes

#ifdef __cplusplus
extern "C" {
#endif

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

// Connection states
typedef enum {
    STATE_READING_REQUEST,
    STATE_WRITING_RESPONSE,
    STATE_CLOSING,
} connection_state;

typedef struct connection_t {
    char read_buf[READ_BUFFER_SIZE];  // Buffer for incoming data of size READ_BUFFER_SIZE (arena allocated)
    struct request_t* request;        // HTTP request data
    response_t* response;             // HTTP response data
    Arena* arena;                     // Memory arena for allocations

    // 4-byte fields
    int fd;                // Client socket file descriptor
    time_t last_activity;  // Timestamp of last I/O activity
    size_t read_bytes;     // Bytes currently in read buffer

    // Small fields (1-2 bytes)
    connection_state state;  // Current connection state (enum, likely 1-4 bytes)
    uint8_t keep_alive;      // Keep-alive flag (bool, 1 byte)
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

typedef bool (*HttpHandler)(connection_t* conn);

typedef struct route_t {
    int flags;                // Bit mask for route type. NormalRoute | StaticRoute
    char* pattern;            // dynamically allocated route pattern
    char* dirname;            // Directory name (for static routes)
    HttpMethod method;        // Http method.
    HttpHandler handler;      // Handler function pointer
    PathParams* path_params;  // Path parameters
} route_t;

#ifdef __cplusplus
}
#endif

// Register a new route.
route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler);

// Register a new route to server static file in directory at dir.
// dir must exist and pattern not NULL.
// Handles serving of index.html at root of directory. File System Traversal
// `should` be blocked.
route_t* register_static_route(const char* pattern, const char* dir);

// Serve a file with given filename efficiently with sendfile.
bool conn_servefile(connection_t* conn, const char* filename);

// Send a null-terminated string.
int conn_write_string(connection_t* conn, const char* str);

// Send a 404 page as text/html.
int serve_404(connection_t* conn);

// Write data to response body.
int conn_write(connection_t* conn, const void* data, size_t len);

// Send a formatted message with variadic arguments.
// Uses similar format as printf.
__attribute__((format(printf, 2, 3))) int conn_writef(connection_t* conn, const char* fmt, ...);

// Start server on port and run the server loop forever.
// Stop with SIGINT or SIGTERM.
int pulsar_run(int port);

// Get value for a query parameter if present or NULL.
const char* query_get(connection_t* conn, const char* name);

// Get the path parameter value by name if present or NULL.
const char* get_path_param(connection_t* conn, const char* name);

// Return an HttpMethod enum constant from string.
// Returns HTTP_INVALID if not supported.
HttpMethod http_method_from_string(const char* method);

// Convert HttpMethod enum variant to string.
const char* http_method_to_string(const HttpMethod method);

// If http method is safe. (GET / OPTIONS)
static inline bool is_safe_method(HttpMethod method) {
    return method == HTTP_GET || method == HTTP_OPTIONS;
}

static inline unsigned long parse_ulong(const char* value, bool* valid) {
    assert(valid);

    *valid        = false;
    char* endptr  = NULL;
    errno         = 0;
    uintmax_t num = strtoumax(value, &endptr, 10);

    // Overflow or underflow.
    if ((num > ULONG_MAX) || (errno == ERANGE && (num == 0 || num == UINTMAX_MAX))) {
        return 0;
    }

    // Invalid value.
    if (*endptr != '\0' || endptr == value) {
        return 0;
    }

    *valid = true;
    return num;
}

// Set content-type header. This is indempotent.
bool conn_set_content_type(connection_t* conn, const char* content_type);

// Set a header.
bool conn_writeheader(connection_t* conn, const char* name, const char* value);

// Set HTTP status code.
void conn_set_status(connection_t* conn, http_status code);

#endif  // PULSAR_H
