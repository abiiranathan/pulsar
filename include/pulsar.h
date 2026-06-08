#ifndef PULSAR_H
#define PULSAR_H

#include <signal.h>
#include <sys/uio.h>
#include <time.h>

#include "constants.h"
#include "events.h"
#include "locals.h"
#include "routing.h"
#include "status.h"
#include "types.h"
#include "url.h"

extern volatile sig_atomic_t server_running;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Response object structure
 *
 * Contains all data related to the HTTP response being constructed
 */
typedef struct response_t response_t;

/**
 * @brief Connection object structure
 *
 * Represents a client connection and maintains all connection state
 */
typedef struct pulsar_conn PulsarConn;

/**
 * @brief Request object structure
 *
 * Contains all data related to the incoming HTTP request
 */
typedef struct request_t request_t;

// Callback function pointer called after the handler runs before writing
// data to the socket. Ideal for logging. total_ns is the server processing time
// and does not include network IO for sending the data. The userdata pointer
// is the same pointer set via pulsar_set_handler_userdata.
typedef void (*PulsarCallback)(PulsarCtx* ctx, uint64_t total_ns);

// Callback to create a new context object(Locals) that is passed per-request.
typedef Locals* (*LocalsCreateCallback)();

/**
 * @brief Starts the Pulsar HTTP server event loop
 *
 * @param addr The IP address to bind to (NULL for all interfaces)
 * @param port The TCP port to listen on. Valid range is 1-65535.
 * @return int 0 on success, non-zero on error
 */
int pulsar_run(const char* addr, int port);

// Re-arm client socket for another write and yield from
// on_write callback giving control back to the event loop.
#define yield_write(conn)                                         \
    event_mod_write(conn->owner_queue_fd, conn->client_fd, conn); \
    return;

// Re-arm client socket for another read and yield from
// on_read callback giving control back to the event loop.
#define yield_read(conn)                                         \
    event_mod_read(conn->owner_queue_fd, conn->client_fd, conn); \
    return;

/** Returns the worker id of the current worker.
Can be used as an index for per-thread objects because each worker runs in a
seperate thread. The returned IDs are in the range 0 - NUM_WORKERS.
*/
int conn_worker_id(PulsarConn* conn);

// Returns true if connection is still open.
bool conn_is_open(PulsarConn* conn);

/**
 * @brief Registers global middleware functions
 *
 * @param middleware Array of middleware handler functions
 * @param count Number of middleware functions in array
 */
void use_global_middleware(HttpHandler* middleware, size_t count);

/**
 * @brief Registers route-specific middleware functions
 *
 * @param route The route to attach middleware to
 * @param middleware Array of middleware handler functions
 * @param count Number of middleware functions in array
 */
void use_route_middleware(route_t* route, HttpHandler* middleware, size_t count);

// Set a global userdata pointer which will be provided as the second argument
// to every handler and middleware. The pointer is owned by the caller.
void pulsar_set_handler_userdata(void* userdata);

// Get the currently set handler userdata pointer.
void* pulsar_get_handler_userdata(void);

/** @brief Set a post_handler callback that is called after the handler runs
 * before writing data to the socket.
 * @param cb User-provided callback function pointer.
 * @param fd File descriptor for the logger (must be set to enable logging).
 * @note The callback is ideal for logging request latency and other metrics.
 * The callback receives the total processing time in nanoseconds (excluding
 * network I/O) and a pointer to the request context. 
 * The userdata pointer in the context is the same pointer set via pulsar_set_handler_userdata.
 * @note The callback must be set before starting the server and 
 * can only be set once.
 * @return true If async logger background thread was successfully initialized. 
 */
bool pulsar_set_callback(PulsarCallback cb, int fd);

/** Pulsar Async Logger
* ---------------------
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
void pulsar_logger(PulsarCtx* ctx, uint64_t total_ns);

// Set a user-owned value pointer to the context with a callback function to
// free the value. The function may be NULL if the value is not to be freed.
// Returns true on success.
bool pulsar_set(PulsarConn* conn, const char* key, void* value, ValueFreeFunc free_func);

#include <stddef.h>  // for size_t, NULL (C11)
#include <stdlib.h>  // for malloc, NULL
#include <string.h>  // for strlen, memcpy

/**
 * @brief Allocate memory of at least 'size' bytes that is managed by the
 * server.
 *
 * The returned memory is valid only for the duration of the current request
 * handler. It must not be freed by the caller and will become invalid once the
 * handler returns (the underlying arena is reset after each request).
 *
 * @param conn  Connection handle (used to access the per-request arena).
 * @param size  Minimum number of bytes to allocate.
 * @return Pointer to the allocated memory, or NULL if allocation fails.
 */
void* pulsar_alloc(PulsarConn* conn, size_t size);

/**
 * @brief Duplicate a string using the request-scoped arena allocator.
 *
 * The returned string is valid only for the duration of the current request
 * handler and must not be freed by the caller.
 *
 * @param conn Connection handle (required for arena allocation).
 * @param str  NUL-terminated string to duplicate. May be NULL.
 * @return Pointer to the duplicated string, or NULL if allocation fails or str
 * is NULL.
 */
static inline char* pulsar_strdup(PulsarConn* conn, const char* str) {
    if (str == NULL) { return NULL; }

    size_t len = strlen(str);
    char* dup = pulsar_alloc(conn, len + 1);
    if (dup != NULL) {
        memcpy(dup, str, len + 1);  // includes terminating NUL
    }
    return dup;
}

// Get a thread-safe arena for this connection.
// It's lifetime is tied to the handler and will be reset or destroyed when
// the handler returns. Use this if you are building custom allocators for other
// libs like yyjson e.t.c.
Arena* pulsar_get_arena(PulsarConn* conn);

/**
 * @brief Allocate an array of 'nmemb' elements of 'size' bytes each using the
 * request-scoped arena.
 *
 * Equivalent to calloc() semantics (zero-initialized memory), but backed by the
 * per-request arena. The returned memory must not be freed by the caller.
 *
 * @param conn  Connection handle.
 * @param nmemb Number of elements.
 * @param size  Size of each element in bytes.
 * @return Pointer to the allocated zero-initialized memory, or NULL on failure
 * or overflow.
 */
static inline void* pulsar_calloc(PulsarConn* conn, size_t nmemb, size_t size) {
    /* Guard against overflow in nmemb * size */
    if (nmemb != 0 && size > SIZE_MAX / nmemb) { return NULL; }

    size_t total = nmemb * size;
    void* ptr = pulsar_alloc(conn, total);
    if (ptr != NULL) { memset(ptr, 0, total); }
    return ptr;
}

/**
 * @brief Re-allocate arena-backed memory to a new size, preserving existing
 * content.
 *
 * This function allocates a new block with at least 'new_size' bytes, copies up
 * to 'old_size' bytes from the old pointer (or all available if new_size is
 * smaller), and returns the new pointer. The old pointer becomes invalid after
 * this call.
 *
 * The returned memory follows the same rules as pulsar_alloc(): it must not be
 * freed and is valid only until the end of the current request handler.
 *
 * @param conn     Connection handle.
 * @param ptr      Previous pointer returned by pulsar_alloc(), pulsar_strdup(),
 * etc. May be NULL (treated as allocation of new block).
 * @param old_size Number of valid bytes currently pointed to by 'ptr'.
 *                 Must be exact if ptr != NULL.
 * @param new_size Desired minimum size in bytes for the new block.
 * @return New pointer with at least 'new_size' bytes, containing the previous
 * content (truncated or unchanged as appropriate), or NULL on failure or
 * overflow.
 */
static inline void* pulsar_realloc(PulsarConn* conn, void* ptr, size_t old_size, size_t new_size) {
    /* Handle NULL ptr as pure allocation */
    if (ptr == NULL) { return pulsar_alloc(conn, new_size); }

    /* Guard against overflow when comparing sizes */
    if (new_size > SIZE_MAX) { return NULL; }

    void* new_ptr = pulsar_alloc(conn, new_size);
    if (new_ptr == NULL) { return NULL; }

    /* Determine how many bytes to copy: the minimum of old_size and new_size */
    size_t copy_size = old_size < new_size ? old_size : new_size;

    if (copy_size > 0) { memcpy(new_ptr, ptr, copy_size); }
    return new_ptr;
}

// Get a context value stored with pulsar_set.
void* pulsar_get(PulsarConn* conn, const char* key);

// Delete the context value stored with pulsar_set.
void pulsar_delete(PulsarConn* conn, const char* key);

/**
 * @brief Serves a file as the response
 *
 * @param conn The connection object
 * @param filename Path to file to serve
 * @return true File was successfully opened
 * @return false File could not be opened
 */
bool conn_servefile(PulsarConn* conn, const char* filename);

/**
 * @brief Writes a string to the response body
 *
 * @param conn The connection object
 * @param str String to write (NULL-terminated)
 * @return int Number of bytes written, or -1 on error
 */
int conn_write_string(PulsarConn* conn, const char* str);

/**
 * @brief Sends a 404 Not Found response
 *
 * @param conn The connection object
 * @return int Number of bytes written
 */
int conn_notfound(PulsarConn* conn);

/**
 * @brief Writes binary data to the response body
 *
 * @param conn The connection object
 * @param data Pointer to data to write
 * @param len Length of data in bytes
 * @return int Number of bytes written, or -1 on error
 */
int conn_write(PulsarConn* conn, const void* data, size_t len);

/**
 * @brief Writes formatted string to response body. If the data is below 1024
 * bytes uses a stack buffer, otherwise dynamically allocates.
 * @param conn The connection object
 * @param fmt printf-style format string
 * @param ... Format arguments
 * @return int Number of bytes written, or -1 on error
 */
int conn_writef(PulsarConn* conn, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

/**
 * @brief Aborts request processing
 *
 * Stops middleware and handler execution immediately
 *
 * @param conn The connection object
 */
void conn_abort(PulsarConn* conn);

/**
 * @brief Sets the Content-Type header
 *
 * @param conn The connection object
 * @param content_type Content type string
 */
void conn_set_content_type(PulsarConn* conn, StrSlice content_type);

/**
 * @brief Adds a header to the response. name and value MUST be valid
 * null-terminated strings and not empty.
 * @param conn The connection object
 * @param name Header name string slice. e.g SS_LIT("Content-Type")
 * @param value Header value string slice. e.g SS_LIT("application/json")
 */
void conn_writeheader(PulsarConn* conn, StrSlice name, StrSlice value);

/**
 * @brief Adds raw pre-formatted header(s) to the response.
 * Each header must be terminated with \r\n.
 * This is the most perfomant variant of the 3 header writing functions.
 * @param conn The connection object
 * @param header Pre-formatted header.
 * @param value Length of the header excluding the null-terminator.
 */
void conn_writeheader_raw(PulsarConn* conn, const char* header, size_t length);

/**
 * @brief Sends a complete response
 *
 * @param conn The connection object
 * @param status HTTP status code
 * @param data Response body data
 * @param length Length of response body
 */
void conn_send(PulsarConn* conn, http_status status, const void* data, size_t length);

/**
 * @brief Sends a JSON response
 * @param conn The connection object
 * @param status HTTP status code
 * @param json Null-terminated JSON string
 * @param length Length of response body
 */
void conn_send_json(PulsarConn* conn, http_status status, const char* json, size_t length);

/**
 * @brief Sends an HTML response
 * @param conn The connection object
 * @param status HTTP status code
 * @param html Null-terminated HTML string
 * @param length Length of response body
 */
void conn_send_html(PulsarConn* conn, http_status status, const char* html, size_t length);

/**
 * @brief Sends a plain text response
 * @param conn The connection object
 * @param status HTTP status code
 * @param text Null-terminated text string
 * @param length Length of response body
 */
void conn_send_text(PulsarConn* conn, http_status status, const char* text, size_t length);

/**
 * @brief Sends a redirect response
 * @param conn The connection object
 * @param location URL to redirect to
 * @param permanent Use 301 (permanent) instead of 302 (temporary)
 */
void conn_send_redirect(PulsarConn* conn, const char* location, bool permanent);

/**
 * @brief Sends an XML response
 * @param conn The connection object
 * @param status HTTP status code
 * @param xml Null-terminated XML string
 * @param length Length of response body
 */
void conn_send_xml(PulsarConn* conn, http_status status, const char* xml, size_t length);

/**
 * @brief Sends a JavaScript response
 * @param conn The connection object
 * @param status HTTP status code
 * @param javascript Null-terminated JS string
 * @param length Length of response body
 */
void conn_send_javascript(PulsarConn* conn, http_status status, const char* javascript, size_t length);

/**
 * @brief Sends a CSS response
 * @param conn The connection object
 * @param status HTTP status code
 * @param css Null-terminated CSS string
 * @param length Length of response body
 */
void conn_send_css(PulsarConn* conn, http_status status, const char* css, size_t length);

// Start chunked transfer. Stop by calling conn_end_chunked_transfer.
void conn_start_chunked_transfer(PulsarConn* conn, int max_age_seconds);

// Write a chunk into response after calling 'conn_start_chunked_transfer'.
// Returns the number of bytes written into the socket. (including chunk
// headers)
ssize_t conn_write_chunk(PulsarConn* conn, const void* data, size_t size);

// End chunked transfer.
void conn_end_chunked_transfer(PulsarConn* conn);

#define WITH_SSE_CONNECTION(conn, block)            \
    do {                                            \
        conn_start_sse(conn);                       \
        block;                                      \
        if (conn_is_open(conn)) conn_end_sse(conn); \
    } while (0)

#define WITH_CHUNKED_TRANSFER(conn, block)                       \
    do {                                                         \
        conn_start_chunked_transfer(conn, 0);                    \
        block;                                                   \
        if (conn_is_open(conn)) conn_end_chunked_transfer(conn); \
    } while (0)

typedef struct {
    StrSlice data;
    StrSlice event;
    StrSlice id;
} SSEvent;

#define SSE_EVENT_INIT(data_, event_, id_)              \
    (SSEvent) {                                         \
        .data = (data_), .event = (event_), .id = (id_) \
    }

// Start SSE event.
void conn_start_sse(PulsarConn* conn);

/**
 * @brief Sends an event stream response (SSE)
 * @param conn The connection object
 * @param evt Pointer to sse_event_t struct.
 */
void conn_send_event(PulsarConn* conn, const SSEvent* evt);

// End SSE event.
void conn_end_sse(PulsarConn* conn);

/**
 * @brief Write multiple pre-formatted headers at once into response.
 *
 * @param conn The connection object.
 * @param headers The vector of headers.
 * @param count The number of headers.
 */
void conn_writeheaders_vec(PulsarConn* conn, const struct iovec* headers, size_t count);

/**
 * @brief Sets the HTTP response status and returns the status text.
 *
 * @param conn The connection object
 * @param code HTTP status code
 * @return void
 */
void conn_set_status(PulsarConn* conn, http_status code);

/**
 * @brief Gets a query parameter value
 *
 * @param conn The connection object
 * @param name Parameter name
 * @return A string slice for query. It is empty(but valid) if query not found.
 */
StrSlice query_get(PulsarConn* conn, const char* name);

/**
 * @brief Gets all query parameters
 *
 * @param conn The connection object
 * @return headers_t* Map of all query parameters
 */
headers_t* query_params(PulsarConn* conn);

/**
 * @brief Gets the request headers
 *
 * @param conn The connection object
 * @return The headers fixed-size array.
 */
const headers_t* req_headers(PulsarConn* conn);

/**
 * @brief Gets a request header value
 *
 * @param conn The connection object
 * @param name Header name
 * @return A string slice for header matching name. It is empty(but valid) if not found.
 */
StrSlice req_header_get(PulsarConn* conn, const char* name);

/**
 * @brief Gets a response header value
 *
 * @param conn The connection object
 * @param name Header name
 * @return A dynamically allocated header value (char *) if it exists or NULL
 * otherwise.
 */
char* res_header_get(PulsarConn* conn, const char* name);

/**
 * @brief Gets a response header value
 *
 * @param conn The connection object
 * @param name Header name
 * @param dest The destination buffer to write the header value.
 * @param dest_size The destination buffer size.
 * @return true on success or false if buffer is small or header does not exist.
 */
bool res_header_get_buf(PulsarConn* conn, const char* name, char* dest, size_t dest_size);

/** @brief Returns the response status code. */
http_status res_get_status(PulsarConn* conn);

/**
 * @brief Gets the request body data. 
 * 
 * @param conn The connection object
 * @return const char* request body or NULL if none
 */
char* req_body(PulsarConn* conn);

/**
 * @brief Gets the request body string slice. 
 * 
 * @param conn The connection object
 * @return Request body slice or NULL if none
 */
StrSlice req_body_slice(PulsarConn* conn);

/**
 * @brief Gets the request method
 *
 * @param conn The connection object
 * @return const char* HTTP method string
 */
const char* req_method(PulsarConn* conn);

/**
 * @brief Gets the request path
 *
 * @param conn The connection object
 * @return const char* Request path
 */
const char* req_path(PulsarConn* conn);

/**
 * @brief Gets a path parameter value
 *
 * @param conn The connection object
 * @param name Parameter name
 * @return const char* Parameter value or NULL if not found
 */
const char* get_path_param(PulsarConn* conn, const char* name);

// Read-Only request data.
typedef struct Request {
    const char* path;           // Request path
    const char* method;         // HTTP method (GET, POST etc.)
    StrSlice body;              // Request body. The body.data ptr is guaranteed to be NULL-terminated.
    const char* route_pattern;  // Matched route pattern(has static lifetime)
} Request;

/**
 * @brief Populates all the request metadata.
 *  Must not be modified by the caller.
 * @param req Pointer to Request structure and must be a valid pointer.
 */
Request conn_get_request_metadata(PulsarConn* conn);

// Our structure are defined.
#define PulsarConnDef 1

#ifdef __cplusplus
}
#endif

#endif /* PULSAR_H */
