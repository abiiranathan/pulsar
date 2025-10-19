#ifndef PULSAR_H
#define PULSAR_H

#include <signal.h>
#include <sys/uio.h>
#include <time.h>
#include "constants.h"
#include "content_types.h"
#include "locals.h"
#include "routing.h"
#include "status_code.h"
#include "utils.h"

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
typedef struct connection_t connection_t;

/**
 * @brief Request object structure
 *
 * Contains all data related to the incoming HTTP request
 */
typedef struct request_t request_t;

// Callback function pointer called after the handler runs before writing
// data to the socket. Ideal for logging. Note that total_ns is the server processing time
// and does not include network IO for sending the data.
typedef void (*PulsarCallback)(connection_t* conn, uint64_t total_ns);

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

// Returns true if connection is still open.
bool conn_is_open(connection_t* conn);

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

/** @brief Set a post_handler callback that is called after the handler runs
 * before writing data to the socket.
 */
void pulsar_set_callback(PulsarCallback cb);

// Set a user-owned value pointer to the context with a callback function to free the value.
// The function may be NULL if the value is not to be freed.
// Returns true on success.
bool pulsar_set(connection_t* conn, const char* key, void* value, ValueFreeFunc free_func);

// Get a context value stored with pulsar_set.
void* pulsar_get(connection_t* conn, const char* key);

// Delete the context value stored with pulsar_set.
void pulsar_delete(connection_t* conn, const char* key);

/**
 * @brief Serves a file as the response
 *
 * @param conn The connection object
 * @param filename Path to file to serve
 * @return true File was successfully opened
 * @return false File could not be opened
 */
bool conn_servefile(connection_t* conn, const char* filename);

/**
 * @brief Writes a string to the response body
 *
 * @param conn The connection object
 * @param str String to write (NULL-terminated)
 * @return int Number of bytes written, or -1 on error
 */
int conn_write_string(connection_t* conn, const char* str);

/**
 * @brief Sends a 404 Not Found response
 *
 * @param conn The connection object
 * @return int Number of bytes written
 */
int conn_notfound(connection_t* conn);

/**
 * @brief Writes binary data to the response body
 *
 * @param conn The connection object
 * @param data Pointer to data to write
 * @param len Length of data in bytes
 * @return int Number of bytes written, or -1 on error
 */
int conn_write(connection_t* conn, const void* data, size_t len);

/**
 * @brief Writes formatted string to response body. If the data is below 1024 bytes
 * uses a stack buffer, otherwise dynamically allocates.
 * @param conn The connection object
 * @param fmt printf-style format string
 * @param ... Format arguments
 * @return int Number of bytes written, or -1 on error
 */
int conn_writef(connection_t* conn, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

/**
 * @brief Aborts request processing
 *
 * Stops middleware and handler execution immediately
 *
 * @param conn The connection object
 */
void conn_abort(connection_t* conn);

/**
 * @brief Sends a complete response
 *
 * @param conn The connection object
 * @param status HTTP status code
 * @param data Response body data
 * @param length Length of response body
 */
void conn_send(connection_t* conn, http_status status, const void* data, size_t length);

/**
 * @brief Sends a JSON response
 * @param conn The connection object
 * @param status HTTP status code
 * @param json Null-terminated JSON string
 */
void conn_send_json(connection_t* conn, http_status status, const char* json);

/**
 * @brief Sends an HTML response
 * @param conn The connection object
 * @param status HTTP status code
 * @param html Null-terminated HTML string
 */
void conn_send_html(connection_t* conn, http_status status, const char* html);

/**
 * @brief Sends a plain text response
 * @param conn The connection object
 * @param status HTTP status code
 * @param text Null-terminated text string
 */
void conn_send_text(connection_t* conn, http_status status, const char* text);

/**
 * @brief Sends a redirect response
 * @param conn The connection object
 * @param location URL to redirect to
 * @param permanent Use 301 (permanent) instead of 302 (temporary)
 */
void conn_send_redirect(connection_t* conn, const char* location, bool permanent);

/**
 * @brief Sends an XML response
 * @param conn The connection object
 * @param status HTTP status code
 * @param xml Null-terminated XML string
 */
void conn_send_xml(connection_t* conn, http_status status, const char* xml);

/**
 * @brief Sends a JavaScript response
 * @param conn The connection object
 * @param status HTTP status code
 * @param javascript Null-terminated JS string
 */
void conn_send_javascript(connection_t* conn, http_status status, const char* javascript);

/**
 * @brief Sends a CSS response
 * @param conn The connection object
 * @param status HTTP status code
 * @param css Null-terminated CSS string
 */
void conn_send_css(connection_t* conn, http_status status, const char* css);

// Start chunked transfer. Stop by calling conn_end_chunked_transfer.
void conn_start_chunked_transfer(connection_t* conn, int max_age_seconds);

// Write a chunk into response after calling 'conn_start_chunked_transfer'.
// Returns the number of bytes written into the socket. (including chunk headers)
ssize_t conn_write_chunk(connection_t* conn, const void* data, size_t size);

// End SSE or chunked transfer.
void conn_end_chunked_transfer(connection_t* conn);

#define WITH_SSE_CONNECTION(conn, block)                                                           \
    do {                                                                                           \
        conn_start_sse(conn);                                                                      \
        block;                                                                                     \
        if (conn_is_open(conn)) conn_end_sse(conn);                                                \
    } while (0)

#define WITH_CHUNKED_TRANSFER(conn, block)                                                         \
    do {                                                                                           \
        conn_start_chunked_transfer(conn, 0);                                                      \
        block;                                                                                     \
        if (conn_is_open(conn)) conn_end_chunked_transfer(conn);                                   \
    } while (0)

typedef struct {
    const char* data;
    size_t data_len;
    const char* event;
    size_t event_len;
    const char* id;
    size_t id_len;
} sse_event_t;

#define SSE_EVENT_INIT(data_, event_, id_)                                                         \
    (sse_event_t){.data      = (data_),                                                            \
                  .data_len  = (data_ != NULL) ? strlen(data_) : 0,                                \
                  .event     = (event_),                                                           \
                  .event_len = (event_ != NULL) ? strlen(event_) : 0,                              \
                  .id        = (id_),                                                              \
                  .id_len    = (id_ != NULL) ? strlen(id_) : 0}

// Start SSE event.
void conn_start_sse(connection_t* conn);

/**
 * @brief Sends an event stream response (SSE)
 * @param conn The connection object
 * @param evt Pointer to sse_event_t struct.
 */
void conn_send_event(connection_t* conn, const sse_event_t* evt);

// End SSE event.
void conn_end_sse(connection_t* conn);

/**
 * @brief Sets the Content-Type header
 *
 * @param conn The connection object
 * @param content_type Content type string
 */
void conn_set_content_type(connection_t* conn, const char* content_type);

/**
 * @brief Adds a header to the response. name and value MUST be valid
 * null-terminated strings and not empty.
 * @param conn The connection object
 * @param name Header name
 * @param value Header value
 */
void conn_writeheader(connection_t* conn, const char* name, const char* value);

/**
 * @brief Adds raw pre-formatted header(s) to the response.
 * Each header must be terminated with \r\n.
 * This is the most perfomant variant of the 3 header writing functions.
 * @param conn The connection object
 * @param header Pre-formatted header.
 * @param value Length of the header excluding the null-terminator.
 */
void conn_writeheader_raw(connection_t* conn, const char* header, size_t length);

/**
 * @brief Write multiple pre-formatted headers at once into response.
 *
 * @param conn The connection object.
 * @param headers The vector of headers.
 * @param count The number of headers.
 */
void conn_writeheaders_vec(connection_t* conn, const struct iovec* headers, size_t count);

/**
 * @brief Sets the HTTP response status and returns the status text.
 *
 * @param conn The connection object
 * @param code HTTP status code
 * @return const char* Status text or NULL if invalid status code.
 */
const char* conn_set_status(connection_t* conn, http_status code);

/**
 * @brief Gets a query parameter value
 *
 * @param conn The connection object
 * @param name Parameter name
 * @return const char* Parameter value or NULL if not found
 */
const char* query_get(connection_t* conn, const char* name);

/**
 * @brief Gets all query parameters
 *
 * @param conn The connection object
 * @return headers_t* Map of all query parameters
 */
headers_t* query_params(connection_t* conn);

/**
 * @brief Gets a request header value
 *
 * @param conn The connection object
 * @param name Header name
 * @return const char* Header value or NULL if not found
 */
const char* req_header_get(connection_t* conn, const char* name);

/**
 * @brief Gets a response header value
 *
 * @param conn The connection object
 * @param name Header name
 * @return A dynamically allocated header value (char *) if it exists or NULL otherwise.
 */
char* res_header_get(connection_t* conn, const char* name);

/**
 * @brief Gets a response header value
 *
 * @param conn The connection object
 * @param name Header name
 * @param dest The destination buffer to write the header value.
 * @param dest_size The destination buffer size.
 * @return true on success or false if buffer is small or header does not exist.
 */
bool res_header_get_buf(connection_t* conn, const char* name, char* dest, size_t dest_size);

/** @brief Returns the response status code. */
http_status res_get_status(connection_t* conn);

/**
 * @brief Gets the request body
 *
 * @param conn The connection object
 * @return const char* Request body or NULL if none
 */
const char* req_body(connection_t* conn);

/**
 * @brief Gets the request method
 *
 * @param conn The connection object
 * @return const char* HTTP method string
 */
const char* req_method(connection_t* conn);

/**
 * @brief Gets the request path
 *
 * @param conn The connection object
 * @return const char* Request path
 */
const char* req_path(connection_t* conn);

/**
 * @brief Gets the request content length
 *
 * @param conn The connection object
 * @return size_t Content-Length header value
 */
size_t req_content_len(connection_t* conn);

/**
 * @brief Gets a path parameter value
 *
 * @param conn The connection object
 * @param name Parameter name
 * @return const char* Parameter value or NULL if not found
 */
const char* get_path_param(connection_t* conn, const char* name);

/**
 * @brief Attaches user data to a connection
 *
 * @param conn The connection object
 * @param ptr User data pointer
 * @param free_func Optional cleanup function
 */
void set_userdata(connection_t* conn, void* ptr, void (*free_func)(void* ptr));

/**
 * @brief Gets user data from connection
 *
 * @param conn The connection object
 * @return void* User data pointer or NULL
 */
void* get_userdata(connection_t* conn);

#ifdef __cplusplus
}
#endif

#endif /* PULSAR_H */
