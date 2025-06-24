#ifndef PULSAR_H
#define PULSAR_H

#include <stddef.h>
#include "headers.h"
#include "status_code.h"

#define NUM_WORKERS 8             // Number of workers.
#define MAX_EVENTS 2048           // Maximum events for epoll->ready queue.
#define READ_BUFFER_SIZE 819      // Buffer size for incoming statusline + headers +/-(part/all of body)
#define CONNECTION_TIMEOUT 30     // Keep-Alive connection timeout in seconds
#define MAX_BODY_SIZE (2 << 20)   // Max Request body allowed.
#define ARENA_CAPACITY 8 * 1024   // Arena memory per connection(8KB). Expand to 16 KB if required.
#define MAX_ROUTES 64             // Maximum number of routes
#define MAX_GLOBAL_MIDDLEWARE 32  // maximum number of global middleware.
#define MAX_ROUTE_MIDDLEWARE 4    // Maximum number of route middleware.

#define UNUSED(var) ((void)var)

#ifdef __cplusplus
extern "C" {
#endif

// ======= Declare opaque structs ===============
// Opaque structs make it easy to extend the API and prevent user
// Mutation of server state.

// Opaque structure for path parameters.
typedef struct PathParams PathParams;

// Response object structure.
typedef struct response_t response_t;

// Connection Object structure.
typedef struct connection_t connection_t;

// Request Object structure.
typedef struct request_t request_t;

// Route structure.
typedef struct route_t route_t;

// ================================================

// Http handler function pointer.
// This is also the same signature for the middleware.
// If its returns false, a 500 response is sent unless another code was already set.
// If a middleware was being executed, the chain will be aborted and handler will never be called.
typedef bool (*HttpHandler)(connection_t* conn);

typedef enum {
    HTTP_INVALID = -1,
    HTTP_OPTIONS,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_PATCH,
    HTTP_DELETE,
} HttpMethod;

// Start server on port and run the server loop forever.
// Stop with SIGINT or SIGTERM.
int pulsar_run(int port);

// ======= Route Registration
//=================================================================

// Register a new route.
route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler);

// Register a new route to server static file in directory at dir.
// dir must exist and pattern not NULL.
// Handles serving of index.html at root of directory. File System Traversal
// `should` be blocked.
route_t* register_static_route(const char* pattern, const char* dir);

// =============================================================

// Set a user data pointer inside the current route.
// This must be called from inside the middleware handler.
// The ptr is freed after the request is finished.
void set_userdata(connection_t* conn, void* ptr, void (*free_func)(void* ptr));

// Returns the void* ptr, set with set_userdata function or NULL.
// Should be called from inside the middleware/handler.
void* get_userdata(connection_t* conn);

// ====================== Middleware ==========================

// Register one or more global middleware.
void use_global_middleware(HttpHandler* middleware, size_t count);

// Register one or more middleware for this route.
void use_route_middleware(route_t* route, HttpHandler* middleware, size_t count);

// =============================================================

// ======================= Response Writer functions ===========

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

// Abort request processing and middleware.
void conn_abort(connection_t* conn);

// ========================================================

// ==================== Method, Parameter and Query functions ==============

// Get value for a query parameter if present or NULL.
const char* query_get(connection_t* conn, const char* name);

// Returns the Query parameters.
headers_t* query_params(connection_t* conn);

// Get a request header.(Possibly NULL)
const char* req_header_get(connection_t* conn, const char* name);

// Returns request body or NULL if not available.
const char* req_body(connection_t* conn);

const char* req_method(connection_t* conn);
const char* req_path(connection_t* conn);

// Returns request body size. (Content-Length).
size_t req_content_len(connection_t* conn);

// Get a response header.(Possibly NULL)
const char* res_header_get(connection_t* conn, const char* name);

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

// ===============================================================

// Set content-type header. This is indempotent.
bool conn_set_content_type(connection_t* conn, const char* content_type);

// Set a header. name and value must be valid NULL-terminated strings.
bool conn_writeheader(connection_t* conn, const char* name, const char* value);

// Set HTTP status code.
void conn_set_status(connection_t* conn, http_status code);

#ifdef __cplusplus
}
#endif

#endif /* PULSAR_H */
