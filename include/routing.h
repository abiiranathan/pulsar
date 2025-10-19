#ifndef ROUTING_H
#define ROUTING_H

#ifdef __cplusplus
extern "C" {
#endif

#include "constants.h"
#include "headers.h"
#include "method.h"

// Path parameter.
typedef struct {
    char* name;   // Parameter name
    char* value;  // Parameter value from the URL
} PathParam;

// Array structure for path parameters.
typedef struct PathParams {
    PathParam* items;     // Array of matched parameters
    size_t match_count;   // Number of matched parameters from request path.
    size_t total_params;  // Total parameters counted at startup.
} PathParams;

// Forward declaration for main connection structure defined in pulsar.c.
// This avoid circular imports and need to make everything public.
// We want to keep the struct Opaque.
struct pulsar_conn;

// Http handler function pointer.
// This is also the same signature for the middleware.
// Handlers and middleware now receive a second `userdata` pointer which is set
// globally via `pulsar_set_handler_userdata`. This allows passing DB connections,
// loggers, etc. to every handler without changing per-route registration.
typedef void (*HttpHandler)(struct pulsar_conn* conn, void* userdata);

typedef HttpHandler Middleware;  // Middleware function is same as the handler.

typedef struct route_t {
    const char* pattern;  // dynamically allocated route pattern
    uint8_t is_static;    // true for static route.
    uint8_t pattern_len;  // Length of the pattern
    HttpMethod method;    // Http method.
    HttpHandler handler;  // Handler function pointer
    union {
        struct {
            const char* dirname;  // Directory name (for static routes)
            uint8_t dirname_len;  // Length of the dirname
        } static_;
        PathParams* path_params;  // Path parameters
    } state;
    Middleware middleware[MAX_ROUTE_MIDDLEWARE];  // Array of middleware
    uint8_t mw_count;                             // Number of middleware
} route_t;

// Helper to sort routes after registration such that
// they can searched with binary search.
void sort_routes(void);

// Register a new route.
route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler);

// Register a /GET route.
static inline route_t* route_get(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_GET, handler);
}

// Register a /POST route.
static inline route_t* route_post(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_POST, handler);
}

// Register a /PUT route.
static inline route_t* route_put(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_PUT, handler);
}

// Register a /PATCH route.
static inline route_t* route_patch(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_PATCH, handler);
}

// Register a /HEAD route.
static inline route_t* route_head(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_HEAD, handler);
}

// Register a /OPTIONS route.
static inline route_t* route_options(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_OPTIONS, handler);
}

// Register a /DELETE route.
static inline route_t* route_delete(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_DELETE, handler);
}

// Register a new route to server static file in directory at dir.
// dir must be a resolved path and must exist and pattern not NULL.
// Handles serving of index.html at root of directory. File System Traversal
// `should` be blocked.
route_t* route_static(const char* pattern, const char* dir);

// Entry Point to router.
// Matches request path and method to a registered route and parses and populates the path
// parameters. The path params have the lifetime of the arena where they are allocated.
route_t* route_match(const char* path, size_t url_length, HttpMethod method, Arena* arena);

#ifdef __cplusplus
}
#endif

#endif /* ROUTING_H */
