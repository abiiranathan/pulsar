#ifndef ROUTING_H
#define ROUTING_H

#ifdef __cplusplus
extern "C" {
#endif

#include "constants.h"
#include "headers.h"
#include "method.h"

/** Route type constants (stored in route_t.route_type). */
#define ROUTE_TYPE_EXACT  0
#define ROUTE_TYPE_STATIC 1
#define ROUTE_TYPE_PARAM  2

/** Path parameter extracted from URL. */
typedef struct {
    char* name;   // Parameter name (arena-allocated)
    char* value;  // Parameter value (arena-allocated)
} PathParam;

/** Array structure for path parameters. */
typedef struct PathParams {
    PathParam* items;      // Array of matched parameters
    uint8_t match_count;   // Number of matched parameters from request path
    uint8_t total_params;  // Total parameters counted at startup
} PathParams;

/** Forward declaration for main connection structure. */
struct pulsar_conn;

/**
 * HTTP handler function pointer.
 * @param conn The connection object
 * @param userdata Global user data set via pulsar_set_handler_userdata
 */
typedef void (*HttpHandler)(struct pulsar_conn* conn, void* userdata);

/** Middleware function (same signature as handler). */
typedef HttpHandler Middleware;

/** Forward declaration of route structure. */
struct route_t;

/** Route state union to save space. */
typedef union {
    struct {
        const char* dirname;  // Directory name (for static routes)
        uint8_t dirname_len;  // Length of the dirname
    } static_;
    PathParams* path_params;  // Path parameters (for param routes)
} route_state_t;

/**
 * Route structure optimized for cache locality.
 */
typedef struct route_t {
    // HOT: Fields accessed during route matching (first cache line)
    const char* pattern;   // Route pattern (dynamically allocated)
    HttpHandler handler;   // Handler function pointer
    uint16_t pattern_len;  // Length of the pattern
    HttpMethod method;     // HTTP method (HttpMethod)
    uint8_t route_type;    // 0=exact, 1=static, 2=param
    uint8_t mw_count;      // Number of middleware
    uint8_t _padding[3];   // Align to 8 bytes

    // WARM: Fields accessed less frequently
    route_state_t state;                          // Route-specific state
    Middleware middleware[MAX_ROUTE_MIDDLEWARE];  // Middleware array
} route_t;

/**
 * Sorts all registered routes for optimized matching.
 * Must be called after all routes are registered and before handling requests.
 */
void sort_routes(void);

/**
 * Registers a new route with the given pattern, method, and handler.
 * @param pattern URL pattern (may contain {param} placeholders)
 * @param method HTTP method
 * @param handler Function to handle requests matching this route
 * @return Pointer to the registered route structure
 */
route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler);

/** Registers a GET route. */
static inline route_t* route_get(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_GET, handler);
}

/** Registers a POST route. */
static inline route_t* route_post(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_POST, handler);
}

/** Registers a PUT route. */
static inline route_t* route_put(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_PUT, handler);
}

/** Registers a PATCH route. */
static inline route_t* route_patch(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_PATCH, handler);
}

/** Registers a HEAD route. */
static inline route_t* route_head(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_HEAD, handler);
}

/** Registers an OPTIONS route. */
static inline route_t* route_options(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_OPTIONS, handler);
}

/** Registers a DELETE route. */
static inline route_t* route_delete(const char* pattern, HttpHandler handler) {
    return route_register(pattern, HTTP_DELETE, handler);
}

/**
 * Registers a static file serving route.
 * @param pattern URL prefix pattern
 * @param dir Directory path (must exist and be resolved)
 * @return Pointer to the registered route structure
 * @note Handles index.html serving and prevents directory traversal
 */
route_t* route_static(const char* pattern, const char* dir);

/**
 * Matches an incoming request to a registered route.
 * @param path URL path to match
 * @param url_length Length of the path
 * @param method HTTP method
 * @param arena Arena for allocating path parameter strings
 * @return Matched route or NULL if no match found
 * @note For HEAD requests, falls back to GET routes if no HEAD route matches
 * @note For OPTIONS requests, matches any route regardless of method
 */
route_t* route_match(const char* path, size_t url_length, HttpMethod method, Arena* arena);

#ifdef __cplusplus
}
#endif

#endif /* ROUTING_H */
