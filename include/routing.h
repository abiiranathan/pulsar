#ifndef ROUTING_H
#define ROUTING_H

#ifdef __cplusplus
extern "C" {
#endif

#include "constants.h"
#include "headers.h"
#include "method.h"

#define STATIC_ROUTE_FLAG 0x01
#define NORMAL_ROUTE_FLAG 0x02
#define ROUTE_CACHE_SIZE  (NEXT_POWER_OF_TWO(MAX_ROUTES))
#define ROUTE_CACHE_MASK  (ROUTE_CACHE_SIZE - 1)

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

// Forward declaration for main connection structure defined in pulsar.c.
// This avoid circular imports and need to make everything public.
// We want to keep the struct Opaque.
struct connection_t;

// Http handler function pointer.
// This is also the same signature for the middleware.
// If its returns false, a 500 response is sent unless another code was already set.
// If a middleware was being executed, the chain will be aborted and handler will never be called.
typedef void (*HttpHandler)(struct connection_t* conn);

typedef HttpHandler Middleware;  // Middleware function is same as the handler.

typedef struct route_t {
    const char* pattern;      // dynamically allocated route pattern
    const char* dirname;      // Directory name (for static routes)
    HttpHandler handler;      // Handler function pointer
    PathParams* path_params;  // Path parameters
    uint8_t flags;            // Bit mask for route type. NormalRoute | StaticRoute
    HttpMethod method;        // Http method.
    Middleware middleware[MAX_ROUTE_MIDDLEWARE];  // Array of middleware
    size_t mw_count;                              // Number of middleware
} route_t;

// Helper to sort routes after registration such that
// they can searched with binary search.
void sort_routes(void);

// Register a new route.
route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler);

// Register a new route to server static file in directory at dir.
// dir must be a resolved path and must exist and pattern not NULL.
// Handles serving of index.html at root of directory. File System Traversal
// `should` be blocked.
route_t* route_static(const char* pattern, const char* dir);

// Entry Point to router.
// Matches request path and method to a registered route and parses and populates the path
// parameters. The path params have the lifetime of the arena where they are allocated.
route_t* route_match(const char* path, HttpMethod method);

#ifdef __cplusplus
}
#endif

#endif /* ROUTING_H */
