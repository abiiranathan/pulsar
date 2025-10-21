#include "../include/routing.h"
#include <string.h>
#include "../include/common.h"
#include "../include/method.h"

/** Static file handler provided by pulsar.c. */
extern void static_file_handler(struct pulsar_conn* conn, void* userdata);

/** Global route storage. */
static route_t global_routes[MAX_ROUTES] = {0};
static size_t global_route_count         = 0;

/**
 * Method-specific route arrays for O(1) method dispatch.
 * Each array contains pointers to routes sorted by specificity.
 * Index = HttpMethod enum value.
 */
typedef struct {
    route_t** routes;   // Array of route pointers
    uint16_t count;     // Number of routes for this method
    uint16_t _padding;  // Align to 8 bytes
} MethodRoutes;

static MethodRoutes method_routes[HTTP_METHOD_COUNT] = {0};

/** Pre-allocated storage for method-specific route pointer arrays. */
static route_t* method_route_storage[HTTP_METHOD_COUNT][MAX_ROUTES] = {0};

/**
 * Counts path parameters in a pattern and validates syntax.
 * @param pattern Route pattern string
 * @param valid Output: set to true if pattern is valid, false otherwise
 * @return Number of parameters in pattern (0 if invalid)
 */
static size_t count_path_params(const char* pattern, bool* valid) {
    const char* ptr = pattern;
    size_t count    = 0;
    *valid          = true;

    while (*ptr) {
        if (*ptr == '{') {
            const char* end = ptr + 1;
            // Validate parameter syntax
            while (*end && *end != '}') {
                if (*end == '{') {
                    *valid = false;  // Nested braces
                    return 0;
                }
                end++;
            }

            if (*end == '}') {
                count++;
                ptr = end + 1;
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

/**
 * Classifies route type based on pattern characteristics.
 * @param pattern Route pattern
 * @param is_static True if this is a static file route
 * @return Route type constant (ROUTE_TYPE_*)
 */
static inline uint8_t classify_route(const char* pattern, bool is_static, uint8_t* nparams) {
    if (is_static) return ROUTE_TYPE_STATIC;

    bool valid;
    *nparams = count_path_params(pattern, &valid);
    ASSERT(valid && "Invalid path parameters in pattern");
    return (*nparams > 0) ? ROUTE_TYPE_PARAM : ROUTE_TYPE_EXACT;
}

/**
 * Internal route registration helper.
 * @param pattern URL pattern
 * @param method HTTP method
 * @param handler Handler function
 * @param is_static True for static file routes
 * @return Pointer to registered route
 */
static route_t* route_register_helper(const char* pattern, HttpMethod method, HttpHandler handler,
                                      int is_static) {
    ASSERT(global_route_count < MAX_ROUTES && "Route table full");
    ASSERT(METHOD_VALID(method) && "Invalid HTTP method");
    ASSERT(pattern && handler && "pattern and handler must not be NULL");

    uint8_t nparams = 0;
    route_t* r      = &global_routes[global_route_count];
    r->pattern      = pattern;
    r->pattern_len  = strlen(pattern);
    r->method       = method;
    r->handler      = handler;
    r->route_type   = classify_route(pattern, is_static, &nparams);
    r->mw_count     = 0;
    memset(r->middleware, 0, sizeof(r->middleware));

    // Initialize route-specific state
    if (r->route_type == ROUTE_TYPE_PARAM && nparams > 0) {
        r->state.path_params = malloc(sizeof(PathParams));
        ASSERT(r->state.path_params && "Failed to allocate PathParams");

        r->state.path_params->match_count  = 0;
        r->state.path_params->total_params = nparams;
        r->state.path_params->items        = calloc(nparams, sizeof(PathParam));
        ASSERT(r->state.path_params->items && "Failed to allocate PathParam array");
    } else {
        r->state.path_params = nullptr;
    }

    global_route_count++;
    return r;
}

route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler) {
    return route_register_helper(pattern, method, handler, 0);
}

route_t* route_static(const char* pattern, const char* dirname) {
    ASSERT(pattern && dirname && "pattern and dirname must be non-NULL");
    ASSERT(is_dir(dirname) && "dir must be an existing directory");

    route_t* r                   = route_register_helper(pattern, HTTP_GET, static_file_handler, 1);
    r->route_type                = ROUTE_TYPE_STATIC;
    r->state.static_.dirname     = dirname;
    r->state.static_.dirname_len = (uint8_t)strlen(dirname);
    return r;
}

/**
 * Comparison function for sorting routes.
 * Sort order:
 * 1. By HTTP method (for method lookup tables)
 * 2. By specificity: exact > static > param
 * 3. By length (longer = more specific)
 * 4. Alphabetically (for deterministic ordering)
 */
static int compare_routes(const void* a, const void* b) {
    const route_t* ra = (const route_t*)a;
    const route_t* rb = (const route_t*)b;

    // Sort by method first
    if (ra->method < rb->method) return -1;
    if (ra->method > rb->method) return 1;

    // Sort by route type (exact < static < param for best matching order)
    if (ra->route_type < rb->route_type) return -1;
    if (ra->route_type > rb->route_type) return 1;

    // Within same type, longer patterns first (more specific)
    if (ra->pattern_len > rb->pattern_len) return -1;
    if (ra->pattern_len < rb->pattern_len) return 1;

    // Alphabetically for determinism
    return strcmp(ra->pattern, rb->pattern);
}

void sort_routes(void) {
    static int sorted = 0;
    if (sorted || global_route_count == 0) return;

    // Sort global array
    qsort(global_routes, global_route_count, sizeof(route_t), compare_routes);

    // Build method-specific lookup tables
    for (size_t i = 0; i < HTTP_METHOD_COUNT; i++) {
        method_routes[i].routes = method_route_storage[i];
        method_routes[i].count  = 0;
    }

    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r        = &global_routes[i];
        HttpMethod method = r->method;

        ASSERT(method < HTTP_METHOD_COUNT && "Invalid method during sort");
        ASSERT(method_routes[method].count < MAX_ROUTES && "Too many routes for method");

        method_routes[method].routes[method_routes[method].count++] = r;
    }

    sorted = 1;
}

/**
 * Fast exact string comparison optimized for route matching.
 * Checks length first, then first character, then full memcmp.
 */
static inline bool str_exact_match(const char* pattern, uint16_t pat_len, const char* url,
                                   size_t url_len) {
    return (pat_len == url_len) && (pattern[0] == url[0]) && (memcmp(pattern, url, url_len) == 0);
}

/**
 * Fast prefix match for static routes.
 * Checks if URL starts with pattern.
 */
static inline bool str_prefix_match(const char* pattern, uint16_t pat_len, const char* url,
                                    size_t url_len) {
    return (pat_len <= url_len) && (pattern[0] == url[0]) && (memcmp(pattern, url, pat_len) == 0);
}

/**
 * Matches path parameters and extracts values into arena-allocated strings.
 * @param pattern Route pattern with {param} placeholders
 * @param url URL path to match
 * @param path_params PathParams structure to populate
 * @param arena Arena for string allocations
 * @return true if pattern matches URL and all params extracted
 */
static bool match_path_parameters(const char* pattern, const char* url, PathParams* path_params,
                                  Arena* arena) {
    const char* pat            = pattern;
    const char* url_ptr        = url;
    uint8_t nparams            = 0;
    const uint8_t total_params = path_params->total_params;

    path_params->match_count = 0;

    while (*pat && *url_ptr && nparams < total_params) {
        if (*pat == '{') {
            PathParam* param = &path_params->items[nparams++];
            pat++;  // Skip '{'

            // Extract parameter name
            const char* name_start = pat;
            while (*pat && *pat != '}')
                pat++;
            if (*pat != '}') return false;  // Malformed pattern

            size_t name_len = (size_t)(pat - name_start);
            param->name     = arena_strdupn(arena, name_start, name_len);
            if (!param->name) return false;
            pat++;  // Skip '}'

            // Extract parameter value (until '/' or next pattern char or end)
            const char* val_start = url_ptr;
            while (*url_ptr && *url_ptr != '/' && *url_ptr != *pat) {
                url_ptr++;
            }

            size_t val_len = (size_t)(url_ptr - val_start);
            param->value   = arena_strdupn(arena, val_start, val_len);
            if (!param->value) return false;
        } else {
            // Literal character match
            if (*pat != *url_ptr) return false;
            pat++;
            url_ptr++;
        }
    }

    // Skip trailing slashes in both pattern and URL
    while (*pat == '/')
        pat++;
    while (*url_ptr == '/')
        url_ptr++;

    path_params->match_count = nparams;

    // Valid match if: both exhausted AND all params found
    return (*pat == '\0' && *url_ptr == '\0' && nparams == total_params);
}

/**
 * Matches a route against URL based on route type.
 * Inlined to eliminate virtual dispatch overhead.
 */
static inline bool route_matches(route_t* route, const char* url, size_t url_length, Arena* arena) {
    switch (route->route_type) {
        case ROUTE_TYPE_EXACT:
            return str_exact_match(route->pattern, route->pattern_len, url, url_length);

        case ROUTE_TYPE_STATIC:
            return str_prefix_match(route->pattern, route->pattern_len, url, url_length);

        case ROUTE_TYPE_PARAM:
            return match_path_parameters(route->pattern, url, route->state.path_params, arena);

        default:
            return false;
    }
}

/**
 * Searches routes for a specific method.
 * Linear search is optimal for small arrays (< 64 routes per method).
 */
static inline route_t* match_method_routes(HttpMethod method, const char* path, size_t url_length,
                                           Arena* arena) {
    if (method >= HTTP_METHOD_COUNT) return nullptr;

    MethodRoutes* mr     = &method_routes[method];
    route_t** routes     = mr->routes;
    const uint16_t count = mr->count;

    // Linear search with early exit on match
    for (uint16_t i = 0; i < count; i++) {
        route_t* r = routes[i];
        if (route_matches(r, path, url_length, arena)) {
            return r;
        }
    }

    return nullptr;
}

/**
 * Matches any route regardless of method (for OPTIONS handling).
 */
static inline route_t* match_any_method(const char* path, size_t url_length, Arena* arena) {
    for (size_t method = 0; method < HTTP_METHOD_COUNT; method++) {
        route_t* found = match_method_routes(method, path, url_length, arena);
        if (found) return found;
    }
    return nullptr;
}

route_t* route_match(const char* path, size_t url_length, HttpMethod method, Arena* arena) {
    // Fast path: direct method lookup
    route_t* found = match_method_routes(method, path, url_length, arena);
    if (found) return found;

    // Fallback: HEAD requests try GET routes
    if (method == HTTP_HEAD) {
        return match_method_routes(HTTP_GET, path, url_length, arena);
    }

    // Fallback: OPTIONS matches any route
    if (method == HTTP_OPTIONS) {
        return match_any_method(path, url_length, arena);
    }

    return nullptr;
}

/** Cleanup function called at program exit. */
__attribute__((destructor)) void routing_cleanup(void) {
    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = &global_routes[i];
        if (r->route_type == ROUTE_TYPE_PARAM && r->state.path_params) {
            if (r->state.path_params->items) {
                free(r->state.path_params->items);
            }
            free(r->state.path_params);
        }
    }
}
