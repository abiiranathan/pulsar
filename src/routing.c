#include "../include/routing.h"
#include "../include/common.h"
#include "../include/method.h"

// Static file handler is provided by pulsar.c.
extern void static_file_handler(struct pulsar_conn* conn, void* userdata);

// Global routes - now separated by type for better cache locality
static route_t global_routes[MAX_ROUTES] = {0};
static size_t global_route_count         = 0;

// Separate arrays for different route types to eliminate branching
static route_t* static_routes[MAX_ROUTES] = {0};
static route_t* param_routes[MAX_ROUTES]  = {0};
static route_t* exact_routes[MAX_ROUTES]  = {0};

static size_t static_count = 0;
static size_t param_count  = 0;
static size_t exact_count  = 0;

// Method lookup tables now separated by route type
static uint32_t method_static_ranges[HTTP_METHOD_COUNT] = {0};
static uint32_t method_param_ranges[HTTP_METHOD_COUNT]  = {0};
static uint32_t method_exact_ranges[HTTP_METHOD_COUNT]  = {0};

static bool match_static_route(route_t* route, const char* url, size_t url_length, Arena* arena) {
    (void)arena;  // Unused for static routes
    return (route->pattern_len <= url_length) && (route->pattern[0] == url[0]) &&
           (memcmp(route->pattern, url, route->pattern_len) == 0);
}

/**
 * match_path_parameters compares the pattern with the URL and extracts the parameters.
 * The pattern can contain parameters in the form of {name}.
 * Matches parameters are dynamically allocated and populated in path_params.
 * Dynamic allocation is necessary b'se the name and value must have program-lifetime
 * since the params are cached inside the route. MemoryPools/Arenas would cause bugs
 * when we reset them.
 *
 * @param pattern: The pattern to match
 * @param url_path: The URL path to match
 * @param pathParams: The PathParams struct to store the matched parameters
 * @return true if the pattern and URL match, false otherwise
 */
INLINE bool match_path_parameters(const char* pattern, const char* url_path,
                                  PathParams* path_params, Arena* arena) {
    const char* pat          = pattern;
    const char* url          = url_path;
    size_t nparams           = 0;
    path_params->match_count = 0;

    while (*pat && *url && nparams < path_params->total_params) {
        if (*pat == '{') {
            // Bounds check
            PathParam* param = &path_params->items[nparams++];

            // Extract parameter name
            pat++;  // Skip '{'
            const char* name_start = pat;
            while (*pat && *pat != '}')
                pat++;
            if (*pat != '}') return false;

            size_t name_len = (size_t)(pat - name_start);
            param->name     = arena_strdupn(arena, name_start, name_len);
            if (!param->name) {
                return false;
            }
            pat++;  // Skip '}'

            // Extract parameter value
            const char* val_start = url;
            while (*url && *url != '/' && *url != *pat) {
                url++;
            }

            size_t val_len = (size_t)(url - val_start);
            param->value   = arena_strdupn(arena, val_start, val_len);
            if (!param->value) {
                return false;
            }
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

// Count the number of path parameters in pattern.
// If there is an invalid (unterminated) parameter, valid is updated to false.
size_t count_path_params(const char* pattern, bool* valid) {
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

static bool match_param_route(route_t* route, const char* url, size_t url_length, Arena* arena) {
    (void)url_length;  // length is handled in match_path_parameters
    return match_path_parameters(route->pattern, url, route->state.path_params, arena);
}

static bool match_exact_route(route_t* route, const char* url, size_t url_length, Arena* arena) {
    (void)arena;  // Unused for exact routes
    const char* pat = route->pattern;
    size_t pat_len  = route->pattern_len;

    return (pat_len == url_length) && (pat[0] == url[0]) && (memcmp(pat, url, url_length) == 0);
}

// Route type classification
typedef enum { ROUTE_STATIC, ROUTE_PARAM, ROUTE_EXACT } route_type_t;

static route_type_t classify_route(const char* pattern, bool is_static) {
    if (is_static) return ROUTE_STATIC;

    bool valid;
    size_t nparams = count_path_params(pattern, &valid);
    ASSERT(valid && "Invalid path parameters in pattern");

    return (nparams > 0) ? ROUTE_PARAM : ROUTE_EXACT;
}

// Modified route registration
static route_t* route_register_helper(const char* pattern, HttpMethod method, HttpHandler handler,
                                      int is_static) {
    ASSERT(global_route_count < MAX_ROUTES);
    ASSERT(METHOD_VALID(method));
    ASSERT(pattern && handler && "pattern and handler must not be NULL");

    route_t* r     = &global_routes[global_route_count];
    r->pattern     = pattern;
    r->pattern_len = strlen(pattern);
    r->method      = method;
    r->handler     = handler;
    r->is_static   = is_static;

    // Classify route type and set appropriate matcher
    route_type_t type = classify_route(pattern, is_static);
    switch (type) {
        case ROUTE_STATIC:
            r->matcher = match_static_route;
            break;
        case ROUTE_PARAM:
            r->matcher = match_param_route;
            // Allocate path params (your existing code)
            bool pattern_valid;
            size_t nparams = count_path_params(pattern, &pattern_valid);
            ASSERT(pattern_valid);

            r->state.path_params = malloc(sizeof(PathParams));
            ASSERT(r->state.path_params);

            r->state.path_params->match_count  = 0;
            r->state.path_params->total_params = nparams;
            r->state.path_params->items        = calloc(nparams, sizeof(PathParam));
            ASSERT(r->state.path_params->items);
            break;
        case ROUTE_EXACT:
            r->matcher           = match_exact_route;
            r->state.path_params = NULL;
            break;
    }

    memset(r->middleware, 0, sizeof(r->middleware));
    r->mw_count = 0;
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
    r->is_static                 = true;
    r->state.static_.dirname     = dirname;
    r->state.static_.dirname_len = strlen(dirname);
    return r;
}

// Comparison function for sorting routes by method, then by specificity
static int compare_routes(const void* a, const void* b) {
    const route_t* ra = (const route_t*)a;
    const route_t* rb = (const route_t*)b;

    // First sort by method
    if (ra->method < rb->method) return -1;
    if (ra->method > rb->method) return 1;

    // Sort by specificity: exact matches before parameterized routes
    bool ra_has_params = (!ra->is_static && ra->state.path_params != NULL);
    bool rb_has_params = (!rb->is_static && rb->state.path_params != NULL);

    if (!ra_has_params && rb_has_params) return -1;  // Exact routes first
    if (ra_has_params && !rb_has_params) return 1;

    // For routes of same type, longer patterns first (more specific)
    if (ra->pattern_len > rb->pattern_len) return -1;
    if (ra->pattern_len < rb->pattern_len) return 1;

    // Finally sort alphabetically for deterministic ordering
    return strcmp(ra->pattern, rb->pattern);
}

// Helper to build method ranges for any route array
INLINE void build_method_ranges(route_t** routes, size_t count, uint32_t* ranges);

// Generic matcher for any route type array
INLINE route_t* match_route_type(route_t** routes, uint32_t* ranges, const char* path,
                                 size_t url_length, HttpMethod method, Arena* arena);

// OPTIONS handler - check if any route matches regardless of method
INLINE route_t* match_any_route(const char* path, size_t url_length, Arena* arena);

// Build separate arrays for each route type during sorting
void sort_routes(void) {
    static int global_sort_state = 0;

    if (global_sort_state == 0 && global_route_count > 0) {
        // Sort global routes array
        qsort(global_routes, global_route_count, sizeof(route_t), compare_routes);

        // Build separate arrays by type
        static_count = param_count = exact_count = 0;

        for (size_t i = 0; i < global_route_count; i++) {
            route_t* r        = &global_routes[i];
            route_type_t type = classify_route(r->pattern, r->is_static);

            switch (type) {
                case ROUTE_STATIC:
                    static_routes[static_count++] = r;
                    break;
                case ROUTE_PARAM:
                    param_routes[param_count++] = r;
                    break;
                case ROUTE_EXACT:
                    exact_routes[exact_count++] = r;
                    break;
            }
        }

        // Build method lookup tables for each route type
        build_method_ranges(static_routes, static_count, method_static_ranges);
        build_method_ranges(param_routes, param_count, method_param_ranges);
        build_method_ranges(exact_routes, exact_count, method_exact_ranges);

        global_sort_state = 1;
    }
}

// Helper to build method ranges for any route array
INLINE void build_method_ranges(route_t** routes, size_t count, uint32_t* ranges) {
    if (count == 0) return;

    HttpMethod current_method = routes[0]->method;
    uint32_t start_idx        = 0;

    for (size_t i = 1; i < count; i++) {
        HttpMethod method = routes[i]->method;
        if (method != current_method) {
            ranges[current_method] = (start_idx << 16) | (uint32_t)i;
            start_idx              = (uint32_t)i;
            current_method         = method;
        }
    }
    ranges[current_method] = (start_idx << 16) | (uint32_t)count;
}

// Optimized route matching with no type branching
route_t* route_match(const char* path, size_t url_length, HttpMethod method, Arena* arena) {
    route_t* found = NULL;

    // Try exact routes first (fastest, no allocation)
    found = match_route_type(exact_routes, method_exact_ranges, path, url_length, method, arena);
    if (found) return found;

    // Try static routes next
    found = match_route_type(static_routes, method_static_ranges, path, url_length, method, arena);
    if (found) return found;

    // Try param routes last (slowest, may allocate)
    found = match_route_type(param_routes, method_param_ranges, path, url_length, method, arena);
    if (found) return found;

    // Handle special method fallbacks
    if (method == HTTP_HEAD) {
        return route_match(path, url_length, HTTP_GET, arena);
    } else if (method == HTTP_OPTIONS) {
        // OPTIONS matches if ANY route exists for this path
        return match_any_route(path, url_length, arena);
    }

    return NULL;
}

// Generic matcher for any route type array
INLINE route_t* match_route_type(route_t** routes, uint32_t* ranges, const char* path,
                                 size_t url_length, HttpMethod method, Arena* arena) {
    uint32_t packed  = ranges[method];
    size_t start_idx = packed >> 16;
    size_t end_idx   = packed & 0xFFFF;

    for (size_t i = start_idx; i < end_idx; i++) {
        route_t* current = routes[i];
        if (current->matcher(current, path, url_length, arena)) {
            return current;
        }
    }
    return NULL;
}

// OPTIONS handler - check if any route matches regardless of method
INLINE route_t* match_any_route(const char* path, size_t url_length, Arena* arena) {
    // Check exact routes
    for (size_t i = 0; i < exact_count; i++) {
        if (exact_routes[i]->matcher(exact_routes[i], path, url_length, arena)) {
            return exact_routes[i];
        }
    }

    // Check static routes
    for (size_t i = 0; i < static_count; i++) {
        if (static_routes[i]->matcher(static_routes[i], path, url_length, arena)) {
            return static_routes[i];
        }
    }

    // Check param routes
    for (size_t i = 0; i < param_count; i++) {
        if (param_routes[i]->matcher(param_routes[i], path, url_length, arena)) {
            return param_routes[i];
        }
    }

    return NULL;
}

__attribute__((destructor())) void routing_cleanup(void) {
    // Your existing cleanup code remains the same
    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = &global_routes[i];
        if (r->is_static || (!r->is_static && r->state.path_params == NULL)) {
            continue;
        }
        PathParams* p = r->state.path_params;
        if (p->items) free(p->items);
        free(p);
    }
}
