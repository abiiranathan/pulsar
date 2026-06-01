#include "../include/routing.h"
#include <string.h>
#include "../include/common.h"
#include "../include/method.h"

/** Static file handler provided by pulsar.c. */
extern void static_file_handler(PulsarCtx* ctx);

/** Global route storage. */
static route_t global_routes[MAX_ROUTES] = {0};
static size_t global_route_count         = 0;

/**
 * Method-specific route arrays for O(1) method dispatch.
 * Each array contains pointers to routes sorted by specificity.
 * Index = HttpMethod enum value.
 */
typedef struct {
    route_t** routes; /**< Array of route pointers for this method. */
    uint16_t count;   /**< Number of routes registered for this method. */
    uint16_t _pad;    /**< Explicit padding; aligns struct to 8 bytes. */
} MethodRoutes;

static MethodRoutes method_routes[HTTP_METHOD_COUNT] = {0};

/** Pre-allocated backing storage for per-method route pointer arrays. */
static route_t* method_route_storage[HTTP_METHOD_COUNT][MAX_ROUTES] = {0};

/**
 * Counts path parameters in a pattern and validates its syntax.
 *
 * Single-pass: each character is visited exactly once.
 *
 * @param pattern Route pattern string to inspect.
 * @param valid   Output flag; set to false on malformed input, true otherwise.
 * @return Number of {param} placeholders found; 0 on invalid pattern.
 */
static size_t count_path_params(const char* pattern, bool* valid) {
    const char* p = pattern;
    size_t count  = 0;
    *valid        = true;

    while (*p) {
        if (*p == '{') {
            p++; /* step past '{' before inner scan */
            while (*p && *p != '}') {
                if (*p == '{') {
                    *valid = false; /* nested brace — illegal */
                    return 0;
                }
                p++;
            }
            if (*p != '}') {
                *valid = false; /* unterminated brace */
                return 0;
            }
            count++;
            p++;            /* step past '}' */
        } else if (*p == '}') {
            *valid = false; /* unmatched closing brace */
            return 0;
        } else {
            p++;
        }
    }
    return count;
}

/**
 * Classifies a route based on its pattern and sets the parameter count.
 *
 * @param pattern   Route pattern string.
 * @param is_static True for static file routes.
 * @param nparams   Output: number of path parameters found.
 * @return ROUTE_TYPE_STATIC, ROUTE_TYPE_EXACT, or ROUTE_TYPE_PARAM.
 */
static inline uint8_t classify_route(const char* pattern, bool is_static, uint8_t* nparams) {
    if (is_static) return ROUTE_TYPE_STATIC;

    bool valid;
    *nparams = (uint8_t)count_path_params(pattern, &valid);
    ASSERT(valid && "Invalid path parameters in pattern");
    return (*nparams > 0) ? ROUTE_TYPE_PARAM : ROUTE_TYPE_EXACT;
}

/**
 * Pre-populates param names in a PathParams structure from a route pattern.
 *
 * Called once at registration time so that the hot-path matcher only needs
 * to write extracted values, never names.
 *
 * @param pattern     Route pattern containing {name} placeholders.
 * @param path_params Destination structure; items must already be allocated
 *                    and total_params must reflect the actual placeholder count.
 */
static void populate_param_names(const char* pattern, PathParams* path_params) {
    const char* p       = pattern;
    uint8_t idx         = 0;
    const uint8_t total = path_params->total_params;

    while (*p && idx < total) {
        if (*p != '{') {
            p++;
            continue;
        }

        p++; /* skip '{' */
        const char* name_start = p;
        while (*p && *p != '}')
            p++;

        /* Pattern was validated by count_path_params; '}' is guaranteed. */
        const size_t name_len = (size_t)(p - name_start);
        p++; /* skip '}' */

        /*
         * Names are stored as interior pointers into the (static, permanent)
         * pattern string.  No allocation is needed; lifetime matches the route.
         * We cast away const to satisfy the non-const field, but the pointer
         * will never be written through in the matcher.
         */
        path_params->items[idx].name     = (char*)name_start;
        path_params->items[idx].name_len = name_len;
        idx++;
    }
}

/**
 * Internal route registration helper.
 *
 * @param pattern   URL pattern string (must have static lifetime).
 * @param method    HTTP method enum value.
 * @param handler   Request handler function.
 * @param is_static True for static file routes.
 * @return Pointer to the newly registered route_t entry.
 */
static route_t* route_register_helper(const char* pattern, HttpMethod method, HttpHandler handler,
                                      int is_static) {
    ASSERT(global_route_count < MAX_ROUTES && "Route table full");
    ASSERT(METHOD_VALID(method) && "Invalid HTTP method");
    ASSERT(pattern && handler && "pattern and handler must not be NULL");

    uint8_t nparams = 0;
    route_t* r      = &global_routes[global_route_count];

    /* Zero-initialise the whole entry via compound literal, then fill fields.
     * A single memset-equivalent store is cheaper than piecemeal zeroing. */
    *r = (route_t){
        .pattern     = pattern,
        .pattern_len = (uint16_t)strlen(pattern),
        .method      = method,
        .handler     = handler,
        .route_type  = classify_route(pattern, is_static, &nparams),
    };

    if (r->route_type == ROUTE_TYPE_PARAM && nparams > 0) {
        r->state.path_params = malloc(sizeof(PathParams));
        ASSERT(r->state.path_params && "Failed to allocate PathParams");

        /* calloc zero-initialises name/value pointers in every PathParam. */
        r->state.path_params->items = calloc(nparams, sizeof(PathParam));
        ASSERT(r->state.path_params->items && "Failed to allocate PathParam array");

        r->state.path_params->match_count  = 0;
        r->state.path_params->total_params = nparams;

        /*
         * Pre-populate parameter names once at registration time.
         * The hot-path matcher (match_path_parameters) then only writes
         * values, eliminating arena_strdupn calls for names on each request.
         */
        populate_param_names(pattern, r->state.path_params);
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
    r->state.static_.dirname     = dirname;
    r->state.static_.dirname_len = (uint8_t)strlen(dirname);
    return r;
}

/**
 * Comparison function for qsort-based route ordering.
 *
 * Sort order (most to least significant):
 *   1. HTTP method (groups routes for O(1) per-method dispatch).
 *   2. Root static routes last (catch-all semantics).
 *   3. Route type: exact → static → param (match in specificity order).
 *   4. Pattern length descending (longer = more specific).
 *   5. Lexicographic (deterministic tie-break).
 */
static int compare_routes(const void* a, const void* b) {
    const route_t* ra = (const route_t*)a;
    const route_t* rb = (const route_t*)b;

    if (ra->method != rb->method) return (ra->method < rb->method) ? -1 : 1;

    /* Root static routes serve as catch-alls; push them to the end. */
    const bool ra_root_static =
        (ra->route_type == ROUTE_TYPE_STATIC && ra->pattern_len == 1 && ra->pattern[0] == '/');
    const bool rb_root_static =
        (rb->route_type == ROUTE_TYPE_STATIC && rb->pattern_len == 1 && rb->pattern[0] == '/');

    if (ra_root_static != rb_root_static) return ra_root_static ? 1 : -1;

    if (ra->route_type != rb->route_type) return (ra->route_type < rb->route_type) ? -1 : 1;

    if (ra->pattern_len != rb->pattern_len) return (ra->pattern_len > rb->pattern_len) ? -1 : 1;

    return strcmp(ra->pattern, rb->pattern);
}

void sort_routes(void) {
    static int sorted = 0;
    if (sorted || global_route_count == 0) return;

    qsort(global_routes, global_route_count, sizeof(route_t), compare_routes);

    /* Build per-method pointer arrays from the now-sorted global table. */
    for (size_t i = 0; i < HTTP_METHOD_COUNT; i++) {
        method_routes[i].routes = method_route_storage[i];
        method_routes[i].count  = 0;
    }

    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r              = &global_routes[i];
        const HttpMethod method = r->method;

        ASSERT(method < HTTP_METHOD_COUNT && "Invalid method during sort");
        ASSERT(method_routes[method].count < MAX_ROUTES && "Too many routes for method");

        method_routes[method].routes[method_routes[method].count++] = r;
    }

    sorted = 1;
}

/**
 * Fast exact string comparison for route matching.
 *
 * Checks length, then the first character (cheap divergence filter), then
 * delegates to memcmp for the remainder.
 */
static inline bool str_exact_match(const char* pattern, uint16_t pat_len, const char* url,
                                   size_t url_len) {
    return (pat_len == (uint16_t)url_len) && (pattern[0] == url[0]) &&
           (memcmp(pattern, url, url_len) == 0);
}

/**
 * Fast prefix match for static file routes.
 *
 * Returns true if url begins with pattern.
 */
static inline bool str_prefix_match(const char* pattern, uint16_t pat_len, const char* url,
                                    size_t url_len) {
    return (pat_len <= (uint16_t)url_len) && (pattern[0] == url[0]) &&
           (memcmp(pattern, url, pat_len) == 0);
}

/**
 * Matches a parameterised route pattern against a URL and extracts values.
 *
 * Param names are pre-populated at registration time (see populate_param_names),
 * so this function only allocates arena memory for extracted values — never for
 * names.  This is the primary hot-path optimisation over the naive approach.
 *
 * Single-pass over both strings simultaneously.  The literal-character path
 * (overwhelmingly the common case) costs one compare and two pointer increments
 * per character.  The bitwise-AND loop condition tests both pointers for
 * non-NUL in a single branch.
 *
 * @param pattern     Route pattern with {param} placeholders.
 * @param url         URL path to match against.
 * @param path_params PathParams with names already filled; values are written here.
 * @param arena       Arena used for value string allocation.
 * @return true if the pattern matches the URL exactly and all params were filled.
 */
static bool match_path_parameters(const char* pattern, const char* url, PathParams* path_params,
                                  Arena* arena) {
    const char* pat            = pattern;
    const char* url_ptr        = url;
    const uint8_t total_params = path_params->total_params;
    uint8_t nparams            = 0;

    path_params->match_count = 0;

    while (*pat & *url_ptr) { /* bitwise-AND: both non-NUL in a single branch */
        if (*pat != '{') {
            /* ---- Hot path: literal character match ---- */
            if (*pat != *url_ptr) return false;
            pat++;
            url_ptr++;
            continue;
        }

        /* ---- Param path ---- */
        if (nparams == total_params) return false; /* guard: no overflow */

        PathParam* param = &path_params->items[nparams++];

        /* Skip past the {name} token; the name pointer was stored at
         * registration time, so we only need to advance pat here. */
        pat++; /* skip '{' */
        while (*pat && *pat != '}')
            pat++;
        if (*pat != '}') return false; /* malformed pattern — defensive */
        pat++;                         /* skip '}' */

        /* Extract value: stop at '/', the next literal pattern character,
         * or end-of-string.  Hoist *pat to avoid re-dereferencing each iter. */
        const char* val_start = url_ptr;
        const char stop_pat   = *pat; /* next pattern char after '}' */

        if (stop_pat == '\0') {
            /* Terminal param: consume everything except a trailing slash. */
            while (*url_ptr && *url_ptr != '/')
                url_ptr++;
        } else {
            while (*url_ptr && *url_ptr != '/' && *url_ptr != stop_pat)
                url_ptr++;
        }

        const size_t val_len = (size_t)(url_ptr - val_start);
        param->value         = arena_strdupn(arena, val_start, val_len);
        if (!param->value) return false;
    }

    /* Strip optional trailing slashes before the exhaustion check. */
    while (*pat == '/')
        pat++;
    while (*url_ptr == '/')
        url_ptr++;

    path_params->match_count = nparams;

    /* Branchless final check: all three conditions are cheap boolean loads. */
    return (*pat == '\0') & (*url_ptr == '\0') & (nparams == total_params);
}

/**
 * Dispatches to the correct match strategy based on route type.
 *
 * Marked inline to eliminate call overhead in the search loop; the compiler
 * can also propagate the constant route_type into the switch arms.
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
 * Searches the per-method route array for the first match.
 *
 * Linear search is optimal for the small arrays typical of a single HTTP
 * method (< 64 routes).  Routes are sorted by specificity so the first
 * match is always the most specific.
 *
 * @param method     HTTP method to search.
 * @param path       Request path.
 * @param url_length Byte length of path.
 * @param arena      Arena passed through to param matchers.
 * @return Matched route pointer, or NULL if none found.
 */
static inline route_t* match_method_routes(HttpMethod method, const char* path, size_t url_length,
                                           Arena* arena) {
    if (method >= HTTP_METHOD_COUNT) return NULL;

    const MethodRoutes* mr = &method_routes[method];
    route_t** const routes = mr->routes;
    const uint16_t count   = mr->count;

    for (uint16_t i = 0; i < count; i++) {
        if (route_matches(routes[i], path, url_length, arena)) {
            return routes[i];
        }
    }

    return NULL;
}

/**
 * Searches all methods for a matching route.
 *
 * Used by OPTIONS handling to find any route on the requested path
 * regardless of the registered method.
 */
static inline route_t* match_any_method(const char* path, size_t url_length, Arena* arena) {
    for (size_t method = 0; method < HTTP_METHOD_COUNT; method++) {
        route_t* found = match_method_routes((HttpMethod)method, path, url_length, arena);
        if (found) return found;
    }
    return NULL;
}

route_t* route_match(const char* path, size_t url_length, HttpMethod method, Arena* arena) {
    route_t* found = match_method_routes(method, path, url_length, arena);
    if (found) return found;

    /* HEAD falls back to GET routes per RFC 9110 §9.3.2. */
    if (method == HTTP_HEAD) return match_method_routes(HTTP_GET, path, url_length, arena);

    /* OPTIONS matches any registered route on the path. */
    if (method == HTTP_OPTIONS) return match_any_method(path, url_length, arena);

    return NULL;
}

/** Releases PathParams memory allocated during route registration. */
__attribute__((destructor)) void routing_cleanup(void) {
    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = &global_routes[i];
        if (r->route_type == ROUTE_TYPE_PARAM && r->state.path_params) {
            free(r->state.path_params->items);
            free(r->state.path_params);
        }
    }
}
