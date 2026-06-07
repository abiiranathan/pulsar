#include "../include/routing.h"
#include <solidc/filepath.h>
#include <stdalign.h>
#include <string.h>

#include "../include/method.h"

/** Static file handler provided by pulsar.c. */
extern void static_file_handler(PulsarCtx* ctx);

/** Global route storage. */
static route_t global_routes[MAX_ROUTES] = {0};
static size_t global_route_count = 0;

/*
 * Compact per-route metadata stored contiguously for cache-friendly linear
 * scan. Only the fields that drive the initial match decision are kept here;
 * the full route_t is reached via `target` only on a confirmed match.
 *
 * Layout (on LP64):
 *   pattern    8 B   pointer into the permanent pattern string
 *   target     8 B   pointer to the full route_t (cold path)
 *   pattern_len 2 B
 *   route_type  1 B
 *   first_char  1 B  pre-extracted pattern[0] — saves one indirection per iter
 *   _pad        4 B  explicit padding to 24 B / natural alignment
 */
typedef struct {
    const char* pattern;  /**< Pointer to pattern string (permanent lifetime). */
    route_t* target;      /**< Pointer to the full route_t (used on match). */
    uint16_t pattern_len; /**< Byte length of pattern. */
    uint8_t route_type;   /**< ROUTE_TYPE_{EXACT,STATIC,PARAM}. */
    char first_char;      /**< pattern[0], pre-extracted to avoid a pointer chase. */
    uint8_t _pad[4];      /**< Pad to exactly 24 B (LP64 natural alignment). */
} RouteMetadata;

/*
 * Method-specific pointer directory.
 *
 * Struct is exactly 16 bytes (a power of two). This allows the compiler to index 
 * into `method_routes[method]` using a single shift instruction (e.g. `shl rax, 4`) 
 * instead of generating an expensive `imul` integer multiplication.
 *
 * All directories fit within two 64-byte cache lines. Both `routes` and `count` 
 * are guaranteed to reside in the same cache line.
 */
typedef struct {
    RouteMetadata* routes; /**< Pointer to flat backing storage. */
    uint16_t count;        /**< Number of active entries. */
    uint16_t _pad[3];      /**< Explicit padding to align to exactly 16 B. */
} MethodRoutes;

static MethodRoutes method_routes[HTTP_METHOD_COUNT] = {0};

/* Flat, contiguous backing storage allocated once statically. */
static RouteMetadata method_route_storage[HTTP_METHOD_COUNT][MAX_ROUTES] = {0};

/*
 * Portable __builtin_memcmp shim.
 *
 * GCC and Clang expand __builtin_memcmp to inline scalar/SIMD comparisons
 * for sizes known at compile time, and to a direct call (no PLT) otherwise.
 * The PLT call to bcmp@plt that appeared in the profiling report is the
 * symptom this shim addresses. On compilers that don't provide the builtin
 * the macro falls back to the standard memcmp, which is correct if slower.
 */
#if defined(__GNUC__) || defined(__clang__)
#define ROUTE_MEMCMP(a, b, n) __builtin_memcmp((a), (b), (n))
#else
#define ROUTE_MEMCMP(a, b, n) memcmp((a), (b), (n))
#endif

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
    size_t count = 0;
    *valid = true;

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
INLINE uint8_t classify_route(const char* pattern, bool is_static, uint8_t* nparams) {
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
    const char* p = pattern;
    uint8_t idx = 0;
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
         * pattern string. No allocation is needed; lifetime matches the route.
         * We cast away const to satisfy the non-const field, but the pointer
         * will never be written through in the matcher.
         */
        path_params->items[idx].name = (char*)name_start;
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
static route_t* route_register_helper(const char* pattern, HttpMethod method, HttpHandler handler, int is_static) {
    ASSERT(global_route_count < MAX_ROUTES && "Route table full");
    ASSERT(METHOD_VALID(method) && "Invalid HTTP method");
    ASSERT(pattern && handler && "pattern and handler must not be NULL");

    uint8_t nparams = 0;
    route_t* r = &global_routes[global_route_count];

    /* Zero-initialise the whole entry via compound literal, then fill fields.
     * A single memset-equivalent store is cheaper than piecemeal zeroing. */
    *r = (route_t){
        .pattern = pattern,
        .pattern_len = (uint16_t)strlen(pattern),
        .method = method,
        .handler = handler,
        .route_type = classify_route(pattern, is_static, &nparams),
    };

    if (r->route_type == ROUTE_TYPE_PARAM && nparams > 0) {
        r->state.path_params = malloc(sizeof(PathParams));
        ASSERT(r->state.path_params && "Failed to allocate PathParams");

        /* calloc zero-initialises name/value pointers in every PathParam. */
        r->state.path_params->items = calloc(nparams, sizeof(PathParam));
        ASSERT(r->state.path_params->items && "Failed to allocate PathParam array");

        r->state.path_params->match_count = 0;
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

    route_t* r = route_register_helper(pattern, HTTP_GET, static_file_handler, 1);
    r->state.static_.dirname = dirname;
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
    const bool ra_root_static = (ra->route_type == ROUTE_TYPE_STATIC && ra->pattern_len == 1 && ra->pattern[0] == '/');
    const bool rb_root_static = (rb->route_type == ROUTE_TYPE_STATIC && rb->pattern_len == 1 && rb->pattern[0] == '/');

    if (ra_root_static != rb_root_static) return ra_root_static ? 1 : -1;

    if (ra->route_type != rb->route_type) return (ra->route_type < rb->route_type) ? -1 : 1;

    if (ra->pattern_len != rb->pattern_len) return (ra->pattern_len > rb->pattern_len) ? -1 : 1;

    return strcmp(ra->pattern, rb->pattern);
}

void sort_routes(void) {
    static int sorted = 0;
    if (sorted || global_route_count == 0) return;

    qsort(global_routes, global_route_count, sizeof(route_t), compare_routes);

    /* Reset directory counts and map their contiguous backing storage */
    for (size_t i = 0; i < HTTP_METHOD_COUNT; i++) {
        method_routes[i].routes = method_route_storage[i];
        method_routes[i].count = 0;
    }

    /*
     * Build flat contiguous RouteMetadata arrays from the sorted global table.
     *
     * Copying the hot fields (pattern, pattern_len, route_type, first_char)
     * into the metadata array means the inner scan loop in match_method_routes
     * never dereferences route_t* to read those fields — every byte it needs
     * lives in the same cache line as the metadata entry itself.
     */
    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = &global_routes[i];
        const HttpMethod method = r->method;

        ASSERT(method < HTTP_METHOD_COUNT && "Invalid method during sort");

        uint16_t idx = method_routes[method].count;
        ASSERT(idx < MAX_ROUTES && "Too many routes for method");

        method_routes[method].routes[idx] = (RouteMetadata){
            .pattern = r->pattern,
            .target = r,
            .pattern_len = r->pattern_len,
            .route_type = r->route_type,
            .first_char = r->pattern[0],
        };
        method_routes[method].count++;
    }

    sorted = 1;
}

/**
 * Matches a parameterised route pattern against a URL and extracts values.
 *
 * Param names are pre-populated at registration time (see populate_param_names),
 * so this function only allocates arena memory for extracted values — never for
 * names. This is the primary hot-path optimisation over the naive approach.
 *
 * Single-pass over both strings simultaneously. The literal-character path
 * (overwhelmingly the common case) costs one compare and two pointer increments
 * per character. The bitwise-AND loop condition tests both pointers for
 * non-NUL in a single branch.
 *
 * @param pattern     Route pattern with {param} placeholders.
 * @param url         URL path to match against.
 * @param path_params PathParams with names already filled; values are written here.
 * @param arena       Arena used for value string allocation.
 * @return true if the pattern matches the URL exactly and all params were filled.
 */
static bool match_path_parameters(const char* pattern, const char* url, PathParams* path_params, Arena* arena) {
    const char* pat = pattern;
    const char* url_ptr = url;
    const uint8_t total_params = path_params->total_params;
    uint8_t nparams = 0;

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
         * or end-of-string. Hoist *pat to avoid re-dereferencing each iter. */
        const char* val_start = url_ptr;
        const char stop_pat = *pat; /* next pattern char after '}' */

        if (stop_pat == '\0') {
            /* Terminal param: consume everything except a trailing slash. */
            while (*url_ptr && *url_ptr != '/')
                url_ptr++;
        } else {
            while (*url_ptr && *url_ptr != '/' && *url_ptr != stop_pat)
                url_ptr++;
        }

        const size_t val_len = (size_t)(url_ptr - val_start);
        param->value = arena_strdupn(arena, val_start, val_len);
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
 * Searches the per-method RouteMetadata array for the first matching route.
 *
 * Fast bitwise shifts (shl rax, 4) determine directory offsets, replacing 
 * the high-latency integer multiplication (imul) instructions.
 *
 * If no routes exist for a method, this function exits instantly, sparing 
 * the L1 data cache from pulling in unnecessary storage partitions.
 *
 * @param method     HTTP method to search.
 * @param path       Request path.
 * @param url_length Byte length of path.
 * @param arena      Arena passed through to param matchers.
 * @return Matched route pointer, or NULL if none found.
 */
INLINE route_t* match_method_routes(HttpMethod method, const char* path, size_t url_length, Arena* arena) {
    if (method >= HTTP_METHOD_COUNT) return NULL;

    const MethodRoutes* mr = &method_routes[method];
    const uint16_t count = mr->count;

    /* Exit immediately if no routes exist for this method */
    if (count == 0) return NULL;

    const RouteMetadata* routes = mr->routes;
    const char first_url_ch = path[0]; /* hoist: avoids re-read each iteration */

    for (uint16_t i = 0; i < count; i++) {
        const RouteMetadata* meta = &routes[i];

        switch (meta->route_type) {
            case ROUTE_TYPE_EXACT:
                if (meta->pattern_len == (uint16_t)url_length && meta->first_char == first_url_ch &&
                    ROUTE_MEMCMP(meta->pattern, path, url_length) == 0) {
                    return meta->target;
                }
                break;

            case ROUTE_TYPE_STATIC:
                if (meta->pattern_len <= (uint16_t)url_length && meta->first_char == first_url_ch &&
                    ROUTE_MEMCMP(meta->pattern, path, meta->pattern_len) == 0) {
                    return meta->target;
                }
                break;

            case ROUTE_TYPE_PARAM:
                /*
                 * Parameterised matching is inherently variable-length; delegate
                 * to match_path_parameters. The first_char pre-check is omitted
                 * here because param patterns virtually always start with '/' and
                 * so do all URL paths — the check would never filter anything.
                 */
                if (match_path_parameters(meta->pattern, path, meta->target->state.path_params, arena)) {
                    return meta->target;
                }
                break;

            default:
                break;
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
INLINE route_t* match_any_method(const char* path, size_t url_length, Arena* arena) {
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
