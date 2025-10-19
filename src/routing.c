#include "../include/routing.h"
#include "../include/common.h"
#include "../include/method.h"

// Static file handler is provided by pulsar.c.
extern void static_file_handler(struct connection_t* conn);

// Global routes
static route_t global_routes[MAX_ROUTES] = {0};
static size_t global_route_count         = 0;

#define HTTP_METHOD_COUNT 7

// Pre-computed method offsets for O(1) method lookup.
// Packed as: (start_idx << 16) | end_idx for cache efficiency.
static uint32_t method_ranges[HTTP_METHOD_COUNT] = {0};

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

    if (is_static) {
        r->state.path_params = NULL;
    } else {
        bool pattern_valid;
        size_t nparams = count_path_params(pattern, &pattern_valid);
        ASSERT(pattern_valid && "Invalid path parameters in pattern");

        // Only allocate path params if they exist in the pattern.
        if (nparams > 0) {
            r->state.path_params = malloc(sizeof(PathParams));
            ASSERT(r->state.path_params && "malloc failed to allocate PathParams");

            r->state.path_params->match_count  = 0;        // Init the match count
            r->state.path_params->total_params = nparams;  // Set the expected path parameters
            r->state.path_params->items        = NULL;     // Init array to NULL.
            r->state.path_params->items        = calloc(nparams, sizeof(PathParam));
            ASSERT(r->state.path_params->items && "calloc failed to allocate array of PathParam's");
        }
    }

    memset(r->middleware, 0, sizeof(r->middleware));  // zero middleware array
    r->mw_count = 0;                                  // intialize count to 0
    global_route_count++;                             // Increment global count
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

static int global_sort_state = 0;

// Sort routes and build method lookup tables
void sort_routes(void) {
    if (global_sort_state == 0 && global_route_count > 0) {
        qsort(global_routes, global_route_count, sizeof(route_t), compare_routes);

        // Build method lookup tables for O(1) method range finding
        HttpMethod current_method = global_routes[0].method;
        uint32_t start_idx        = 0;

        for (size_t i = 1; i < global_route_count; i++) {
            HttpMethod method = global_routes[i].method;
            if (method != current_method) {
                // Pack: (start_idx << 16) | end_idx
                method_ranges[current_method] = (start_idx << 16) | (uint32_t)i;
                start_idx                     = (uint32_t)i;
                current_method                = method;
            }
        }
        method_ranges[current_method] = (start_idx << 16) | (uint32_t)global_route_count;
        global_sort_state             = 1;
    }
}

INLINE bool route_matches_fast(route_t* route, const char* url, size_t url_length, Arena* arena) {
    // Static route (less common)
    if (route->is_static) {
        return (route->pattern_len <= url_length) &&
               (memcmp(route->pattern, url, route->pattern_len) == 0);
    }

    // Parameterized routes
    if (route->state.path_params != NULL) {
        return match_path_parameters(route->pattern, url, route->state.path_params, arena);
    }

    // Unparameterized routes - handle trailing slashes
    const char* pat     = route->pattern;
    const char* url_ptr = url;
    size_t pat_len      = route->pattern_len;
    size_t url_len      = url_length;

    // Strip trailing slashes from both pattern and URL for comparison
    while (pat_len > 1 && pat[pat_len - 1] == '/') {
        pat_len--;
    }
    while (url_len > 1 && url_ptr[url_len - 1] == '/') {
        url_len--;
    }

    return (pat_len == url_len) && (memcmp(pat, url_ptr, url_len) == 0);
}

route_t* route_match(const char* path, size_t url_length, HttpMethod method, Arena* arena) {
    // Get method range using pre-computed lookup table
    uint32_t packed  = method_ranges[method];
    size_t start_idx = packed >> 16;     // Extract start_idx
    size_t end_idx   = packed & 0xFFFF;  // Extract end_idx

    // Linear search within method range.
    for (size_t i = start_idx; i < end_idx; i++) {
        route_t* current = &global_routes[i];
        if (route_matches_fast(current, path, url_length, arena)) {
            return current;
        }
    }

    // Handle special method fallbacks
    if (method == HTTP_HEAD) {
        return route_match(path, url_length, HTTP_GET, arena);
    } else if (method == HTTP_OPTIONS) {
        // OPTIONS matches if ANY route exists for this path
        for (size_t i = 0; i < global_route_count; i++) {
            if (route_matches_fast(&global_routes[i], path, url_length, arena)) {
                return &global_routes[i];
            }
        }
    }
    return NULL;
}

__attribute__((destructor())) void routing_cleanup(void) {
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
