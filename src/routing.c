#include "../include/routing.h"
#include "../include/method.h"
#include "../include/utils.h"

// Static file handler is provided by pulsar.c.
extern void static_file_handler(struct connection_t* conn);

// Global routes
static route_t global_routes[MAX_ROUTES] = {};
static size_t global_route_count         = 0;

// Count the number of path parameters in pattern.
// If there is an invalid (unterminated) parameter, valid is updated to false.
INLINE size_t count_path_params(const char* pattern, bool* valid) {
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
INLINE bool match_path_parameters(const char* pattern, const char* url_path, PathParams* path_params) {
    const char* pat = pattern;
    const char* url = url_path;
    size_t nparams  = 0;

    // Fast path: exact match when no parameters were allocated.
    if (!path_params || !path_params->params) {
        while (*pat && *url && *pat == *url) {
            pat++;
            url++;
        }
        // Skip trailing slashes
        while (*pat == '/')
            pat++;
        while (*url == '/')
            url++;
        return (*pat == '\0' && *url == '\0');
    }

    // Initialize match count.
    path_params->match_count = 0;

    // Now, we have parameters
    while (*pat && *url && nparams < path_params->total_params) {
        if (*pat == '{') {
            // Bounds check
            PathParam* param = &path_params->params[nparams++];

            // Extract parameter name
            pat++;  // Skip '{'
            const char* name_start = pat;
            while (*pat && *pat != '}')
                pat++;
            if (*pat != '}') return false;

            size_t name_len = pat - name_start;

            param->name = malloc(name_len + 1);
            if (param->name == NULL) {
                perror("malloc");
                goto malloc_fail;
            }

            memcpy(param->name, name_start, name_len);
            param->name[name_len] = '\0';
            pat++;  // Skip '}'

            // Extract parameter value
            const char* val_start = url;
            while (*url && *url != '/' && *url != *pat)
                url++;
            size_t val_len = url - val_start;

            param->value = malloc(val_len + 1);
            if (param->value == NULL) {
                perror("malloc");
                goto malloc_fail;
            }
            memcpy(param->value, val_start, val_len);
            param->value[val_len] = '\0';
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

malloc_fail:
    // Free all params allocated.
    for (size_t i = 0; i < nparams; i++) {
        char* name  = path_params->params[i].name;
        char* value = path_params->params[i].value;
        if (name) free(name);
        if (value) free(value);
    }
    return false;
}

route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler) {
    ASSERT(global_route_count < MAX_ROUTES);
    ASSERT(METHOD_VALID(method));

    ASSERT(pattern && handler && "pattern and handler must not be NULL");

    route_t* r     = &global_routes[global_route_count];
    r->pattern     = pattern;
    r->method      = method;
    r->handler     = handler;
    r->flags       = NORMAL_ROUTE_FLAG;
    r->dirname     = NULL;
    r->path_params = NULL;

    bool pattern_valid;
    size_t nparams = count_path_params(pattern, &pattern_valid);
    ASSERT(pattern_valid && "Invalid path parameters in pattern");

    // Only allocate path params if they exist in the pattern.
    if (nparams > 0) {
        r->path_params = malloc(sizeof(PathParams));
        ASSERT(r->path_params && "malloc failed to allocate PathParams");

        r->path_params->match_count  = 0;        // Init the match count
        r->path_params->total_params = nparams;  // Set the expected path parameters
        r->path_params->params       = NULL;     // Init array to NULL.
        r->path_params->params       = calloc(nparams, sizeof(PathParam));
        ASSERT(r->path_params->params && "calloc failed to allocate array of PathParam's");
    }

    memset(r->middleware, 0, sizeof(r->middleware));  // zero middleware array
    r->mw_count = 0;                                  // intialize count to 0
    global_route_count++;                             // Increment global count
    return r;
}

route_t* route_static(const char* pattern, const char* dirname) {
    ASSERT(pattern && dirname && "pattern and dirname must be non-NULL");
    ASSERT(is_dir(dirname) && "dir must be an existing directory");

    route_t* r = route_register(pattern, HTTP_GET, static_file_handler);
    r->flags   = STATIC_ROUTE_FLAG;
    r->dirname = dirname;
    return r;
}

// Comparison function for sorting(qsort) of routes array by method then pattern.
static int compare_routes(const void* a, const void* b) {
    const route_t* ra = (const route_t*)a;
    const route_t* rb = (const route_t*)b;

    // First sort by method
    if (ra->method < rb->method) return -1;
    if (ra->method > rb->method) return 1;

    // Then sort by pattern length (longer patterns first)
    size_t len_a = strlen(ra->pattern);
    size_t len_b = strlen(rb->pattern);
    if (len_a > len_b) return -1;
    if (len_a < len_b) return 1;

    // Finally sort alphabetically
    return strcmp(ra->pattern, rb->pattern);
}

static int global_sort_state = 0;

// Sort defined routes so we can use binary search.
void sort_routes(void) {
    if (global_sort_state == 0 && global_route_count > 0) {
        qsort(global_routes, global_route_count, sizeof(route_t), compare_routes);
        global_sort_state = 1;
    }
}

typedef struct {
    uint32_t key;    // Hash of method and url.
    route_t* route;  // Matched route.
} RouteCacheEntry;

static RouteCacheEntry route_cache[ROUTE_CACHE_SIZE];

#define HASH_ROUTE_KEY(method, url, result)                                                                  \
    do {                                                                                                     \
        (result)      = (method);                                                                            \
        const char* p = (url);                                                                               \
        while (*p) {                                                                                         \
            (result) = (result) * 33 + *p++;                                                                 \
        }                                                                                                    \
    } while (0)

// Helper function to check if a route matches a URL
INLINE bool route_matches(route_t* route, const char* url, size_t url_length) {
    if ((route->flags & NORMAL_ROUTE_FLAG) != 0) {
        return match_path_parameters(route->pattern, url, route->path_params);
    } else if ((route->flags & STATIC_ROUTE_FLAG) != 0) {
        size_t pat_length = strlen(route->pattern);
        return (pat_length <= url_length) && (memcmp(route->pattern, url, pat_length) == 0);
    }
    return false;
}

route_t* route_match(const char* path, HttpMethod method) {
    // 0. Check cache first
    uint32_t key;
    HASH_ROUTE_KEY(method, path, key);
    uint32_t cache_slot = (key & ROUTE_CACHE_MASK);

    if (route_cache[cache_slot].key == key) {
        return route_cache[cache_slot].route;
    }

    // 1. First try exact method match using binary search
    size_t low         = 0;
    size_t high        = global_route_count;
    size_t first_match = global_route_count;

    while (low < high) {
        size_t mid            = low + (high - low) / 2;
        HttpMethod mid_method = global_routes[mid].method;
        if (mid_method >= method) {
            high = mid;
            if (mid_method == method) {
                first_match = mid;
            }
        } else {
            low = mid + 1;
        }
    }

    size_t url_length      = strlen(path);
    route_t* matched_route = NULL;

    // Search through routes of the matching method
    for (size_t i = first_match; i < global_route_count && global_routes[i].method == method; i++) {
        route_t* current = &global_routes[i];
        if (route_matches(current, path, url_length)) {
            matched_route = current;
            goto caching;
        }
    }

    // 2. Special case fallbacks
    if (method == HTTP_HEAD) {
        // HEAD falls back to GET, but we'll still process it as HEAD later
        matched_route = route_match(path, HTTP_GET);
        goto caching;
    } else if (method == HTTP_OPTIONS) {
        // OPTIONS matches if ANY route exists for this path
        for (size_t i = 0; i < global_route_count; i++) {
            route_t* current = &global_routes[i];
            if (route_matches(current, path, url_length)) {
                matched_route = current;
                goto caching;
            }
        }
    }

    // Store in cache before returning
    if (matched_route) {
    caching:
        route_cache[cache_slot].key   = key;
        route_cache[cache_slot].route = matched_route;
    }
    return matched_route;
}

INLINE void free_path_params(PathParams* path_params) {
    if (!path_params) return;

    PathParam* params_array = path_params->params;
    if (params_array) {
        for (size_t i = 0; i < path_params->match_count; i++) {
            char* name  = params_array[i].name;
            char* value = params_array[i].value;
            if (name) free(name);
            if (value) free(value);
        }
        free(params_array);
    }
    free(path_params);
}

__attribute__((destructor())) void routing_cleanup(void) {
    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = &global_routes[i];
        free_path_params(r->path_params);
    }
}
