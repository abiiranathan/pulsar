// File: routing.c
// Implements Pulsar server routing.
// Heavily uses assert in functions that are guaranteed to fail at startup
// if a constraint is violated.

#include "../include/routing.h"
#include <linux/limits.h>
#include <stddef.h>
#include <stdio.h>
#include "../include/method.h"
#include "../include/utils.h"

// Static file handler is provided by pulsar.c.
extern void static_file_handler(struct connection_t* conn);

// Global routes
static route_t global_routes[MAX_ROUTES] = {};
static size_t global_route_count         = 0;

// Count the number of path parameters in pattern.
// If there is an invalid (unterminated) parameter, valid is updated to false.
static inline size_t count_path_params(const char* pattern, bool* valid) {
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
static bool match_path_parameters(const char* pattern, const char* url_path, PathParams* path_params) {
    if (!path_params)  // pattern/url/arena should be valid (since this is internal.)
        return false;

    const char* pat          = pattern;
    const char* url          = url_path;
    size_t nparams           = 0;
    path_params->match_count = 0;

    // Fast path: exact match when no parameters were allocated.
    if (path_params->params == NULL) {
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
            if (*pat != '}')
                return false;

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
            if (*pat != *url)
                return false;
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
        if (name)
            free(name);
        if (value)
            free(value);
    }
    return false;
}

route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler) {
    assert(global_route_count < MAX_ROUTES && http_method_valid(method) && pattern && handler &&
           "Invalid arguments");

    route_t* r = &global_routes[global_route_count];
    r->pattern = strdup(pattern);
    assert(r->pattern && "strdup failed to allocate pattern");

    r->method      = method;
    r->handler     = handler;
    r->path_params = malloc(sizeof(PathParams));
    assert(r->path_params && "malloc failed to allocate PathParams");

    bool valid;
    size_t nparams = count_path_params(pattern, &valid);
    assert(valid && "Invalid path parameters in pattern");

    r->path_params->match_count  = 0;        // Init the match count
    r->path_params->total_params = nparams;  // Set the expected path parameters
    r->path_params->params       = NULL;
    if (nparams > 0) {
        r->path_params->params = calloc(nparams, sizeof(PathParam));
        assert(r->path_params->params && "calloc failed to allocate array of PathParam's");
    }

    // default to normal route.
    r->flags   = NORMAL_ROUTE_FLAG;
    r->dirname = NULL;

    // Initialize route middleware
    r->mw_count = 0;
    memset(r->middleware, 0, sizeof(r->middleware));

    // Increment global count
    global_route_count++;
    return r;
}

route_t* register_static_route(const char* pattern, const char* dir) {
    assert(pattern && dir && "pattern and dir must not be NULL");

    if (strcmp(".", dir) == 0)
        dir = "./";
    if (strcmp("..", dir) == 0)
        dir = "../";
    size_t dirlen = strlen(dir);
    assert((dirlen + 1 < PATH_MAX) && "Directory name is too long");

    char* dirname = NULL;  // will be malloc'd
    if ((dirname = realpath(dir, NULL)) == NULL) {
        fprintf(stderr, "Unable to resolve path: %s\n", dir);
        exit(1);
    }

    // We must have a valid directory
    assert(is_dir(dirname) && "dir must be a valid path to an existing directory");

    if (dirname[dirlen - 1] == '/') {
        dirname[dirlen - 1] = '\0';  // Remove trailing slash
    }

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
    if (ra->method < rb->method)
        return -1;
    if (ra->method > rb->method)
        return 1;

    // Then sort by pattern length (longer patterns first)
    size_t len_a = strlen(ra->pattern);
    size_t len_b = strlen(rb->pattern);
    if (len_a > len_b)
        return -1;
    if (len_a < len_b)
        return 1;

    // Finally sort alphabetically
    return strcmp(ra->pattern, rb->pattern);
}

static int global_sort_state = 0;
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

// Generate a uint32_t hash of the method and url using FNV-1a hash.
static inline uint32_t hash_route_key(HttpMethod method, const char* url) {
    // FNV-1a hash.
    uint32_t hash = 2166136261u;

    // Hash method (as 4 bytes)
    // The prime multiplier (16777619) is specifically chosen for good avalanche characteristics
    // This manual byte extraction maintains the same hash irrespective of endianness.
    hash = (hash ^ (method >> 0)) * 16777619u;
    hash = (hash ^ (method >> 8)) * 16777619u;
    hash = (hash ^ (method >> 16)) * 16777619u;
    hash = (hash ^ (method >> 24)) * 16777619u;

    // Hash URL string
    while (*url) {
        hash = (hash ^ (uint32_t)(*url++)) * 16777619u;
    }
    return hash;
}

// Helper function to check if a route matches a URL
static inline bool route_matches(route_t* route, const char* url, size_t url_length) {
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
    uint32_t key        = hash_route_key(method, path);
    uint32_t cache_slot = key & (ROUTE_CACHE_SIZE - 1);

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

static inline void free_path_params(PathParams* path_params) {
    if (!path_params)
        return;

    PathParam* params = path_params->params;
    for (size_t i = 0; i < path_params->match_count; i++) {
        char* name  = params[i].name;
        char* value = params[i].value;
        if (name)
            free(name);
        if (value)
            free(value);
    }
    free(params);
    free(path_params);
}

__attribute__((destructor())) void routing_cleanup(void) {
    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = &global_routes[i];
        free(r->pattern);

        if (r->dirname) {
            free(r->dirname);
        }
        free_path_params(r->path_params);
    }
}
