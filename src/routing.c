#include "../include/routing.h"
#include "../include/common.h"
#include "../include/method.h"

// Static file handler is provided by pulsar.c.
extern void static_file_handler(struct connection_t* conn);

// Normal routes
static route_t dynamic_routes[MAX_ROUTES] = {0};
static size_t dynamic_route_count         = 0;

// Static routes routes
static route_t static_routes[MAX_STATIC_ROUTES] = {0};
static size_t static_route_count                = 0;

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
INLINE bool match_path_parameters(const char* pattern, const char* url_path,
                                  PathParams* path_params) {
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

            size_t name_len = (size_t)(pat - name_start);

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
            size_t val_len = (size_t)(url - val_start);

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

INLINE route_t* _register_route_helper(const char* pattern, HttpMethod method, HttpHandler handler,
                                       bool is_static) {
    route_t* routes   = is_static ? static_routes : dynamic_routes;
    size_t* count     = (is_static ? &static_route_count : &dynamic_route_count);
    size_t max_routes = (is_static ? MAX_STATIC_ROUTES : MAX_ROUTES);

    ASSERT(METHOD_VALID(method));
    ASSERT(pattern && handler && "pattern and handler must not be NULL");
    ASSERT(
        *count < max_routes &&
        "Exceeded maximum allowed routes. Increase the MAX_ROUTES or MAX_STATIC_ROUTES constants");

    route_t* r         = &routes[*count];
    r->pattern         = pattern;
    r->pattern_len     = strlen(pattern);
    r->method          = method;
    r->handler         = handler;
    r->dirname         = NULL;
    r->dirname_len     = 0;
    r->path_params     = NULL;
    bool pattern_valid = false;

    size_t nparams = count_path_params(pattern, &pattern_valid);
    ASSERT(pattern_valid && "Invalid path parameters in pattern");
    r->has_params = nparams > 0 ? 1 : 0;

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
    (*count)++;                                       // Increment global count
    return r;
}

route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler) {
    return _register_route_helper(pattern, method, handler, false);
}

route_t* route_static(const char* pattern, const char* dirname) {
    ASSERT(pattern && dirname && "pattern and dirname must be non-NULL");
    ASSERT(is_dir(dirname) && "dir must be an existing directory");

    route_t* r    = _register_route_helper(pattern, HTTP_GET, static_file_handler, true);
    r->dirname    = dirname;
    size_t length = strlen(dirname);

    // Make sure length fits inside uint8_t.
    ASSERT(length <= UINT8_MAX && "dirname should be <= 255 characters");
    r->dirname_len = length;
    return r;
}

// single fast path.
INLINE bool route_matches_fast(const route_t* route, const char* url, size_t url_len) {
    // Exact match route: memcmp with trailing slash tolerance
    if (!route->has_params) {
        // Try exact match first (most common case)
        if (route->pattern_len == url_len && memcmp(route->pattern, url, url_len) == 0) {
            return true;
        }

        // Handle trailing slash cases: /api/json vs /api/json/
        const char* pat     = route->pattern;
        const char* url_ptr = url;

        // Skip past common prefix
        size_t min_len = (route->pattern_len < url_len) ? route->pattern_len : url_len;
        if (memcmp(pat, url_ptr, min_len) != 0) {
            return false;
        }

        // Skip trailing slashes in both
        pat += min_len;
        url_ptr += min_len;
        while (*pat == '/')
            pat++;
        while (*url_ptr == '/')
            url_ptr++;

        return (*pat == '\0' && *url_ptr == '\0');
    }

    // Exact match route
    if (!route->has_params) {
        return memcmp(route->pattern, url, url_len) == 0;
    }

    // Parameterized route.
    return match_path_parameters(route->pattern, url, route->path_params);
}

__attribute__((hot)) const route_t* route_match(const char* path, HttpMethod method) {
    size_t url_len = strlen(path);

retry_method:
    // --- 1. Dynamic routes (parameterized) ---
    for (size_t i = 0; i < dynamic_route_count; i++) {
        const route_t* route = &dynamic_routes[i];

        // Methods always match for dynamic routes
        if (route->method != method) continue;

        if (route_matches_fast(route, path, url_len)) return route;
    }

    // --- 2. Static routes (prefix match) ---
    for (size_t i = 0; i < static_route_count; i++) {
        const route_t* route = &static_routes[i];

        if (route->method != method) continue;
        if (route->pattern_len > url_len) continue;

        // Prefix match only (fast path)
        if (memcmp(route->pattern, path, route->pattern_len) == 0) return route;
    }

    // --- 3. Fallback logic ---
    switch (method) {
        case HTTP_HEAD:
            // Retry as GET (shared handlers)
            method = HTTP_GET;
            goto retry_method;

        case HTTP_OPTIONS:
            // OPTIONS matches any existing route
            for (size_t i = 0; i < dynamic_route_count; i++) {
                if (route_matches_fast(&dynamic_routes[i], path, url_len))
                    return &dynamic_routes[i];
            }
            for (size_t i = 0; i < static_route_count; i++) {
                if (memcmp(static_routes[i].pattern, path, static_routes[i].pattern_len) == 0)
                    return &static_routes[i];
            }
            break;

        default:
            break;
    }

    return NULL;
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
    for (size_t i = 0; i < dynamic_route_count; i++) {
        route_t* r = &dynamic_routes[i];
        free_path_params(r->path_params);
    }
}
