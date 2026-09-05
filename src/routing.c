#include "../include/routing.h"
#include <solidc/filepath.h>
#include <stdalign.h>
#include <stdint.h>
#include <string.h>

#include "../include/method.h"

/** Static file handler provided by pulsar.c. */
extern void static_file_handler(PulsarCtx* ctx);

/** Global route storage. */
alignas(64) size_t global_route_count = 0;
alignas(64) route_t global_routes[MAX_ROUTES] = {0};

/** Direct O(1) fast-path cache for root route ("/") */
alignas(64) route_t* fast_root_routes[HTTP_METHOD_COUNT] = {0};

/** Safely reads up to 8 bytes into a 64-bit unsigned integer (zero-padded). */
INLINE uint64_t load_prefix8(const char* s, size_t len) {
    uint64_t v = 0;
    if (len >= 8) {
        memcpy(&v, s, 8);
    } else if (len > 0) {
        memcpy(&v, s, len);
    }
    return v;
}

/** Safely reads bytes 8..15 into a 64-bit unsigned integer (zero-padded). */
INLINE uint64_t load_prefix16(const char* s, size_t len) {
    uint64_t v = 0;
    if (len >= 16) {
        memcpy(&v, s + 8, 8);
    } else if (len > 8) {
        memcpy(&v, s + 8, len - 8);
    }
    return v;
}

/*
 * Compact per-route metadata stored contiguously for cache-friendly linear
 * scan. Only the fields that drive the initial match decision are kept here;
 * the full route_t is reached via `target` only on a confirmed match.
 *
 * Layout (on LP64):
 *   prefix8     8 B   first 8 bytes of pattern for 1-cycle integer rejection
 *   pattern     8 B   pointer into the permanent pattern string
 *   target      8 B   pointer to the full route_t (cold path)
 *   pattern_len 2 B
 *   route_type  1 B
 *   first_char  1 B   pattern[0], pre-extracted to avoid a pointer chase
 *   _pad        4 B   explicit padding to 32 B / natural alignment
 */
typedef struct ALIGN(32) RouteMetadata {
    uint64_t prefix8;     /**< First 8 bytes of pattern for 1-cycle rejection. */
    const char* pattern;  /**< Pointer to pattern string (permanent lifetime). */
    route_t* target;      /**< Pointer to the full route_t (used on match). */
    uint16_t pattern_len; /**< Byte length of pattern. */
    uint8_t route_type;   /**< ROUTE_TYPE_{EXACT,STATIC,PARAM}. */
    char first_char;      /**< pattern[0], pre-extracted to avoid a pointer chase. */
    uint8_t _pad[4];      /**< Pad to exactly 32 B (Power of 2). */
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
typedef struct ALIGN(16) MethodRoutes {
    RouteMetadata* routes; /**< Pointer to flat backing storage. */
    uint16_t count;        /**< Number of active entries. */
    uint16_t _pad[3];      /**< Explicit padding to align to exactly 16 B. */
} MethodRoutes;

alignas(64) static MethodRoutes method_routes[HTTP_METHOD_COUNT] = {0};

/* Flat, contiguous backing storage allocated once statically. */
alignas(64) static RouteMetadata method_route_storage[HTTP_METHOD_COUNT][MAX_ROUTES] = {0};

/*
 * Exact-match hash table (method + path -> route_t*).
 *
 * Exact routes dominate real-world traffic ("GET /", "GET /api/users"), and
 * the linear scan pays a length compare + first-char compare + memcmp per
 * candidate. This open-addressed table resolves them in one probe on average.
 * Built once in sort_routes(); read-only afterwards, so no locking needed.
 *
 * ROUTE_TYPE_EXACT routes are removed from the per-method linear arrays so
 * the fallback scan never re-tests what the hash already ruled out.
 */
#define EXACT_TABLE_SIZE 256 /* power of two; >= 2x MAX_ROUTES */
#define EXACT_TABLE_MASK (EXACT_TABLE_SIZE - 1)

typedef struct ALIGN(32) ExactEntry {
    uint64_t prefix8;     /**< First 8 bytes of pattern for 1-cycle integer comparison. */
    uint64_t prefix16;    /**< Bytes 8..15 (allows 16-byte matches without memcmp). */
    const char* pattern;  /**< Full pattern string. */
    route_t* target;      /**< Target route. */
    uint16_t pattern_len; /**< Pattern length. */
    uint16_t method;      /**< HttpMethod, folded into the probe key. */
    uint32_t hash_sig;    /**< 32-bit hash signature to verify collisions. */
} ExactEntry;

/* Aligned to 64-byte L1 cache boundaries */
alignas(64) static ExactEntry exact_table[EXACT_TABLE_SIZE] = {0};

/** 64-bit SWAR Multiplicative Hash: 3-cycle branchless hash for <= 8 bytes, SWAR for longer paths.
 */
INLINE uint32_t exact_hash(const char* path, size_t len, uint16_t method, uint64_t prefix8) {
    if (likely(len <= 8)) {
        uint64_t h = prefix8 ^ ((uint64_t)method * 0x9E3779B97F4A7C15ULL) ^
                     ((uint64_t)len * 0x517CC1B727220A95ULL);
        h ^= (h >> 33);
        h *= 0xFF51AFD7ED558CCDULL;
        h ^= (h >> 33);
        return (uint32_t)h;
    }

    uint64_t h =
        ((uint64_t)method * 0x9E3779B97F4A7C15ULL) ^ (len * 0x517CC1B727220A95ULL) ^ prefix8;
    const uint8_t* p = (const uint8_t*)path + 8;
    size_t rem = len - 8;

    while (rem >= 8) {
        uint64_t v;
        memcpy(&v, p, 8);
        h ^= v;
        h *= 0x517CC1B727220A95ULL;
        h ^= (h >> 32);
        p += 8;
        rem -= 8;
    }

    if (rem >= 4) {
        uint32_t v;
        memcpy(&v, p, 4);
        h ^= (uint64_t)v;
        h *= 0x517CC1B727220A95ULL;
        p += 4;
        rem -= 4;
    }

    while (rem > 0) {
        h ^= *p++;
        h *= 0x100000001B3ULL;
        rem--;
    }

    h ^= (h >> 33);
    h *= 0xFF51AFD7ED558CCDULL;
    h ^= (h >> 33);
    return (uint32_t)h;
}

/**
 * Looks up an EXACT route by method + path in O(1).
 * @return Matched route, or NULL.
 */
INLINE route_t* exact_lookup(const char* path, size_t len, HttpMethod method, uint64_t prefix8) {
    const uint32_t sig = exact_hash(path, len, (uint16_t)method, prefix8);
    size_t i = sig & EXACT_TABLE_MASK;

    while (exact_table[i].target) {
        const ExactEntry* e = &exact_table[i];
        if (e->hash_sig == sig && e->method == (uint16_t)method && e->pattern_len == len &&
            e->prefix8 == prefix8) {
            if (likely(len <= 8)) {
                return e->target;
            }
            if (len <= 16) {
                uint64_t p16 = load_prefix16(path, len);
                if (e->prefix16 == p16) return e->target;
            } else {
                if (memcmp(e->pattern + 8, path + 8, len - 8)) {
                    return e->target;
                }
            }
        }
        i = (i + 1) & EXACT_TABLE_MASK;
    }
    return NULL;
}

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
            p++; /* step past '}' */
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
        while (*p && *p != '}') p++;

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
static route_t* route_register_helper(const char* pattern, HttpMethod method, HttpHandler handler,
                                      int is_static) {
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

    /* Reset directory counts and map their contiguous backing storage */
    for (size_t i = 0; i < HTTP_METHOD_COUNT; i++) {
        method_routes[i].routes = method_route_storage[i];
        method_routes[i].count = 0;
        fast_root_routes[i] = NULL;
    }
    memset(exact_table, 0, sizeof(exact_table));

    /*
     * Build flat contiguous RouteMetadata arrays from the sorted global table.
     *
     * Copying the hot fields (pattern, pattern_len, route_type, first_char)
     * into the metadata array means the inner scan loop in match_method_routes
     * never dereferences route_t* to read those fields — every byte it needs
     * lives in the same cache line as the metadata entry itself.
     *
     * EXACT routes are diverted into exact_table[] instead; the linear scan
     * then only walks STATIC/PARAM candidates.
     */
    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = &global_routes[i];
        const HttpMethod method = r->method;

        ASSERT(method < HTTP_METHOD_COUNT && "Invalid method during sort");

        /* Cache fast-path root route */
        if (r->pattern_len == 1 && r->pattern[0] == '/' && r->route_type == ROUTE_TYPE_EXACT) {
            fast_root_routes[method] = r;
        }

        if (r->route_type == ROUTE_TYPE_EXACT) {
            uint64_t p8 = load_prefix8(r->pattern, r->pattern_len);
            uint64_t p16 = load_prefix16(r->pattern, r->pattern_len);
            uint32_t sig = exact_hash(r->pattern, r->pattern_len, (uint16_t)method, p8);
            size_t slot = sig & EXACT_TABLE_MASK;
            while (exact_table[slot].target) slot = (slot + 1) & EXACT_TABLE_MASK;

            exact_table[slot] = (ExactEntry){
                .prefix8 = p8,
                .prefix16 = p16,
                .pattern = r->pattern,
                .target = r,
                .pattern_len = r->pattern_len,
                .method = (uint16_t)method,
                .hash_sig = sig,
            };
            continue;
        }

        uint16_t idx = method_routes[method].count;
        ASSERT(idx < MAX_ROUTES && "Too many routes for method");

        method_routes[method].routes[idx] = (RouteMetadata){
            .prefix8 = load_prefix8(r->pattern, r->pattern_len),
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
static bool match_path_parameters(const char* pattern, const char* url, PathParams* path_params,
                                  Arena* arena) {
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
        while (*pat && *pat != '}') pat++;
        if (*pat != '}') return false; /* malformed pattern — defensive */
        pat++;                         /* skip '}' */

        /* Extract value: stop at '/', the next literal pattern character,
         * or end-of-string. Hoist *pat to avoid re-dereferencing each iter. */
        const char* val_start = url_ptr;
        const char stop_pat = *pat; /* next pattern char after '}' */

        if (stop_pat == '\0') {
            /* Terminal param: consume everything except a trailing slash. */
            while (*url_ptr && *url_ptr != '/') url_ptr++;
        } else {
            while (*url_ptr && *url_ptr != '/' && *url_ptr != stop_pat) url_ptr++;
        }

        const size_t val_len = (size_t)(url_ptr - val_start);
        param->value = arena_strdupn(arena, val_start, val_len);
        if (!param->value) return false;
    }

    /* Strip optional trailing slashes before the exhaustion check. */
    while (*pat == '/') pat++;
    while (*url_ptr == '/') url_ptr++;

    path_params->match_count = nparams;

    /* Branchless final check: all three conditions are cheap boolean loads. */
    return (*pat == '\0') & (*url_ptr == '\0') & (nparams == total_params);
}

/**
 * Searches the per-method RouteMetadata array for the first matching route.
 *
 * Only STATIC and PARAM routes live here; EXACT routes are resolved through
 * exact_table[] (see route_match). Candidates are ordered by specificity.
 *
 * @param method      HTTP method to search.
 * @param path        Request path.
 * @param url_length  Byte length of path.
 * @param prefix8     First 8 bytes of the path.
 * @param arena       Arena passed through to param matchers.
 * @return Matched route pointer, or NULL if none found.
 */
INLINE route_t* match_method_routes(HttpMethod method, const char* path, size_t url_length,
                                    uint64_t prefix8, Arena* arena) {
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
            case ROUTE_TYPE_STATIC:
                if (meta->pattern_len <= (uint16_t)url_length && meta->first_char == first_url_ch) {
                    if (meta->pattern_len <= 8) {
                        uint64_t mask = (meta->pattern_len == 8)
                                            ? ~0ULL
                                            : ((1ULL << (meta->pattern_len * 8)) - 1);
                        if ((prefix8 & mask) == meta->prefix8) {
                            return meta->target;
                        }
                    } else if (meta->prefix8 == prefix8 &&
                               memcmp(meta->pattern + 8, path + 8, meta->pattern_len - 8)) {
                        return meta->target;
                    }
                }
                break;

            case ROUTE_TYPE_PARAM:
                /*
                 * Parameterised matching is inherently variable-length; delegate
                 * to match_path_parameters. The first_char pre-check is omitted
                 * here because param patterns virtually always start with '/' and
                 * so do all URL paths — the check would never filter anything.
                 */
                if (match_path_parameters(meta->pattern, path, meta->target->state.path_params,
                                          arena)) {
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
INLINE route_t* match_any_method(const char* path, size_t url_length, uint64_t prefix8,
                                 Arena* arena) {
    for (size_t method = 0; method < HTTP_METHOD_COUNT; method++) {
        route_t* found = match_method_routes((HttpMethod)method, path, url_length, prefix8, arena);
        if (found) return found;
    }
    return NULL;
}

route_t* route_match(const char* path, size_t url_length, HttpMethod method, Arena* arena) {
    if (likely(url_length == 1 && path[0] == '/')) {
        if (likely((unsigned)method < HTTP_METHOD_COUNT)) {
            route_t* r = fast_root_routes[method];
            if (likely(r != NULL)) return r;
        }
        if (method == HTTP_HEAD) {
            route_t* r = fast_root_routes[HTTP_GET];
            if (r != NULL) return r;
        }
    }

    const uint64_t prefix8 = load_prefix8(path, url_length);
    route_t* found = exact_lookup(path, url_length, method, prefix8);
    if (likely(found != NULL)) return found;

    /* HEAD falls back to GET routes per RFC 9110 §9.3.2 (exact first). */
    if (method == HTTP_HEAD) {
        found = exact_lookup(path, url_length, HTTP_GET, prefix8);
        if (found) return found;
        return match_method_routes(HTTP_GET, path, url_length, prefix8, arena);
    }

    /* OPTIONS matches any registered route on the path. */
    if (method == HTTP_OPTIONS) {
        for (size_t m = 0; m < HTTP_METHOD_COUNT; m++) {
            found = exact_lookup(path, url_length, (HttpMethod)m, prefix8);
            if (found) return found;
        }
        return match_any_method(path, url_length, prefix8, arena);
    }

    return match_method_routes(method, path, url_length, prefix8, arena);
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
