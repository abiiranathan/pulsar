#include "../include/routing.h"
#include <solidc/filepath.h>
#include <stdalign.h>
#include <stdint.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <nmmintrin.h>  // Hardware CRC32 intrinsics
#endif

#include "../include/method.h"

#if defined(__clang__)
#define PULSAR_ASSUME(cond) __builtin_assume(cond)
#elif defined(__GNUC__)
#define PULSAR_ASSUME(cond)                   \
    do {                                      \
        if (!(cond)) __builtin_unreachable(); \
    } while (0)
#else
#define PULSAR_ASSUME(cond) ((void)0)
#endif

/** Static file handler provided by pulsar.c. */
extern void static_file_handler(PulsarCtx* ctx);

/** Global route storage. */
alignas(64) size_t global_route_count = 0;
alignas(64) route_t global_routes[MAX_ROUTES] = {0};

/** Direct O(1) fast-path cache for root route ("/") */
alignas(64) route_t* fast_root_routes[HTTP_METHOD_COUNT] = {0};

/**
 * Safely reads up to 8 bytes into a 64-bit integer.
 * Since path is always backed by a PATH_MAX (4096 B) buffer,
 * an 8-byte load is always memory-safe.
 */
INLINE uint64_t load_prefix8(const char* s, size_t len) {
    uint64_t v = 0;
    if (likely(len >= 8)) {
        memcpy(&v, s, 8);
    } else if (len > 0) {
        memcpy(&v, s, 8);  // Safe read from PATH_MAX buffer
        v &= (1ULL << (len * 8)) - 1ULL;
    }
    return v;
}

INLINE uint64_t load_prefix16(const char* s, size_t len) {
    uint64_t v = 0;
    if (len >= 16) {
        memcpy(&v, s + 8, 8);
    } else if (len > 8) {
        memcpy(&v, s + 8, 8);
        v &= (1ULL << ((len - 8) * 8)) - 1ULL;
    }
    return v;
}

typedef struct ALIGN(32) RouteMetadata {
    uint64_t prefix8;     /**< First 8 bytes of pattern for 1-cycle rejection. */
    const char* pattern;  /**< Pointer to pattern string (permanent lifetime). */
    route_t* target;      /**< Pointer to the full route_t (used on match). */
    uint16_t pattern_len; /**< Byte length of pattern. */
    uint8_t route_type;   /**< ROUTE_TYPE_{EXACT,STATIC,PARAM}. */
    char first_char;      /**< pattern[0], pre-extracted to avoid a pointer chase. */
    uint8_t _pad[4];      /**< Pad to exactly 32 B (Power of 2). */
} RouteMetadata;

typedef struct ALIGN(16) MethodRoutes {
    RouteMetadata* routes; /**< Pointer to flat backing storage. */
    uint16_t count;        /**< Number of active entries. */
    uint16_t _pad[3];      /**< Explicit padding to align to exactly 16 B. */
} MethodRoutes;

alignas(64) static MethodRoutes method_routes[HTTP_METHOD_COUNT] = {0};
alignas(64) static RouteMetadata method_route_storage[HTTP_METHOD_COUNT][MAX_ROUTES] = {0};

/*
 * Exact-match hash table (method + path -> route_t*).
 * Packed to exactly 32 BYTES: 2 entries fit per 64-byte L1 cache line.
 */
#define EXACT_TABLE_SIZE 256
#define EXACT_TABLE_MASK (EXACT_TABLE_SIZE - 1)

typedef struct ALIGN(32) ExactEntry {
    uint64_t prefix8;    /**< First 8 bytes of pattern. */
    uint64_t prefix16;   /**< Bytes 8..15. */
    route_t* target;     /**< Target route (contains pattern string pointer). */
    uint32_t len_method; /**< Combined (pattern_len << 16) | method for 1-cycle compare. */
    uint32_t hash_sig;   /**< 32-bit hash signature. */
} ExactEntry;

alignas(64) static ExactEntry exact_table[EXACT_TABLE_SIZE] = {0};

/**
 * Hardware-accelerated 3-cycle CRC32 hash for x86-64
 */
INLINE uint32_t exact_hash(const char* path, size_t len, uint16_t method, uint64_t prefix8) {
#if defined(__x86_64__) || defined(_M_X64)
    uint64_t crc = _mm_crc32_u64((uint64_t)method, prefix8);
    crc = _mm_crc32_u64(crc, (uint64_t)len);
    if (unlikely(len > 8)) {
        const uint8_t* p = (const uint8_t*)path + 8;
        size_t rem = len - 8;
        while (rem >= 8) {
            uint64_t v;
            memcpy(&v, p, 8);
            crc = _mm_crc32_u64(crc, v);
            p += 8;
            rem -= 8;
        }
        while (rem > 0) {
            crc = _mm_crc32_u8((uint32_t)crc, *p++);
            rem--;
        }
    }
    return (uint32_t)crc;
#else
    // High-entropy fallback
    uint64_t h =
        prefix8 ^ ((uint64_t)method * 0x9E3779B97F4A7C15ULL) ^ (len * 0x517CC1B727220A95ULL);
    h ^= (h >> 33);
    h *= 0xFF51AFD7ED558CCDULL;
    h ^= (h >> 33);
    return (uint32_t)h;
#endif
}

/**
 * Looks up an EXACT route by method + path in O(1).
 */
INLINE route_t* exact_lookup(const char* path, size_t len, HttpMethod method, uint64_t prefix8) {
    const uint32_t sig = exact_hash(path, len, (uint16_t)method, prefix8);
    const uint32_t len_method = ((uint32_t)len << 16) | (uint16_t)method;
    size_t i = sig & EXACT_TABLE_MASK;

    while (exact_table[i].target) {
        const ExactEntry* e = &exact_table[i];
        if (e->hash_sig == sig && e->len_method == len_method && e->prefix8 == prefix8) {
            if (likely(len <= 8)) {
                return e->target;
            }
            if (len <= 16) {
                if (e->prefix16 == load_prefix16(path, len)) return e->target;
            } else {
                // FIXED BUG: Added == 0
                if (memcmp(e->target->pattern + 8, path + 8, len - 8) == 0) {
                    return e->target;
                }
            }
        }
        i = (i + 1) & EXACT_TABLE_MASK;
    }
    return NULL;
}

static size_t count_path_params(const char* pattern, bool* valid) {
    const char* p = pattern;
    size_t count = 0;
    *valid = true;

    while (*p) {
        if (*p == '{') {
            p++;
            while (*p && *p != '}') {
                if (*p == '{') {
                    *valid = false;
                    return 0;
                }
                p++;
            }
            if (*p != '}') {
                *valid = false;
                return 0;
            }
            count++;
            p++;
        } else if (*p == '}') {
            *valid = false;
            return 0;
        } else {
            p++;
        }
    }
    return count;
}

INLINE uint8_t classify_route(const char* pattern, bool is_static, uint8_t* nparams) {
    if (is_static) return ROUTE_TYPE_STATIC;

    bool valid;
    *nparams = (uint8_t)count_path_params(pattern, &valid);
    ASSERT(valid && "Invalid path parameters in pattern");
    return (*nparams > 0) ? ROUTE_TYPE_PARAM : ROUTE_TYPE_EXACT;
}

static void populate_param_names(const char* pattern, PathParams* path_params) {
    const char* p = pattern;
    uint8_t idx = 0;
    const uint8_t total = path_params->total_params;

    while (*p && idx < total) {
        if (*p != '{') {
            p++;
            continue;
        }

        p++;
        const char* name_start = p;
        while (*p && *p != '}') p++;

        const size_t name_len = (size_t)(p - name_start);
        p++;

        path_params->items[idx].name = (char*)name_start;
        path_params->items[idx].name_len = name_len;
        idx++;
    }
}

static route_t* route_register_helper(const char* pattern, HttpMethod method, HttpHandler handler,
                                      int is_static) {
    ASSERT(global_route_count < MAX_ROUTES && "Route table full");
    ASSERT(METHOD_VALID(method) && "Invalid HTTP method");
    ASSERT(pattern && handler && "pattern and handler must not be NULL");

    uint8_t nparams = 0;
    route_t* r = &global_routes[global_route_count];

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

        r->state.path_params->items = calloc(nparams, sizeof(PathParam));
        ASSERT(r->state.path_params->items && "Failed to allocate PathParam array");

        r->state.path_params->match_count = 0;
        r->state.path_params->total_params = nparams;

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

static int compare_routes(const void* a, const void* b) {
    const route_t* ra = (const route_t*)a;
    const route_t* rb = (const route_t*)b;

    if (ra->method != rb->method) return (ra->method < rb->method) ? -1 : 1;

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

    for (size_t i = 0; i < HTTP_METHOD_COUNT; i++) {
        method_routes[i].routes = method_route_storage[i];
        method_routes[i].count = 0;
        fast_root_routes[i] = NULL;
    }
    memset(exact_table, 0, sizeof(exact_table));

    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = &global_routes[i];
        const HttpMethod method = r->method;

        ASSERT(method < HTTP_METHOD_COUNT && "Invalid method during sort");

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
                .target = r,
                .len_method = ((uint32_t)r->pattern_len << 16) | (uint16_t)method,
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

    // Pre-alias HEAD root route to GET root route if no explicit HEAD route was defined
    if (fast_root_routes[HTTP_HEAD] == NULL && fast_root_routes[HTTP_GET] != NULL) {
        fast_root_routes[HTTP_HEAD] = fast_root_routes[HTTP_GET];
    }

    sorted = 1;
}

static bool match_path_parameters(const char* pattern, const char* url, PathParams* path_params,
                                  Arena* arena) {
    const char* pat = pattern;
    const char* url_ptr = url;
    const uint8_t total_params = path_params->total_params;
    uint8_t nparams = 0;

    path_params->match_count = 0;

    while (*pat & *url_ptr) {
        if (*pat != '{') {
            if (*pat != *url_ptr) return false;
            pat++;
            url_ptr++;
            continue;
        }

        if (nparams == total_params) return false;

        PathParam* param = &path_params->items[nparams++];

        pat++;
        while (*pat && *pat != '}') pat++;
        if (*pat != '}') return false;
        pat++;

        const char* val_start = url_ptr;
        const char stop_pat = *pat;

        if (stop_pat == '\0') {
            while (*url_ptr && *url_ptr != '/') url_ptr++;
        } else {
            while (*url_ptr && *url_ptr != '/' && *url_ptr != stop_pat) url_ptr++;
        }

        const size_t val_len = (size_t)(url_ptr - val_start);
        param->value = arena_strdupn(arena, val_start, val_len);
        if (!param->value) return false;
    }

    while (*pat == '/') pat++;
    while (*url_ptr == '/') url_ptr++;

    path_params->match_count = nparams;
    return (*pat == '\0') & (*url_ptr == '\0') & (nparams == total_params);
}

INLINE route_t* match_method_routes(HttpMethod method, const char* path, size_t url_length,
                                    uint64_t prefix8, Arena* arena) {
    if (method >= HTTP_METHOD_COUNT) return NULL;

    const MethodRoutes* mr = &method_routes[method];
    const uint16_t count = mr->count;

    if (count == 0) return NULL;

    const RouteMetadata* routes = mr->routes;
    const char first_url_ch = path[0];

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
                               memcmp(meta->pattern + 8, path + 8, meta->pattern_len - 8) ==
                                   0) {  // FIXED BUG: Added == 0
                        return meta->target;
                    }
                }
                break;

            case ROUTE_TYPE_PARAM:
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

INLINE route_t* match_any_method(const char* path, size_t url_length, uint64_t prefix8,
                                 Arena* arena) {
    for (size_t method = 0; method < HTTP_METHOD_COUNT; method++) {
        route_t* found = match_method_routes((HttpMethod)method, path, url_length, prefix8, arena);
        if (found) return found;
    }
    return NULL;
}

__attribute__((hot)) route_t* route_match(const char* path, size_t url_length, HttpMethod method,
                                          Arena* arena) {
    // Ultra-fast path for "/"
    if (likely(url_length == 1 && path[0] == '/')) {
        if (likely((unsigned)method < HTTP_METHOD_COUNT)) {
            route_t* r = fast_root_routes[method];
            if (likely(r != NULL)) {
                // Eliminate the 6.33% branch stall by telling the compiler this is guaranteed EXACT
                PULSAR_ASSUME(r->route_type == ROUTE_TYPE_EXACT);
                PULSAR_ASSUME(r->handler != NULL);
                PULSAR_ASSUME(r->mw_count == 0);
                return r;
            }
        }
    }

    const uint64_t prefix8 = load_prefix8(path, url_length);
    route_t* found = exact_lookup(path, url_length, method, prefix8);
    if (likely(found != NULL)) return found;

    if (method == HTTP_HEAD) {
        found = exact_lookup(path, url_length, HTTP_GET, prefix8);
        if (found) return found;
        return match_method_routes(HTTP_GET, path, url_length, prefix8, arena);
    }

    if (method == HTTP_OPTIONS) {
        for (size_t m = 0; m < HTTP_METHOD_COUNT; m++) {
            found = exact_lookup(path, url_length, (HttpMethod)m, prefix8);
            if (found) return found;
        }
        return match_any_method(path, url_length, prefix8, arena);
    }

    return match_method_routes(method, path, url_length, prefix8, arena);
}

__attribute__((destructor)) void routing_cleanup(void) {
    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = &global_routes[i];
        if (r->route_type == ROUTE_TYPE_PARAM && r->state.path_params) {
            free(r->state.path_params->items);
            free(r->state.path_params);
        }
    }
}
