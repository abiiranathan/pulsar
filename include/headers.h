/**
 * @file headers.h
 * @brief Ultra-fast HTTP header storage with O(1) static header lookups
 *
 * This implementation uses a bitmask for O(1) presence checking of common headers,
 * combined with hash-based identification for fast operations. Custom headers fall
 * back to hash table semantics with linear probing.
 *
 * Features:
 * - O(1) presence check for standard headers via bitmask
 * - Pre-computed hash table for header name resolution
 * - Arena-based memory management for zero-fragmentation
 * - Support for multi-value headers (Set-Cookie)
 * - Case-insensitive header name matching
 *
 * @copyright Copyright (c) 2024
 */

#ifndef SOLIDC_HEADERS_H
#define SOLIDC_HEADERS_H

#include <solidc/arena.h>
#include <stdbool.h>
#include <stdint.h>
#include <strings.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Configuration */
#ifndef HEADERS_CAPACITY
#define HEADERS_CAPACITY 64
#endif

/**
 * @brief Standard HTTP header identifiers (max 63 for uint64_t bitmask)
 *
 * These IDs correspond to bit positions in the headers_t.mask field.
 * HDR_CUSTOM (0) is reserved for non-standard headers.
 */
typedef enum {
    HDR_CUSTOM = 0,  // Non-standard header

    /* Request Headers */
    HDR_HOST,                       // 1
    HDR_USER_AGENT,                 // 2
    HDR_ACCEPT,                     // 3
    HDR_ACCEPT_ENCODING,            // 4
    HDR_ACCEPT_LANGUAGE,            // 5
    HDR_ACCEPT_CHARSET,             // 6
    HDR_CONNECTION,                 // 7
    HDR_CONTENT_TYPE,               // 8
    HDR_CONTENT_LENGTH,             // 9
    HDR_CONTENT_ENCODING,           // 10
    HDR_AUTHORIZATION,              // 11
    HDR_COOKIE,                     // 12
    HDR_REFERER,                    // 13
    HDR_ORIGIN,                     // 14
    HDR_IF_MODIFIED_SINCE,          // 15
    HDR_IF_NONE_MATCH,              // 16
    HDR_IF_MATCH,                   // 17
    HDR_IF_UNMODIFIED_SINCE,        // 18
    HDR_IF_RANGE,                   // 19
    HDR_RANGE,                      // 20
    HDR_CACHE_CONTROL,              // 21
    HDR_PRAGMA,                     // 22
    HDR_TE,                         // 23
    HDR_UPGRADE,                    // 24
    HDR_UPGRADE_INSECURE_REQUESTS,  // 25

    /* Response Headers */
    HDR_SET_COOKIE,          // 26
    HDR_LOCATION,            // 27
    HDR_SERVER,              // 28
    HDR_DATE,                // 29
    HDR_LAST_MODIFIED,       // 30
    HDR_ETAG,                // 31
    HDR_EXPIRES,             // 32
    HDR_AGE,                 // 33
    HDR_VARY,                // 34
    HDR_TRANSFER_ENCODING,   // 35
    HDR_ALLOW,               // 36
    HDR_CONTENT_RANGE,       // 37
    HDR_ACCEPT_RANGES,       // 38
    HDR_WWW_AUTHENTICATE,    // 39
    HDR_PROXY_AUTHENTICATE,  // 40
    HDR_RETRY_AFTER,         // 41

    /* CORS Headers */
    HDR_ACCESS_CONTROL_ALLOW_ORIGIN,       // 42
    HDR_ACCESS_CONTROL_ALLOW_METHODS,      // 43
    HDR_ACCESS_CONTROL_ALLOW_HEADERS,      // 44
    HDR_ACCESS_CONTROL_EXPOSE_HEADERS,     // 45
    HDR_ACCESS_CONTROL_MAX_AGE,            // 46
    HDR_ACCESS_CONTROL_ALLOW_CREDENTIALS,  // 47
    HDR_ACCESS_CONTROL_REQUEST_METHOD,     // 48
    HDR_ACCESS_CONTROL_REQUEST_HEADERS,    // 49

    /* Security Headers */
    HDR_STRICT_TRANSPORT_SECURITY,  // 50
    HDR_CONTENT_SECURITY_POLICY,    // 51
    HDR_X_FRAME_OPTIONS,            // 52
    HDR_X_CONTENT_TYPE_OPTIONS,     // 53
    HDR_X_XSS_PROTECTION,           // 54
    HDR_REFERRER_POLICY,            // 55

    /* Other Common Headers */
    HDR_X_FORWARDED_FOR,    // 56
    HDR_X_FORWARDED_PROTO,  // 57
    HDR_X_FORWARDED_HOST,   // 58
    HDR_X_REAL_IP,          // 59
    HDR_FORWARDED,          // 60
    HDR_VIA,                // 61
    HDR_ALT_SVC,            // 62

    HDR_MAX_STATIC = 63  // Maximum static header ID
} header_id_t;

/**
 * @brief Individual header entry
 */
typedef struct {
    uint32_t hash;      // FNV-1a hash of lowercase name
    uint8_t id;         // header_id_t
    const char* name;   // Header name (points to static string or arena)
    const char* value;  // Header value (arena-allocated)
} header_entry;

/**
 * @brief HTTP headers collection with fast static header lookups
 */
typedef struct {
    Arena* arena;   // Memory arena for allocations
    uint64_t mask;  // Bitmask: bit i set if HDR_i is present
    size_t count;   // Number of headers
    header_entry entries[HEADERS_CAPACITY];
} headers_t;

/* Static header name strings (shared, never duplicated) */
static const char* const HEADER_NAMES[] = {
    [HDR_CUSTOM] = NULL,
    [HDR_HOST] = "Host",
    [HDR_USER_AGENT] = "User-Agent",
    [HDR_ACCEPT] = "Accept",
    [HDR_ACCEPT_ENCODING] = "Accept-Encoding",
    [HDR_ACCEPT_LANGUAGE] = "Accept-Language",
    [HDR_ACCEPT_CHARSET] = "Accept-Charset",
    [HDR_CONNECTION] = "Connection",
    [HDR_CONTENT_TYPE] = "Content-Type",
    [HDR_CONTENT_LENGTH] = "Content-Length",
    [HDR_CONTENT_ENCODING] = "Content-Encoding",
    [HDR_AUTHORIZATION] = "Authorization",
    [HDR_COOKIE] = "Cookie",
    [HDR_REFERER] = "Referer",
    [HDR_ORIGIN] = "Origin",
    [HDR_IF_MODIFIED_SINCE] = "If-Modified-Since",
    [HDR_IF_NONE_MATCH] = "If-None-Match",
    [HDR_IF_MATCH] = "If-Match",
    [HDR_IF_UNMODIFIED_SINCE] = "If-Unmodified-Since",
    [HDR_IF_RANGE] = "If-Range",
    [HDR_RANGE] = "Range",
    [HDR_CACHE_CONTROL] = "Cache-Control",
    [HDR_PRAGMA] = "Pragma",
    [HDR_TE] = "TE",
    [HDR_UPGRADE] = "Upgrade",
    [HDR_UPGRADE_INSECURE_REQUESTS] = "Upgrade-Insecure-Requests",
    [HDR_SET_COOKIE] = "Set-Cookie",
    [HDR_LOCATION] = "Location",
    [HDR_SERVER] = "Server",
    [HDR_DATE] = "Date",
    [HDR_LAST_MODIFIED] = "Last-Modified",
    [HDR_ETAG] = "ETag",
    [HDR_EXPIRES] = "Expires",
    [HDR_AGE] = "Age",
    [HDR_VARY] = "Vary",
    [HDR_TRANSFER_ENCODING] = "Transfer-Encoding",
    [HDR_ALLOW] = "Allow",
    [HDR_CONTENT_RANGE] = "Content-Range",
    [HDR_ACCEPT_RANGES] = "Accept-Ranges",
    [HDR_WWW_AUTHENTICATE] = "WWW-Authenticate",
    [HDR_PROXY_AUTHENTICATE] = "Proxy-Authenticate",
    [HDR_RETRY_AFTER] = "Retry-After",
    [HDR_ACCESS_CONTROL_ALLOW_ORIGIN] = "Access-Control-Allow-Origin",
    [HDR_ACCESS_CONTROL_ALLOW_METHODS] = "Access-Control-Allow-Methods",
    [HDR_ACCESS_CONTROL_ALLOW_HEADERS] = "Access-Control-Allow-Headers",
    [HDR_ACCESS_CONTROL_EXPOSE_HEADERS] = "Access-Control-Expose-Headers",
    [HDR_ACCESS_CONTROL_MAX_AGE] = "Access-Control-Max-Age",
    [HDR_ACCESS_CONTROL_ALLOW_CREDENTIALS] = "Access-Control-Allow-Credentials",
    [HDR_ACCESS_CONTROL_REQUEST_METHOD] = "Access-Control-Request-Method",
    [HDR_ACCESS_CONTROL_REQUEST_HEADERS] = "Access-Control-Request-Headers",
    [HDR_STRICT_TRANSPORT_SECURITY] = "Strict-Transport-Security",
    [HDR_CONTENT_SECURITY_POLICY] = "Content-Security-Policy",
    [HDR_X_FRAME_OPTIONS] = "X-Frame-Options",
    [HDR_X_CONTENT_TYPE_OPTIONS] = "X-Content-Type-Options",
    [HDR_X_XSS_PROTECTION] = "X-XSS-Protection",
    [HDR_REFERRER_POLICY] = "Referrer-Policy",
    [HDR_X_FORWARDED_FOR] = "X-Forwarded-For",
    [HDR_X_FORWARDED_PROTO] = "X-Forwarded-Proto",
    [HDR_X_FORWARDED_HOST] = "X-Forwarded-Host",
    [HDR_X_REAL_IP] = "X-Real-IP",
    [HDR_FORWARDED] = "Forwarded",
    [HDR_VIA] = "Via",
    [HDR_ALT_SVC] = "Alt-Svc",
};

/**
 * @brief Compute FNV-1a hash and resolve header ID
 * @param name Header name (case-insensitive)
 * @param out_hash Output parameter for computed hash
 * @return Static header ID or HDR_CUSTOM
 */
static ARENA_INLINE header_id_t resolve_static_id(const char* name, uint32_t* out_hash) {
    // FNV-1a hash with case normalization
    uint32_t h = 0x811c9dc5u;
    const char* p = name;
    while (*p) {
        char c = *p++;
        if (c >= 'A' && c <= 'Z') c += 32;  // to lowercase
        h = (h ^ (uint8_t)c) * 0x01000193u;
    }

    if (out_hash) *out_hash = h;

    // Perfect hash lookup for common headers
    // These hashes are computed from lowercase header names
    switch (h) {
        case 0xaffea56fu:
            return HDR_HOST;
        case 0x24259beeu:
            return HDR_USER_AGENT;
        case 0x08247e29u:
            return HDR_ACCEPT;
        case 0xc9715a99u:
            return HDR_ACCEPT_ENCODING;
        case 0x75f67716u:
            return HDR_ACCEPT_LANGUAGE;
        case 0xda645c68u:
            return HDR_ACCEPT_CHARSET;
        case 0x38b99ed9u:
            return HDR_CONNECTION;
        case 0xfcf70995u:
            return HDR_CONTENT_TYPE;
        case 0x4df9451du:
            return HDR_CONTENT_LENGTH;
        case 0x03e2ed88u:
            return HDR_CONTENT_ENCODING;
        case 0x913657beu:
            return HDR_AUTHORIZATION;
        case 0x77a740bfu:
            return HDR_COOKIE;
        case 0xec9af966u:
            return HDR_REFERER;
        case 0xd97f9a4fu:
            return HDR_ORIGIN;
        case 0x83e879a9u:
            return HDR_IF_MODIFIED_SINCE;
        case 0x972b6177u:
            return HDR_IF_NONE_MATCH;
        case 0xd67076eau:
            return HDR_IF_MATCH;
        case 0xe230478au:
            return HDR_IF_UNMODIFIED_SINCE;
        case 0x8b887e3eu:
            return HDR_IF_RANGE;
        case 0xfadc0cd2u:
            return HDR_RANGE;
        case 0x50c8a4cdu:
            return HDR_CACHE_CONTROL;
        case 0x19fa4625u:
            return HDR_PRAGMA;
        case 0x3c453eb2u:
            return HDR_TE;
        case 0xdc97cc77u:
            return HDR_UPGRADE;
        case 0x93c51f85u:
            return HDR_UPGRADE_INSECURE_REQUESTS;
        case 0x6e2be738u:
            return HDR_SET_COOKIE;
        case 0x0bf5a9a6u:
            return HDR_LOCATION;
        case 0x40ac3dd2u:
            return HDR_SERVER;
        case 0xd472dc59u:
            return HDR_DATE;
        case 0xc0575a6bu:
            return HDR_LAST_MODIFIED;
        case 0x06c857c0u:
            return HDR_ETAG;
        case 0x3e8ec783u:
            return HDR_EXPIRES;
        case 0x2c41499cu:
            return HDR_AGE;
        case 0x40abde45u:
            return HDR_VARY;
        case 0xddb4744cu:
            return HDR_TRANSFER_ENCODING;
        case 0xaeb1a832u:
            return HDR_ALLOW;
        case 0xd3ecfa4au:
            return HDR_CONTENT_RANGE;
        case 0x6625cf66u:
            return HDR_ACCEPT_RANGES;
        case 0x2e7bcf02u:
            return HDR_WWW_AUTHENTICATE;
        case 0xa17edaefu:
            return HDR_PROXY_AUTHENTICATE;
        case 0xc6da1376u:
            return HDR_RETRY_AFTER;
        case 0xa1937becu:
            return HDR_ACCESS_CONTROL_ALLOW_ORIGIN;
        case 0x81a75facu:
            return HDR_ACCESS_CONTROL_ALLOW_METHODS;
        case 0x5adb24c0u:
            return HDR_ACCESS_CONTROL_ALLOW_HEADERS;
        case 0x92055aa9u:
            return HDR_ACCESS_CONTROL_EXPOSE_HEADERS;
        case 0x9c6efbceu:
            return HDR_ACCESS_CONTROL_MAX_AGE;
        case 0x35b4ca8cu:
            return HDR_ACCESS_CONTROL_ALLOW_CREDENTIALS;
        case 0x9011af27u:
            return HDR_ACCESS_CONTROL_REQUEST_METHOD;
        case 0xd68cc290u:
            return HDR_ACCESS_CONTROL_REQUEST_HEADERS;
        case 0xf6a71e21u:
            return HDR_STRICT_TRANSPORT_SECURITY;
        case 0x5d85a5dcu:
            return HDR_CONTENT_SECURITY_POLICY;
        case 0xee0d1548u:
            return HDR_X_FRAME_OPTIONS;
        case 0xd93b89c9u:
            return HDR_X_CONTENT_TYPE_OPTIONS;
        case 0x95132148u:
            return HDR_X_XSS_PROTECTION;
        case 0xfd9c31dbu:
            return HDR_REFERRER_POLICY;
        case 0xadb2f988u:
            return HDR_X_FORWARDED_FOR;
        case 0x2eb2af39u:
            return HDR_X_FORWARDED_PROTO;
        case 0x28867067u:
            return HDR_X_FORWARDED_HOST;
        case 0xe37b3c60u:
            return HDR_X_REAL_IP;
        case 0x588604abu:
            return HDR_FORWARDED;
        case 0x69122c13u:
            return HDR_VIA;
        case 0x80154303u:
            return HDR_ALT_SVC;
        default:
            return HDR_CUSTOM;
    }
}

/**
 * @brief Initialize headers structure
 * @param h Headers structure to initialize
 * @param arena Memory arena for allocations
 */
static ARENA_INLINE void headers_init(headers_t* h, Arena* arena) {
    h->arena = arena;
    h->mask = 0;
    h->count = 0;
}

/**
 * @brief Set a header value (replaces existing or adds new)
 * @param h Headers structure
 * @param name Header name (case-insensitive)
 * @param value Header value
 * @return true on success, false if capacity exceeded
 *
 * Note: Set-Cookie allows multiple values; other headers are replaced
 */
static ARENA_INLINE bool headers_set(headers_t* h, const char* name, const char* value) {
    uint32_t name_hash;
    header_id_t id = resolve_static_id(name, &name_hash);

    // O(1) Check: If the bit is NOT set, we know it's a new header (except Set-Cookie)
    if (id != HDR_CUSTOM && id != HDR_SET_COOKIE && (h->mask & (1ULL << id))) {
        // Update existing via fast ID scan
        for (size_t i = 0; i < h->count; i++) {
            if (h->entries[i].id == id) {
                h->entries[i].value = arena_strdup(h->arena, value);
                return true;
            }
        }
    } else if (id == HDR_CUSTOM) {
        // Only scan custom headers if it's not a known static ID
        for (size_t i = 0; i < h->count; i++) {
            if (h->entries[i].id == HDR_CUSTOM && h->entries[i].hash == name_hash &&
                strcasecmp(h->entries[i].name, name) == 0) {
                h->entries[i].value = arena_strdup(h->arena, value);
                return true;
            }
        }
    }

    // Add New Path
    if (ARENA_UNLIKELY(h->count >= HEADERS_CAPACITY)) return false;

    header_entry* e = &h->entries[h->count++];
    e->hash = name_hash;
    e->id = (uint8_t)id;
    e->name = (id != HDR_CUSTOM) ? HEADER_NAMES[id] : arena_strdup(h->arena, name);
    e->value = arena_strdup(h->arena, value);

    // Set the presence bit
    if (id != HDR_CUSTOM) h->mask |= (1ULL << id);

    return true;
}

/**
 * @brief Get a static header value by ID (ultra-fast O(1) check)
 * @param h Headers structure
 * @param id Static header ID
 * @return Header value or NULL if not present
 */
static ARENA_INLINE const char* headers_get_static(const headers_t* h, header_id_t id) {
    if (ARENA_UNLIKELY(!(h->mask & (1ULL << id)))) return NULL;

    for (size_t i = 0; i < h->count; i++) {
        if (h->entries[i].id == id) return h->entries[i].value;
    }

    return NULL;
}

/**
 * @brief Get a header value by name (supports both static and custom headers)
 * @param h Headers structure
 * @param name Header name (case-insensitive)
 * @return Header value or NULL if not present
 */
static ARENA_INLINE const char* headers_get(const headers_t* h, const char* name) {
    uint32_t name_hash;
    header_id_t id = resolve_static_id(name, &name_hash);

    if (id != HDR_CUSTOM) {
        return headers_get_static(h, id);
    }

    // Custom header fallback
    for (size_t i = 0; i < h->count; i++) {
        if (h->entries[i].id == HDR_CUSTOM && h->entries[i].hash == name_hash &&
            strcasecmp(h->entries[i].name, name) == 0) {
            return h->entries[i].value;
        }
    }

    return NULL;
}

/**
 * @brief Check if a header exists
 * @param h Headers structure
 * @param name Header name (case-insensitive)
 * @return true if header exists, false otherwise
 */
static ARENA_INLINE bool headers_has(const headers_t* h, const char* name) {
    uint32_t name_hash;
    header_id_t id = resolve_static_id(name, &name_hash);

    if (id != HDR_CUSTOM) {
        return (h->mask & (1ULL << id)) != 0;
    }

    // Custom header check
    for (size_t i = 0; i < h->count; i++) {
        if (h->entries[i].id == HDR_CUSTOM && h->entries[i].hash == name_hash &&
            strcasecmp(h->entries[i].name, name) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Remove a header
 * @param h Headers structure
 * @param name Header name (case-insensitive)
 * @return true if header was removed, false if not found
 */
static ARENA_INLINE bool headers_remove(headers_t* h, const char* name) {
    uint32_t name_hash;
    header_id_t id = resolve_static_id(name, &name_hash);

    for (size_t i = 0; i < h->count; i++) {
        bool match = false;

        if (id != HDR_CUSTOM) {
            match = (h->entries[i].id == id);
        } else {
            match = (h->entries[i].id == HDR_CUSTOM && h->entries[i].hash == name_hash &&
                     strcasecmp(h->entries[i].name, name) == 0);
        }

        if (match) {
            // Clear bit if static header
            if (id != HDR_CUSTOM) {
                h->mask &= ~(1ULL << id);
            }

            // Shift remaining entries
            for (size_t j = i; j < h->count - 1; j++) {
                h->entries[j] = h->entries[j + 1];
            }
            h->count--;
            return true;
        }
    }

    return false;
}

/**
 * @brief Iterate over all headers
 * @param h Headers structure
 * @param callback Function called for each header (return false to stop iteration)
 * @param userdata User data passed to callback
 */
typedef bool (*header_iter_fn)(const char* name, const char* value, void* userdata);

static ARENA_INLINE void headers_foreach(const headers_t* h, header_iter_fn callback, void* userdata) {
    for (size_t i = 0; i < h->count; i++) {
        if (!callback(h->entries[i].name, h->entries[i].value, userdata)) {
            break;
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SOLIDC_HEADERS_H */
