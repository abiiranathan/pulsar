#include "bridge.h"

#include <ctype.h>   // for isalnum
#include <stddef.h>  // for offsetof, size_t
#include <stdint.h>  // for uint32_t
#include <stdlib.h>  // for malloc, free, strdup
#include <string.h>  // for strlen, strcmp, memcpy, memcmp

#include "../include/headers.h"
#include "../include/pulsar.h"
#include "../include/routing.h"

/** Magic value tagging a route_t::pattern as owned by a GoBinding, so the
 *  trampoline can recover the enclosing struct safely instead of assuming
 *  every matched route was registered from Go. */
#define GO_BINDING_MAGIC 0x47424E44u /* 'GBND' */

/**
 * Out-of-line storage for a Go-registered route's pattern, alongside the
 * route ID used to dispatch back into Go.
 *
 * A GoBinding is allocated once per pulsar_bridge_add_route() call and
 * lives for the lifetime of the process; routes are never unregistered.
 * `pattern` is the normalized form actually installed in the C router
 * (Express-style ":name" rewritten to "{name}"), NUL-terminated and stored
 * inline (flexible array member) so the whole binding is one allocation.
 */
typedef struct {
    uint32_t magic; /**< Always GO_BINDING_MAGIC; guards GO_BINDING_FROM_PATTERN casts. */
    int go_id;      /**< Route ID passed to goPulsarDispatcher on a match. */
    char pattern[]; /**< NUL-terminated normalized pattern. */
} GoBinding;

/** Recovers the enclosing GoBinding from a `route_t::pattern` pointer that
 *  is known to point at a GoBinding's flexible array member. Callers must
 *  check the recovered magic before trusting the result, since a
 *  route_t::pattern may originate from route_static() or elsewhere instead. */
#define GO_BINDING_FROM_PATTERN(p) \
    ((const GoBinding*)((const char*)(p) - offsetof(GoBinding, pattern)))

/**
 * Registered Go route bindings, in registration order.
 *
 * Parallel to g_registered_method. Entries are appended by
 * pulsar_bridge_add_route() and never removed or reordered; routes live for
 * the lifetime of the process.
 *
 * The C router (routing.c) now grows its global route list dynamically, so
 * the bridge mirrors that: these arrays grow via realloc instead of the old
 * fixed MAX_ROUTES cap.
 */
static const GoBinding** g_registered = NULL;

/** HTTP method for g_registered[i], parallel array. */
static HttpMethod* g_registered_method = NULL;

/** Number of valid entries in g_registered / g_registered_method. */
static size_t g_registered_count = 0;

/** Capacity of g_registered / g_registered_method. */
static size_t g_registered_capacity = 0;

/**
 * Returns the length of a path-parameter name starting at s, i.e. the run
 * of alphanumeric/underscore characters before the next '/' or end of
 * string. Does not read past `remaining` bytes.
 *
 * @param s Start of the candidate parameter name (just after ':').
 * @param remaining Number of bytes available at s.
 * @return Length of the parameter name, possibly 0 if s does not start
 *         with a valid name character.
 */
static int param_name_len(const char* s, size_t remaining) {
    size_t j = 0;
    while (j < remaining && (isalnum((unsigned char)s[j]) || s[j] == '_')) {
        j++;
    }
    return (int)j;
}

/**
 * Allocates a GoBinding whose pattern is `pattern` normalized to the
 * "{name}" form the C router expects.
 *
 * Both styles are accepted and equivalent:
 *   - Express-style ":name" segments (at a segment start) become "{name}".
 *   - "{name}" segments pass through unchanged.
 *
 * Regex-style constraints are NOT enforced by the C router, so they are
 * stripped for parity with the Go-side test matcher (WithPattern), which
 * ignores them as well: ":id(\d+)" and "{id:[0-9]+}" both register "{id}"
 * (plain wildcard). Previously ":id(...)" emitted "{id}(...)" with literal
 * trailing parens that could never match, and "{id:...}" registered under
 * the literal name "id:..." so Param("id") missed.
 *
 * Malformed patterns are rejected (NULL): unclosed "{" or stray "}",
 * nested "{{", empty names ("{}" or bare ":"), or an unterminated "(...)"
 * constraint. Note classify_route() only ASSERTs validity, which is a
 * no-op in NDEBUG builds, so validation must happen here.
 *
 * @param pattern Route pattern as supplied by Go, e.g. "/users/:id" or
 *                "/users/{id}". Must start with '/' and be shorter than
 *                MAX_PATH_LEN. The Go layer strips trailing slashes first,
 *                so "/users/" and "/users" register identically.
 * @param go_id Route ID to store in the binding for later dispatch.
 * @return Newly allocated GoBinding on success, or NULL if pattern is
 *         invalid or allocation fails. Caller owns the result and must
 *         free() it (only on the registration-failure path; on success it
 *         is kept alive for the life of the process by g_registered).
 */
static GoBinding* binding_new(const char* pattern, int go_id) {
    if (!pattern || pattern[0] != '/') {
        return NULL;
    }

    size_t in_len = strlen(pattern);
    if (in_len == 0 || in_len >= MAX_PATH_LEN) {
        return NULL;
    }

    // Output never exceeds in_len + nparams + 1: each ":name" gains exactly
    // one byte ("{name}"), while "{name}" passes through and constraints
    // only shrink the output. One allocation sized for the worst case.
    GoBinding* b = malloc(sizeof(*b) + in_len + in_len + 1);
    if (!b) {
        return NULL;
    }
    b->magic = GO_BINDING_MAGIC;
    b->go_id = go_id;

    size_t o = 0;
    for (size_t i = 0; i < in_len;) {
        char ch = pattern[i];

        // Brace style: "{name}" or "{name:constraint}". The C router
        // accepts any "}"-free name here, so only emptiness is rejected
        // (":" style below is stricter: its name must be scannable).
        if (ch == '{') {
            size_t j = i + 1;
            while (j < in_len && pattern[j] != '}' && pattern[j] != '{' && pattern[j] != ':') {
                j++;
            }
            if (j >= in_len || pattern[j] == '{') {
                goto invalid;  // Unclosed "{" or nested "{{".
            }
            size_t namelen = j - (i + 1);
            if (namelen == 0) {
                goto invalid;  // Empty "{}".
            }
            if (pattern[j] == ':') {
                // Skip the constraint up to the closing brace.
                size_t k = j + 1;
                while (k < in_len && pattern[k] != '}') {
                    if (pattern[k] == '{') {
                        goto invalid;  // Nested "{" inside constraint.
                    }
                    k++;
                }

                if (k >= in_len) {
                    goto invalid;  // Unterminated constraint.
                }
                j = k;
            }
            // j now points at the closing "}".
            b->pattern[o++] = '{';
            memcpy(b->pattern + o, pattern + i + 1, namelen);
            o += namelen;
            b->pattern[o++] = '}';
            i = j + 1;
        } else if (ch == '}') {
            goto invalid;  // Stray "}" outside braces.
        } else if (ch == ':' && (i == 0 || pattern[i - 1] == '/')) {
            int namelen = param_name_len(pattern + i + 1, in_len - (i + 1));
            if (namelen <= 0) {
                goto invalid;  // Bare ":" with no parameter name.
            }
            size_t k = i + 1 + (size_t)namelen;
            if (k < in_len && pattern[k] == '(') {
                // Skip a balanced "(...)" constraint (not enforceable).
                int depth = 0;
                do {
                    if (pattern[k] == '(')
                        depth++;
                    else if (pattern[k] == ')')
                        depth--;
                    k++;
                } while (k < in_len && depth > 0);
                if (depth != 0) {
                    goto invalid;  // Unterminated constraint.
                }
            }
            b->pattern[o++] = '{';
            memcpy(b->pattern + o, pattern + i + 1, (size_t)namelen);
            o += (size_t)namelen;
            b->pattern[o++] = '}';
            i = k;
        } else {
            // Literal byte, including mid-segment ":" (e.g. "/files/a:b").
            b->pattern[o++] = pattern[i++];
        }
    }
    b->pattern[o] = '\0';
    return b;

invalid:
    free(b);
    return NULL;
}

/**
 * C-router entry point for every route registered from Go. Recovers the
 * originating GoBinding from the matched route's pattern pointer and
 * dispatches into Go via goPulsarDispatcher(); falls back to a 404 if the
 * match does not carry a recognizable Go binding (defensive: should not
 * happen for routes this bridge registered itself).
 *
 * @param ctx Request context supplied by the C router for the matched
 *            connection.
 */
void pulsar_c_trampoline(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    route_t* matched = conn->request.route;

    if (matched && matched->pattern) {
        const GoBinding* b = GO_BINDING_FROM_PATTERN(matched->pattern);
        if (b->magic == GO_BINDING_MAGIC && b->go_id >= 0) {
            goPulsarDispatcher(conn, b->go_id);
            return;
        }
    }

    conn_notfound(conn);
}

/**
 * Registers a Go-backed route for method and pattern, dispatching matches
 * to route_id via the trampoline.
 *
 * @param method One of the HTTP_* constants from method.h.
 * @param pattern Route pattern with ":name" (Express-style) and/or
 *                "{name}" path parameters, e.g. "/users/:id". Both styles
 *                are equivalent and normalized to "{name}" before being
 *                installed in the C router. Regex-style constraints
 *                (":id(...)" / "{id:...}") are accepted but not enforced:
 *                they register as plain wildcards, matching the Go-side
 *                test matcher. Malformed patterns (unclosed/stray/nested
 *                braces, bare ":", unterminated constraints) are rejected.
 *                The duplicate check compares normalized patterns, so ":id"
 *                and "{id}" collide as they should; it covers Go routes
 *                only — a Go route shadowing a static prefix is resolved by
 *                the C router's sort order.
 * @param route_id Non-negative identifier the Go side uses to look up the
 *                 corresponding handler chain.
 * @return 0 on success. -1 if route_id is negative, method is invalid,
 *         pattern is malformed, (method, pattern) is already registered,
 *         or allocation fails.
 * @note Not safe for concurrent use; call only during single-threaded
 *       startup before Listen begins serving traffic.
 */
int pulsar_bridge_add_route(int method, const char* pattern, int route_id) {
    if (route_id < 0 || !METHOD_VALID(method)) {
        return -1;
    }

    GoBinding* b = binding_new(pattern, route_id);
    if (!b) {
        return -1;
    }

    for (size_t i = 0; i < g_registered_count; i++) {
        if (g_registered_method[i] == (HttpMethod)method &&
            strcmp(g_registered[i]->pattern, b->pattern) == 0) {
            free(b);
            return -1;
        }
    }

    route_t* r = route_register(b->pattern, (HttpMethod)method, pulsar_c_trampoline);
    if (!r) {
        free(b);
        return -1;
    }

    if (g_registered_count >= g_registered_capacity) {
        size_t new_cap = g_registered_capacity == 0 ? 64 : g_registered_capacity * 2;
        const GoBinding** new_regs =
            (const GoBinding**)realloc(g_registered, new_cap * sizeof(*new_regs));
        if (!new_regs) {
            free(b);
            return -1;
        }
        HttpMethod* new_methods =
            (HttpMethod*)realloc(g_registered_method, new_cap * sizeof(*new_methods));
        if (!new_methods) {
            free((void*)new_regs);
            free(b);
            return -1;
        }
        g_registered = new_regs;
        g_registered_method = new_methods;
        g_registered_capacity = new_cap;
    }

    g_registered[g_registered_count] = b;
    g_registered_method[g_registered_count] = (HttpMethod)method;
    g_registered_count++;
    return 0;
}

/**
 * Registers a static file route serving `dirname` under URL prefix
 * `pattern`, handled entirely by the C router via static_file_handler
 * (e.g. sendfile(2)); no Go handler chain is invoked for matches.
 *
 * @param pattern URL prefix to serve the directory under, e.g. "/assets".
 * @param dirname Path to an existing directory on disk. route_static()
 *                stores this pointer as-is rather than copying it, so the
 *                string passed to the underlying route_t must remain valid
 *                for the life of the process; a heap copy is made here for
 *                that reason and deliberately never freed.
 * @return 0 on success. -1 if pattern or dirname is NULL, the route table
 *         is full, dirname is not an existing directory, or registration
 *         otherwise fails.
 * @note Not safe for concurrent use; call only during single-threaded
 *       startup before Listen begins serving traffic.
 */
int pulsar_bridge_add_static(const char* pattern, const char* dirname) {
    if (!pattern || !dirname) {
        return -1;
    }

    // route_static() keeps dirname's pointer for the life of the route, so
    // its backing storage must outlive this call: duplicate it onto the
    // heap and intentionally leave it allocated. pattern, by contrast, is
    // only read during route_register_helper() and does not need to
    // outlive this function, so it is passed through directly.
    char* dir = strdup(dirname);
    if (!dir) {
        return -1;
    }

    route_t* r = route_static(pattern, dir);
    if (!r) {
        free(dir);
        return -1;
    }
    return 0;
}

/**
 * Reports whether a connection's request has been aborted (e.g. via
 * Context.Abort on the Go side).
 *
 * @param conn Connection to check. NULL is treated as not aborted.
 * @return 1 if aborted, 0 otherwise.
 * @note Safe for concurrent use: performs a single read of conn->abort.
 */
int bridge_is_aborted(PulsarConn* conn) { return (conn && conn->abort) ? 1 : 0; }

/**
 * Installs the process-wide request logger, writing to file descriptor fd.
 *
 * @param fd Open, writable file descriptor. Ownership is not transferred:
 *           the caller remains responsible for eventually closing it.
 * @return 0 on success. -1 if fd is negative or a logger callback is
 *         already installed.
 * @note Not safe for concurrent use; call only once during startup.
 */
int pulsar_bridge_set_logger(int fd) {
    if (fd < 0) {
        return -1;
    }
    if (!pulsar_set_callback(pulsar_logger, fd)) {
        return -1;
    }
    return 0;
}

/**
 * Looks up a single path parameter by name for the connection's matched
 * route.
 *
 * @param conn Connection whose matched route's parameters are searched.
 * @param name Parameter name to look up (not NUL-terminated; length given
 *             by name_len).
 * @param name_len Length of name in bytes.
 * @param[out] out_data Set to a pointer into the route's parameter storage
 *                       on success; left unmodified on failure. Valid only
 *                       for the lifetime of the current request.
 * @param[out] out_len Set to the length of the parameter value on success;
 *                      left unmodified on failure.
 * @return 1 if found, 0 if conn/name is invalid, the matched route takes no
 *         path parameters, or no parameter named `name` is present.
 * @note Safe for concurrent use across distinct connections; not
 *       re-entrant for the same conn from multiple threads.
 */
int bridge_get_path_param(PulsarConn* conn, const char* name, size_t name_len,
                          const char** out_data, size_t* out_len) {
    if (!conn || !name || name_len == 0) {
        return 0;
    }
    route_t* route = conn->request.route;
    if (!route || route->route_type != ROUTE_TYPE_PARAM) {
        return 0;
    }

    PathParams* pp = route->state.path_params;
    if (!pp || !pp->items) {
        return 0;
    }
    for (size_t i = 0; i < pp->match_count; i++) {
        const PathParam* p = &pp->items[i];
        if (p->name_len == name_len && p->name && p->value &&
            memcmp(p->name, name, name_len) == 0) {
            *out_data = p->value;
            *out_len = p->value_len;
            return 1;
        }
    }
    return 0;
}

/**
 * Returns the number of path parameters matched for the connection's
 * current route.
 *
 * @param conn Connection to inspect. NULL yields 0.
 * @return Number of matched path parameters, or 0 if the route takes none.
 * @note Safe for concurrent use across distinct connections.
 */
size_t bridge_get_path_params_count(PulsarConn* conn) {
    if (!conn) {
        return 0;
    }
    route_t* route = conn->request.route;
    if (route && route->route_type == ROUTE_TYPE_PARAM && route->state.path_params) {
        return route->state.path_params->match_count;
    }
    return 0;
}

/**
 * Retrieves the path parameter at index idx for the connection's matched
 * route, for iterating all parameters without knowing their names in
 * advance.
 *
 * @param conn Connection whose matched route's parameters are read.
 * @param idx Zero-based index, must be < bridge_get_path_params_count(conn).
 * @param[out] name Set to the parameter's name pointer, or NULL if idx is
 *                   out of range or conn has no matched parameters.
 * @param[out] name_len Set to the parameter name's length, or 0 on failure.
 * @param[out] val Set to the parameter's value pointer, or NULL on failure.
 * @param[out] val_len Set to the parameter value's length, or 0 on failure.
 * @note All four out-parameters are always written, even on failure, so
 *       callers may skip checking a separate return code. Safe for
 *       concurrent use across distinct connections.
 */
void bridge_get_path_param_at(PulsarConn* conn, size_t idx, const char** name, size_t* name_len,
                              const char** val, size_t* val_len) {
    if (name) *name = NULL;
    if (name_len) *name_len = 0;
    if (val) *val = NULL;
    if (val_len) *val_len = 0;
    if (!conn || !name || !name_len || !val || !val_len) {
        return;
    }

    route_t* route = conn->request.route;
    if (!route || route->route_type != ROUTE_TYPE_PARAM) {
        return;
    }
    PathParams* pp = route->state.path_params;
    if (!pp || !pp->items || idx >= pp->match_count) {
        return;
    }

    const PathParam* p = &pp->items[idx];
    *name = p->name;
    *name_len = p->name_len;
    *val = p->value;
    *val_len = p->value ? p->value_len : 0;
}

/**
 * Looks up a query-string parameter by name, case-insensitively.
 *
 * @param conn Connection whose parsed query parameters are searched.
 * @param name Parameter name to look up (not NUL-terminated; length given
 *             by name_len).
 * @param name_len Length of name in bytes.
 * @param[out] out_data Set to a pointer into the connection's query-string
 *                       storage on success; valid only for the lifetime of
 *                       the current request.
 * @param[out] out_len Set to the length of the parameter value on success.
 * @return 1 if found, 0 if conn/name is invalid, the request has no query
 *         parameters, or none is named `name`.
 * @note Safe for concurrent use across distinct connections.
 */
int bridge_query_get(PulsarConn* conn, const char* name, size_t name_len, const char** out_data,
                     size_t* out_len) {
    if (!conn || !name || name_len == 0 || !out_data || !out_len) {
        return 0;
    }
    /* request.query_params is now an inline struct (not a pointer); Go
     * strings are not NUL-terminated, so scan with the explicit length
     * instead of query_get() (which needs a C string and arena-copies). */
    const headers_t* q = &conn->request.query_params;
    StrSlice target = {.data = (char*)name, .len = name_len};
    for (size_t i = 0; i < q->count; ++i) {
        if (ss_equal_nocase(q->entries[i].name, target)) {
            *out_data = q->entries[i].value.data;
            *out_len = q->entries[i].value.len;
            return 1;
        }
    }
    return 0;
}

/**
 * Looks up a request header by name, case-insensitively.
 *
 * @param conn Connection whose request headers are searched.
 * @param name Header name to look up (not NUL-terminated; length given by
 *             name_len).
 * @param name_len Length of name in bytes.
 * @param[out] out_data Set to a pointer into the connection's header
 *                       storage on success; valid only for the lifetime of
 *                       the current request.
 * @param[out] out_len Set to the length of the header value on success.
 * @return 1 if found, 0 if conn/name is invalid, the request has no
 *         headers, or none is named `name`.
 * @note Safe for concurrent use across distinct connections.
 */
int bridge_req_header_get(PulsarConn* conn, const char* name, size_t name_len,
                          const char** out_data, size_t* out_len) {
    if (!conn || !name || name_len == 0 || !out_data || !out_len) {
        return 0;
    }
    /* Same as above: inline struct + non-NUL-terminated Go name. */
    const headers_t* h = &conn->request.headers;
    StrSlice target = {.data = (char*)name, .len = name_len};
    for (size_t i = 0; i < h->count; ++i) {
        if (ss_equal_nocase(h->entries[i].name, target)) {
            *out_data = h->entries[i].value.data;
            *out_len = h->entries[i].value.len;
            return 1;
        }
    }
    return 0;
}

/**
 * Returns the number of parsed query-string parameters for the connection.
 *
 * @param conn Connection to inspect. NULL yields 0.
 * @return Query parameter count (0 when the URL carries no query string).
 */
size_t bridge_query_count(PulsarConn* conn) {
    if (!conn) {
        return 0;
    }
    return conn->request.query_params.count;
}

/**
 * Retrieves the idx-th query parameter as request-scoped views.
 *
 * @return 1 on success, 0 when idx is out of range.
 */
int bridge_query_at(PulsarConn* conn, size_t idx, const char** name, size_t* name_len,
                    const char** val, size_t* val_len) {
    if (!conn || !name || !name_len || !val || !val_len) {
        return 0;
    }
    const headers_t* q = &conn->request.query_params;
    if (idx >= q->count) {
        return 0;
    }

    *name = q->entries[idx].name.data;
    *name_len = q->entries[idx].name.len;
    *val = q->entries[idx].value.data;
    *val_len = q->entries[idx].value.len;
    return 1;
}

/**
 * Returns the number of request headers.
 */
size_t bridge_req_headers_count(PulsarConn* conn) {
    if (!conn) {
        return 0;
    }
    return conn->request.headers.count;
}

/**
 * Retrieves the idx-th request header as request-scoped views.
 *
 * @return 1 on success, 0 when idx is out of range.
 */
int bridge_req_header_at(PulsarConn* conn, size_t idx, const char** name, size_t* name_len,
                         const char** val, size_t* val_len) {
    if (!conn || !name || !name_len || !val || !val_len) {
        return 0;
    }
    const headers_t* h = &conn->request.headers;
    if (idx >= h->count) {
        return 0;
    }
    *name = h->entries[idx].name.data;
    *name_len = h->entries[idx].name.len;
    *val = h->entries[idx].value.data;
    *val_len = h->entries[idx].value.len;
    return 1;
}

/**
 * Returns the matched route's pattern as a request-scoped view.
 *
 * @return 1 on success, 0 when the connection has no matched route.
 */
int bridge_route_pattern(PulsarConn* conn, const char** out_data, size_t* out_len) {
    if (!conn || !out_data || !out_len) {
        return 0;
    }
    route_t* route = conn->request.route;
    if (!route || !route->pattern) {
        return 0;
    }
    *out_data = route->pattern;
    *out_len = route->pattern_len;
    return 1;
}

/**
 * Returns the request's Content-Length (0 when there is no body).
 */
size_t bridge_content_length(PulsarConn* conn) {
    if (!conn) {
        return 0;
    }
    return conn->request.content_length;
}

/**
 * Packs scalar request metadata and collection counts in one call.
 *
 * Method and path are NUL-terminated interior pointers; their lengths are
 * measured once here so the caller can use length-bounded copies instead of
 * paying strlen again. Route pattern uses the stored pattern_len (never
 * re-scanned). Body is a direct view into the receive buffer. Counts let
 * the caller size enumeration loops without extra count calls.
 *
 * Returns 1 on success, 0 when conn/out is NULL.
 */
int bridge_req_snapshot(PulsarConn* conn, BridgeReqSnapshot* out) {
    if (!conn || !out) {
        return 0;
    }
    const char* method = conn->request.method;
    const char* path = conn->request.path;
    out->method = method;
    out->method_len = method ? strlen(method) : 0;
    out->path = path;
    out->path_len = path ? strlen(path) : 0;

    route_t* route = conn->request.route;
    if (route && route->pattern) {
        out->route_pattern = route->pattern;
        out->route_pattern_len = route->pattern_len;
    } else {
        out->route_pattern = NULL;
        out->route_pattern_len = 0;
    }

    out->body = conn->request.body;
    out->body_len = conn->request.body ? conn->request.content_length : 0;
    out->content_length = conn->request.content_length;

    out->nparams = bridge_get_path_params_count(conn);
    out->nquery = bridge_query_count(conn);
    out->nheaders = bridge_req_headers_count(conn);
    return 1;
}

/**
 * Appends a pre-formatted header block and optionally marks Content-Type.
 */
void bridge_commit_headers(PulsarConn* conn, const char* data, size_t len, int content_type_set) {
    if (!conn) {
        return;
    }
    if (data && len > 0) {
        conn_writeheader_raw(conn, data, len);
    }
    if (content_type_set) {
        SET_CONTENT_TYPE(conn->response.flags);
    }
}

/**
 * Parses the current request as multipart/form-data (RFC 7578).
 *
 * The request's Content-Type header supplies the boundary; the request
 * body supplies the payload. Field names/values and file metadata are
 * copied into a private arena owned by the returned form, while file
 * payloads stay in place as offset/size windows into the request body
 * (see bridge_form_file_at()) — no file bytes are copied here.
 */
int bridge_parse_multipart(PulsarConn* conn, MultipartForm** out_form, int* out_code,
                           const char** out_msg) {
    if (out_form) *out_form = NULL;
    if (out_code) *out_code = (int)INVALID_FORM_BOUNDARY;
    if (out_msg) *out_msg = multipart_error(INVALID_FORM_BOUNDARY);
    if (!conn || !out_form) {
        return -1;
    }

    /* Content-Type is stored as a non-NUL-terminated slice; make a
     * NUL-terminated stack copy for parse_boundary(). */
    StrSlice ct = {.data = NULL, .len = 0};
    {
        const headers_t* h = &conn->request.headers;
        StrSlice target = {.data = "Content-Type", .len = 12};
        for (size_t i = 0; i < h->count; ++i) {
            if (ss_equal_nocase(h->entries[i].name, target)) {
                ct = h->entries[i].value;
                break;
            }
        }
    }
    if (!ct.data || ct.len == 0 || ct.len >= 512) {
        return -1;
    }
    char ct_buf[512];
    memcpy(ct_buf, ct.data, ct.len);
    ct_buf[ct.len] = '\0';

    char boundary[256];
    if (!parse_boundary(ct_buf, boundary, sizeof(boundary))) {
        return -1;
    }

    if (!conn->request.body || conn->request.content_length == 0) {
        return -1;
    }

    MultipartForm* form = (MultipartForm*)malloc(sizeof(*form));
    if (!form) {
        if (out_code) *out_code = (int)MEMORY_ALLOC_ERROR;
        if (out_msg) *out_msg = multipart_error(MEMORY_ALLOC_ERROR);
        return -1;
    }

    MultipartCode mc = multipart_init(form);
    if (mc != MULTIPART_OK) {
        if (out_code) *out_code = (int)mc;
        if (out_msg) *out_msg = multipart_error(mc);
        free(form);
        return -1;
    }

    mc = multipart_parse(conn->request.body, conn->request.content_length, boundary, form);
    if (mc != MULTIPART_OK) {
        /* multipart_parse() already ran multipart_cleanup() on failure,
         * which destroyed the arena; only the struct itself is left. */
        if (out_code) *out_code = (int)mc;
        if (out_msg) *out_msg = multipart_error(mc);
        free(form);
        return -1;
    }

    *out_form = form;
    if (out_code) *out_code = (int)MULTIPART_OK;
    if (out_msg) *out_msg = multipart_error(MULTIPART_OK);
    return 0;
}

size_t bridge_form_num_fields(MultipartForm* form) { return form ? form->num_fields : 0; }

size_t bridge_form_num_files(MultipartForm* form) { return form ? form->num_files : 0; }

/**
 * Retrieves the idx-th regular form field. Name/value point into the
 * form's arena (NUL-terminated) and stay valid until
 * bridge_free_multipart().
 */
int bridge_form_field_at(MultipartForm* form, size_t idx, const char** name, size_t* name_len,
                         const char** val, size_t* val_len) {
    if (!form || !name || !name_len || !val || !val_len || idx >= form->num_fields) {
        return 0;
    }
    const FormField* f = &form->fields[idx];
    if (!f->name || !f->value) {
        return 0;
    }
    *name = f->name;
    *name_len = f->name_len;
    *val = f->value;
    *val_len = f->value_len;
    return 1;
}

/**
 * Retrieves the idx-th uploaded file's metadata. String outputs point
 * into the form's arena; offset/size describe a window into the request
 * body (body[offset:offset+size]) that is NOT copied.
 */
int bridge_form_file_at(MultipartForm* form, size_t idx, const char** field, size_t* field_len,
                        const char** filename, size_t* filename_len, const char** mimetype,
                        size_t* mimetype_len, size_t* offset, size_t* size) {
    if (!form || idx >= form->num_files) {
        return 0;
    }
    const FileHeader* fh = form->files[idx];
    if (!fh) {
        return 0;
    }
    if (field) *field = fh->field_name;
    if (field_len) *field_len = fh->field_name ? fh->field_name_len : 0;
    if (filename) *filename = fh->filename;
    if (filename_len) *filename_len = fh->filename ? fh->filename_len : 0;
    if (mimetype) *mimetype = fh->mimetype;
    if (mimetype_len) *mimetype_len = fh->mimetype ? fh->mimetype_len : 0;
    if (offset) *offset = fh->offset;
    if (size) *size = fh->size;
    return 1;
}

/**
 * Releases a form obtained from bridge_parse_multipart(), destroying its
 * arena and freeing the struct. File payload views (windows into the
 * request body) are unaffected; field/file metadata views die here.
 */
void bridge_free_multipart(MultipartForm* form) {
    if (!form) {
        return;
    }
    multipart_cleanup(form);
    free(form);
}

const char* bridge_multipart_error(int code) { return multipart_error((MultipartCode)code); }
