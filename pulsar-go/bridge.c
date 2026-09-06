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

extern size_t global_route_count;

/**
 * Registered Go route bindings, in registration order.
 *
 * Parallel to g_registered_method. Entries are appended by
 * pulsar_bridge_add_route() and never removed or reordered; routes live for
 * the lifetime of the process.
 */
static const GoBinding* g_registered[MAX_ROUTES];

/** HTTP method for g_registered[i], parallel array. */
static HttpMethod g_registered_method[MAX_ROUTES];

/** Number of valid entries in g_registered / g_registered_method. */
static size_t g_registered_count = 0;

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
 * Allocates a GoBinding whose pattern is `pattern` with every Express-style
 * ":name" segment rewritten to "{name}", the form the C router expects.
 *
 * @param pattern Route pattern as supplied by Go, e.g. "/users/:id". Must
 *                start with '/' and be shorter than MAX_PATH_LEN.
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

    // First pass: compute the output length. Each ":name" becomes "{name}",
    // net +1 byte (the leading ':' is replaced by both '{' and '}').
    size_t extra = 0;
    for (size_t i = 0; i < in_len;) {
        int namelen = 0;
        if (pattern[i] == ':' && (i == 0 || pattern[i - 1] == '/') &&
            (namelen = param_name_len(pattern + i + 1, in_len - (i + 1))) > 0) {
            extra += 1;
            i += 1 + (size_t)namelen;
        } else {
            i++;
        }
    }

    GoBinding* b = malloc(sizeof(*b) + in_len + extra + 1);
    if (!b) {
        return NULL;
    }
    b->magic = GO_BINDING_MAGIC;
    b->go_id = go_id;

    // Second pass: rewrite into the freshly sized buffer.
    size_t o = 0;
    for (size_t i = 0; i < in_len;) {
        int namelen = 0;
        if (pattern[i] == ':' && (i == 0 || pattern[i - 1] == '/') &&
            (namelen = param_name_len(pattern + i + 1, in_len - (i + 1))) > 0) {
            b->pattern[o++] = '{';
            memcpy(b->pattern + o, pattern + i + 1, (size_t)namelen);
            o += (size_t)namelen;
            b->pattern[o++] = '}';
            i += 1 + (size_t)namelen;
        } else {
            b->pattern[o++] = pattern[i++];
        }
    }
    b->pattern[o] = '\0';
    return b;
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
 * @param pattern Route pattern using Express-style ":name" path parameters,
 *                e.g. "/users/:id". Normalized internally before being
 *                installed in the C router.
 * @param route_id Non-negative identifier the Go side uses to look up the
 *                 corresponding handler chain.
 * @return 0 on success. -1 if route_id is negative, method is invalid, the
 *         route table is full, pattern is malformed, or (method, pattern)
 *         is already registered.
 * @note Not safe for concurrent use; call only during single-threaded
 *       startup before Listen begins serving traffic.
 */
int pulsar_bridge_add_route(int method, const char* pattern, int route_id) {
    if (route_id < 0 || !METHOD_VALID(method)) {
        return -1;
    }
    if (g_registered_count >= MAX_ROUTES || global_route_count >= MAX_ROUTES) {
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
    if (!pattern || !dirname || global_route_count >= MAX_ROUTES) {
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
            *out_len = strlen(p->value);
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
    *val_len = p->value ? strlen(p->value) : 0;
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
    if (!conn || !conn->request.query_params || !name || name_len == 0) {
        return 0;
    }
    const headers_t* q = conn->request.query_params;
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
    if (!conn || !conn->request.headers || !name || name_len == 0) {
        return 0;
    }
    const headers_t* h = conn->request.headers;
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
    if (!conn || !conn->request.query_params) {
        return 0;
    }
    return conn->request.query_params->count;
}

/**
 * Retrieves the idx-th query parameter as request-scoped views.
 *
 * @return 1 on success, 0 when idx is out of range.
 */
int bridge_query_at(PulsarConn* conn, size_t idx, const char** name, size_t* name_len,
                    const char** val, size_t* val_len) {
    if (!conn || !conn->request.query_params || !name || !name_len || !val || !val_len) {
        return 0;
    }
    const headers_t* q = conn->request.query_params;
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
    if (!conn || !conn->request.headers) {
        return 0;
    }
    return conn->request.headers->count;
}

/**
 * Retrieves the idx-th request header as request-scoped views.
 *
 * @return 1 on success, 0 when idx is out of range.
 */
int bridge_req_header_at(PulsarConn* conn, size_t idx, const char** name, size_t* name_len,
                         const char** val, size_t* val_len) {
    if (!conn || !conn->request.headers || !name || !name_len || !val || !val_len) {
        return 0;
    }
    const headers_t* h = conn->request.headers;
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
    *out_len = strlen(route->pattern);
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
    if (conn->request.headers) {
        const headers_t* h = conn->request.headers;
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
    *name_len = strlen(f->name);
    *val = f->value;
    *val_len = strlen(f->value);
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
    if (field_len) *field_len = fh->field_name ? strlen(fh->field_name) : 0;
    if (filename) *filename = fh->filename;
    if (filename_len) *filename_len = fh->filename ? strlen(fh->filename) : 0;
    if (mimetype) *mimetype = fh->mimetype;
    if (mimetype_len) *mimetype_len = fh->mimetype ? strlen(fh->mimetype) : 0;
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
