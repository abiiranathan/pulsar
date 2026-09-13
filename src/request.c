#include "internal.h"

/* ================================================================
 * Request Accessors
 * ================================================================ */

char* req_body(PulsarConn* conn) { return conn->request.body; }

StrSlice req_body_slice(PulsarConn* conn) {
    return (StrSlice){
        .data = conn->request.body,
        .len = conn->request.content_length,
    };
}

const char* req_method(PulsarConn* conn) { return conn->request.method; }
const char* req_path(PulsarConn* conn) { return conn->request.path; }

const char* query_get(PulsarConn* conn, const char* name) {
    StrSlice h = headers_get(&conn->request.query_params, name);
    const char* dup = arena_strdupn(conn->arena, h.data, h.len);
    return dup;
}

headers_t* query_params(PulsarConn* conn) { return &conn->request.query_params; }

const headers_t* req_headers(PulsarConn* conn) {
    ensure_headers_parsed(conn);
    return (const headers_t*)(&conn->request.headers);
}

const char* req_header_get(PulsarConn* conn, const char* name) {
    ensure_headers_parsed(conn);
    StrSlice h = headers_get(&conn->request.headers, name);
    const char* dup = arena_strdupn(conn->arena, h.data, h.len);
    return dup;
}

/* Materialize the full header table + Content-Length + Range on first header
 * access for requests that took the minimal scan. Runs at most once per
 * request (headers_parsed flag); cold path — handler is already running, so
 * best-effort: a capacity overflow here only truncates the table, it cannot
 * fail the in-flight request. */
void ensure_headers_parsed(PulsarConn* conn) {
    request_t* req = &conn->request;
    if (likely(req->headers_parsed)) return;

    req->headers_parsed = true;
    if (req->hdr_len_raw == 0 || !req->hdr_data) return;

    headers_init(&req->headers);
    /* Recomputes keep_alive/Content-Length/Range identically to the eager
     * path; return status is best-effort (see above). */
    (void)parse_request_headers(conn, req->hdr_data, req->method_type, req->hdr_len_raw);
}

/* ================================================================
 * Path Parameters & Request Metadata
 * ================================================================ */

const char* get_path_param(PulsarConn* conn, const char* name) {
    if (!conn || !name) return NULL;

    route_t* route = conn->request.route;
    if (route && route->route_type == ROUTE_TYPE_PARAM) {
        PathParams* pp = route->state.path_params;
        if (!pp) return NULL;
        const size_t name_len = strlen(name);
        for (size_t i = 0; i < pp->match_count; i++) {
            const PathParam* p = &pp->items[i];
            if (p->name_len == name_len && memcmp(p->name, name, name_len) == 0) return p->value;
        }
    }
    return NULL;
}

Request conn_get_request_metadata(PulsarConn* conn) {
    return (Request){
        .path = conn->request.path,
        .method = conn->request.method,
        .body = (StrSlice){.data = conn->request.body, .len = conn->request.content_length},
        .route_pattern = conn->request.route->pattern,
    };
}
