#include "internal.h"
#include "mimetypes.h"
#include "../include/url.h"

#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

/* ================================================================
 * Range Request Helpers
 * ================================================================ */

#define MAX_RANGE_HDR 64

INLINE bool parse_range(StrSlice hdr, ssize_t* start, ssize_t* end, bool* has_end) {
    if (!ss_contains(hdr, SS_LIT("bytes="))) return false;
    if (hdr.len >= MAX_RANGE_HDR) return false;

    char buf[MAX_RANGE_HDR];
    memcpy(buf, hdr.data, hdr.len);
    buf[hdr.len] = '\0';
    if (sscanf(buf, "bytes=%ld-%ld", start, end) == 2) {
        *has_end = true;
        return true;
    }

    if (sscanf(buf, "bytes=%ld-", start) == 1) {
        *has_end = false;
        return true;
    }

    return false;
}

INLINE bool validate_range(bool has_end, ssize_t* start, ssize_t* end, off_t file_size) {
    if (!start || !end) return false;
    ssize_t sb = *start, eb = *end;
    ssize_t chunk = (4 * 1024 * 1024) - 1;

    if (!has_end && sb >= 0)
        eb = sb + chunk;
    else if (sb < 0) {
        sb = file_size + sb;
        eb = sb + chunk;
    } else if (eb < 0)
        eb = file_size + eb;

    if (eb >= file_size) eb = file_size - 1;
    if (sb < 0 || eb < 0 || sb >= file_size || sb > eb) return false;
    *start = sb;
    *end = eb;
    return true;
}

INLINE void send_range_headers(PulsarConn* conn, ssize_t start, ssize_t end, off_t file_size) {
    static const char hfmt[] =
        "Accept-Ranges: bytes\r\n"
        "Content-Length: %ld\r\n"
        "Content-Range: bytes %ld-%ld/%lld\r\n";
    response_t* resp = &conn->response;

    ensure_headers_capacity(resp, sizeof(hfmt) + 64);
    size_t n = (size_t)snprintf(resp->buf + resp->headers_len, sizeof(hfmt) + 64, hfmt,
                                end - start + 1, start, end, (long long)file_size);
    resp->headers_len += (uint32_t)n;
}

bool conn_servefile(PulsarConn* conn, const char* filename) {
    if (!filename) return false;
    /* Exact-route handlers may call this after the minimal header scan:
     * materialize Range (and the table) before reading range_hdr. */
    ensure_headers_parsed(conn);
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return false;
    }

    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        perror("fstat");
        sys_close_direct(fd);
        return false;
    }

    if (sb.st_size < 0 || (uint64_t)sb.st_size > UINT32_MAX) {
        fprintf(stderr, "file too large for 32-bit file_size\n");
        sys_close_direct(fd);
        return false;
    }

    char tbuf[64];
    struct tm tm_buf;
    if (gmtime_r(&sb.st_mtime, &tm_buf) != NULL) {
        strftime(tbuf, sizeof(tbuf), "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);
        conn_writeheader(conn, SS_LIT("Last-Modified"), ss_from_cstr(tbuf));
    }

    if (!HAS_CONTENT_TYPE(conn->response.flags)) {
        conn_set_content_type(conn, get_mimetype((char*)filename));
    }

    // By default, send the entire file.
    conn->response.file_fd = fd;
    conn->response.file_size = (uint32_t)sb.st_size;
    conn->response.file_offset = 0;
    conn->response.range_end = (uint32_t)sb.st_size;

    // Check for Range header cached in request.
    StrSlice range_hdr = conn->request.range_hdr;
    if (range_hdr.data == NULL) return true;

    ssize_t s = 0, e = 0;
    bool has_end;
    if (parse_range(range_hdr, &s, &e, &has_end)) {
        if (!validate_range(has_end, &s, &e, sb.st_size)) {
            sys_close_direct(fd);
            conn->response.file_fd = -1;
            conn_set_status(conn, StatusRequestedRangeNotSatisfiable);
            return true;
        }

        conn_set_status(conn, StatusPartialContent);
        send_range_headers(conn, s, e, sb.st_size);
        conn->response.file_offset = s;
        conn->response.range_end = (uint32_t)(e + 1);
        SET_RANGE_REQUEST(conn->response.flags);
    }
    return true;
}

/* ================================================================
 * Static File Handler
 * ================================================================ */

void static_file_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    route_t* route = conn->request.route;
    ASSERT(route->route_type == ROUTE_TYPE_STATIC);

    const char* path = conn->request.path;
    const char* dirname = route->state.static_.dirname;
    const char* pattern = route->pattern;
    size_t dirlen = route->state.static_.dirname_len;
    size_t pattern_len = route->pattern_len;

    if (is_malicious_path(path)) {
        conn_notfound(conn);
        return;
    }

    const char* static_ptr = path + pattern_len;
    if (strcmp(pattern, "/") != 0 && *static_ptr == '/') {
        static_ptr++;
    }
    size_t static_len = strlen(static_ptr);

    if (dirlen >= PATH_MAX || static_len >= PATH_MAX || dirlen + static_len + 2 >= PATH_MAX) {
        conn_set_status(conn, StatusRequestURITooLong);
        conn_set_content_type(conn, SS_LIT("text/html"));
        conn_write_string(conn, "<h1>Path too long</h1>");
        return;
    }

    char filepath[PATH_MAX];
    char decoded[PATH_MAX];
    char index_file[PATH_MAX];

    bool needs_slash = dirlen > 0 && dirname[dirlen - 1] != '/';
    int plen = snprintf(filepath, sizeof(filepath), "%.*s%s%.*s", (int)dirlen, dirname,
                        needs_slash ? "/" : "", (int)static_len, static_ptr);
    if (plen < 0 || plen >= (int)sizeof(filepath)) {
        conn_set_status(conn, StatusInternalServerError);
        return;
    }

    if (memchr(filepath, '%', (size_t)plen) || memchr(filepath, '+', (size_t)plen)) {
        url_percent_decode(filepath, decoded, (size_t)plen, sizeof(decoded));
        memcpy(filepath, decoded, (size_t)plen + 1);
    }

    bool use_index = false;
    const char* serve_file = filepath;

    if (!is_file(filepath)) {
        int ilen = snprintf(index_file, sizeof(index_file), "%s%sindex.html", filepath,
                            filepath[plen - 1] != '/' ? "/" : "");
        if (ilen < 0 || ilen >= (int)sizeof(index_file) || !is_file(index_file)) {
            conn_notfound(conn);
            return;
        }
        use_index = true;
        serve_file = index_file;
    }

    StrSlice content_type = use_index ? SS_LIT("text/html") : get_mimetype(filepath);
    conn_set_content_type(conn, content_type);

    if (!conn_servefile(conn, serve_file)) {
        conn_set_status(conn, StatusInternalServerError);
        conn_set_content_type(conn, SS_LIT("text/html"));
        conn_write_string(conn, "<h1>Error serving file</h1>");
    }
}
