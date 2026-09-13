#include "internal.h"
#include "mimetypes.h"

/* ================================================================
 * Response Status & Header Readers
 * ================================================================ */

void conn_set_status(PulsarConn* restrict conn, http_status code) {
    conn->response.status_code = (uint16_t)code;
}

http_status res_get_status(PulsarConn* conn) { return (http_status)conn->response.status_code; }

char* res_header_get(PulsarConn* conn, const char* name) {
    response_t* res = &conn->response;
    char* buf = res->buf;
    char saved = buf[res->headers_len];
    buf[res->headers_len] = '\0';

    char* ptr = strstr(buf, name);
    if (!ptr) {
        buf[res->headers_len] = saved;
        return NULL;
    }
    ptr += strlen(name) + 2;

    char* end = strstr(ptr, "\r\n");
    if (!end) {
        buf[res->headers_len] = saved;
        return NULL;
    }

    size_t vlen = (size_t)(end - ptr);
    char* result = malloc(vlen + 1);
    if (!result) {
        buf[res->headers_len] = saved;
        return NULL;
    }
    memcpy(result, ptr, vlen);
    result[vlen] = '\0';
    buf[res->headers_len] = saved;
    return result;
}

bool res_header_get_buf(PulsarConn* conn, const char* __restrict__ name, char* __restrict__ dest,
                        size_t dest_size) {
    response_t* res = &conn->response;
    char* buf = res->buf;
    char saved = buf[res->headers_len];
    buf[res->headers_len] = '\0';

    char* ptr = strstr(buf, name);
    if (!ptr) {
        buf[res->headers_len] = saved;
        return false;
    }
    ptr += strlen(name) + 2;

    char* end = strstr(ptr, "\r\n");
    if (!end) {
        buf[res->headers_len] = saved;
        return false;
    }

    size_t vlen = (size_t)(end - ptr);
    if (dest_size <= vlen) {
        buf[res->headers_len] = saved;
        return false;
    }
    memcpy(dest, ptr, vlen);
    dest[vlen] = '\0';
    buf[res->headers_len] = saved;
    return true;
}

/* ================================================================
 * Response Header Writers (Directly into res->buf)
 * ================================================================ */

void conn_writeheader(PulsarConn* conn, StrSlice name, StrSlice value) {
    response_t* resp = &conn->response;
    size_t required = name.len + value.len + 4;
    ensure_headers_capacity(resp, required);

    char* dest = resp->buf + resp->headers_len;
    memcpy(dest, name.data, name.len);
    dest[name.len] = ':';
    dest[name.len + 1] = ' ';
    memcpy(dest + name.len + 2, value.data, value.len);
    dest[name.len + 2 + value.len] = '\r';
    dest[name.len + 2 + value.len + 1] = '\n';
    resp->headers_len += (uint32_t)required;
}

void conn_writeheader_raw(PulsarConn* conn, const char* header, size_t length) {
    response_t* resp = &conn->response;
    ensure_headers_capacity(resp, length);
    memcpy(resp->buf + resp->headers_len, header, length);
    resp->headers_len += (uint32_t)length;
}

void conn_writeheaders_vec(PulsarConn* conn, const struct iovec* headers, size_t count) {
    response_t* resp = &conn->response;
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++) {
        total_len += headers[i].iov_len;
    }
    ensure_headers_capacity(resp, total_len);

    char* dest = resp->buf + resp->headers_len;
    for (size_t i = 0; i < count; i++) {
        memcpy(dest, headers[i].iov_base, headers[i].iov_len);
        dest += headers[i].iov_len;
    }
    resp->headers_len += (uint32_t)total_len;
}

void conn_set_content_type(PulsarConn* conn, StrSlice content_type) {
    if (HAS_CONTENT_TYPE(conn->response.flags)) return;
    conn_writeheader(conn, SS_LIT("Content-Type"), content_type);
    SET_CONTENT_TYPE(conn->response.flags);
}

/* ================================================================
 * Response Body Writers
 * ================================================================ */

int conn_write(PulsarConn* conn, const void* data, size_t len) {
    response_t* res = &conn->response;
    size_t body_len = res->body_len;
    size_t required = body_len + len;

    if (unlikely(required > UINT32_MAX)) {
        fprintf(stderr, "body too large\n");
        return -1;
    }

    if (likely(!HAS_HEAP_ALLOCATED(res->flags))) {
        if (required <= RESP_BODY_CAPACITY) {
            memcpy(res->buf + RESP_BODY_OFFSET + body_len, data, len);
            res->body_len = (uint32_t)required;
            return (int)len;
        }

        size_t cap = WRITE_BUFFER_SIZE;
        while (cap < required) {
            if (cap > SIZE_MAX / 2) {
                cap = required;
                break;
            }
            cap *= 2;
        }
        uint8_t* hp = aligned_alloc(CACHE_LINE_SIZE, cap);
        if (!hp) {
            perror("aligned_alloc");
            return -1;
        }
        if (body_len > 0) {
            memcpy(hp, res->buf + RESP_BODY_OFFSET, body_len);
        }
        SET_HEAP_ALLOCATED(res->flags);
        res->body_capacity = (uint32_t)cap;
        res->body.heap = hp;
    }

    if (required > res->body_capacity) {
        size_t cap = res->body_capacity;
        while (cap < required) {
            if (cap > SIZE_MAX / 2) {
                fprintf(stderr, "body too large\n");
                return -1;
            }
            cap *= 2;
        }
        uint8_t* nb = realloc(res->body.heap, cap);
        if (!nb) {
            perror("realloc body");
            return -1;
        }
        res->body.heap = nb;
        res->body_capacity = (uint32_t)cap;
    }

    memcpy(res->body.heap + body_len, data, len);
    res->body_len = (uint32_t)required;
    return (int)len;
}

int conn_notfound(PulsarConn* conn) {
    conn_set_status(conn, StatusNotFound);
    conn_set_content_type(conn, SS_LIT(PLAINTEXT_TYPE));
    return conn_write(conn, "404 Not Found", 13);
}

int conn_write_string(PulsarConn* conn, const char* str) {
    return str ? conn_write(conn, str, strlen(str)) : 0;
}

int conn_writef(PulsarConn* conn, const char* restrict fmt, ...) {
    va_list args;
    char sbuf[4096];
    int len;

    va_start(args, fmt);
    len = vsnprintf(sbuf, sizeof(sbuf), fmt, args);
    va_end(args);

    if (len < 0) return 0;
    if (len < (int)sizeof(sbuf)) return conn_write(conn, sbuf, (size_t)len);
    char* hbuf = malloc((size_t)len + 1);
    if (!hbuf) {
        perror("conn_writef malloc");
        return 0;
    }

    va_start(args, fmt);
    vsnprintf(hbuf, (size_t)len + 1, fmt, args);
    va_end(args);
    int result = conn_write(conn, hbuf, (size_t)len);
    free(hbuf);

    return result;
}

void conn_abort(PulsarConn* conn) { conn->abort = true; }

/* ================================================================
 * Complete-Response Senders
 * ================================================================ */

void conn_send(PulsarConn* conn, http_status status, const void* data, size_t length) {
    conn_set_status(conn, status);
    conn_write(conn, data, length);
}

void conn_send_json(PulsarConn* conn, http_status status, const char* json, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: application/json\r\n", 32);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, json, length);
}

void conn_send_html(PulsarConn* conn, http_status status, const char* html, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: text/html\r\n", 25);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, html, length);
}

void conn_send_text(PulsarConn* conn, http_status status, const char* text, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: text/plain\r\n", 26);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, text, length);
}

void conn_send_xml(PulsarConn* conn, http_status status, const char* xml, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: application/xml\r\n", 31);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, xml, length);
}

void conn_send_javascript(PulsarConn* conn, http_status status, const char* javascript,
                          size_t length) {
    conn_writeheader_raw(conn, "Content-Type: application/javascript\r\n", 38);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, javascript, length);
}

void conn_send_css(PulsarConn* conn, http_status status, const char* css, size_t length) {
    conn_writeheader_raw(conn, "Content-Type: text/css\r\n", 24);
    SET_CONTENT_TYPE(conn->response.flags);
    conn_send(conn, status, css, length);
}

void conn_send_redirect(PulsarConn* conn, const char* location, bool permanent) {
    conn_set_status(conn, permanent ? StatusMovedPermanently : StatusFound);
    response_t* resp = &conn->response;
    size_t loc_len = strlen(location);
    size_t needed = 10 + loc_len + 2;
    ensure_headers_capacity(resp, needed);

    char* dest = resp->buf + resp->headers_len;
    memcpy(dest, "Location: ", 10);
    dest += 10;
    memcpy(dest, location, loc_len);
    dest += loc_len;
    *dest++ = '\r';
    *dest++ = '\n';
    resp->headers_len += (uint32_t)needed;
}
