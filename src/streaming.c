#include "internal.h"

/* ================================================================
 * Streaming / Single-Write Helpers
 * ================================================================ */

INLINE ssize_t write_retry(int fd, const void* data, size_t len) {
    size_t total = 0;
    const char* ptr = (const char*)data;
    while (total < len) {
        ssize_t written = sys_write_direct(fd, ptr + total, len - total);
        if (written < 0) {
            if (written == -EAGAIN || written == -EWOULDBLOCK) {
                usleep(10);
                continue;
            }
            if (written == -EINTR) continue;
            return -1;
        }
        total += (size_t)written;
    }
    return (ssize_t)total;
}

INLINE ssize_t writev_retry(int fd, struct iovec* iov, int iovcnt) {
    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) total += iov[i].iov_len;
    size_t sent_total = 0;

    while (sent_total < total) {
        ssize_t n = sys_writev_direct(fd, iov, iovcnt);
        if (n < 0) {
            if (n == -EAGAIN || n == -EWOULDBLOCK) {
                usleep(10);
                continue;
            }
            if (n == -EINTR) continue;
            return -1;
        }
        sent_total += (size_t)n;
        if (sent_total == total) break;

        size_t rem = (size_t)n;
        while (iovcnt > 0 && rem >= iov[0].iov_len) {
            rem -= iov[0].iov_len;
            iov++;
            iovcnt--;
        }
        if (iovcnt > 0 && rem > 0) {
            iov[0].iov_base = (char*)iov[0].iov_base + rem;
            iov[0].iov_len -= rem;
        }
    }
    return (ssize_t)sent_total;
}

void conn_start_sse(PulsarConn* conn) {
    conn_set_status(conn, StatusOK);
    static const char SSE_HEADERS[] =
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n";
    conn_writeheader_raw(conn, SSE_HEADERS, sizeof(SSE_HEADERS) - 1);
    SET_CONTENT_TYPE(conn->response.flags);
    SET_CHUNKED_TRANSFER(conn->response.flags);
}

void conn_start_chunked_transfer(PulsarConn* conn, int max_age_seconds) {
    conn_set_status(conn, StatusOK);
    static const char TRANS_HEADERS[] =
        "Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n";
    conn_writef(conn, "Cache-Control: public, max-age=%d\r\n", max_age_seconds);
    conn_writeheader_raw(conn, TRANS_HEADERS, sizeof(TRANS_HEADERS) - 1);
    SET_CONTENT_TYPE(conn->response.flags);
    SET_CHUNKED_TRANSFER(conn->response.flags);
}

#define BATCH_SIZE 4096

ssize_t conn_write_chunk(PulsarConn* conn, const void* data, size_t size) {
    char chunk_buf[BATCH_SIZE] = {0};
    size_t pos = 0;

    if (!HAS_HEADERS_WRITTEN(conn->response.flags)) {
        ensure_headers_capacity(&conn->response, 2);
        memcpy(conn->response.buf + conn->response.headers_len, "\r\n", 2);
        conn->response.headers_len += 2;

        if (write_retry(conn->client_fd, conn->response.buf, conn->response.headers_len) < 0)
            return -1;
        SET_HEADERS_WRITTEN(conn->response.flags);
    }

    if (size == 0) {
        static const char final_chunk[] = "0\r\n\r\n";
        return write_retry(conn->client_fd, final_chunk, sizeof(final_chunk) - 1);
    }

    int hlen = snprintf(chunk_buf, sizeof(chunk_buf), "%zx\r\n", size);
    if (hlen > 0) pos += (size_t)hlen;

    if (pos + size + 2 <= sizeof(chunk_buf)) {
        memcpy(chunk_buf + pos, data, size);
        pos += size;
        memcpy(chunk_buf + pos, "\r\n", 2);
        pos += 2;
        return write_retry(conn->client_fd, chunk_buf, pos);
    } else {
        struct iovec iov[3] = {
            {.iov_base = chunk_buf, .iov_len = pos},
            {.iov_base = (void*)data, .iov_len = size},
            {.iov_base = (void*)"\r\n", .iov_len = 2},
        };
        return writev_retry(conn->client_fd, iov, 3);
    }
}

void conn_send_event(PulsarConn* conn, const SSEvent* evt) {
    if (!HAS_HEADERS_WRITTEN(conn->response.flags)) {
        ensure_headers_capacity(&conn->response, 2);
        memcpy(conn->response.buf + conn->response.headers_len, "\r\n", 2);
        conn->response.headers_len += 2;

        write_retry(conn->client_fd, conn->response.buf, conn->response.headers_len);
        SET_HEADERS_WRITTEN(conn->response.flags);
    }

    char batch[BATCH_SIZE] = {0};
    size_t bpos = 0;

#define FLUSH_IF_NEEDED(n)                         \
    do {                                           \
        if (bpos + (n) > BATCH_SIZE && bpos > 0) { \
            conn_write_chunk(conn, batch, bpos);   \
            bpos = 0;                              \
        }                                          \
    } while (0)

    if (ss_is_valid(evt->event)) {
        FLUSH_IF_NEEDED(evt->event.len + 8);
        bpos += (size_t)snprintf(batch + bpos, BATCH_SIZE - bpos, "event: %.*s\n",
                                 (int)evt->event.len, evt->event.data);
    }

    const char* dp = evt->data.data;
    size_t drem = evt->data.len;
    while (drem > 0) {
        const char* le = memchr(dp, '\n', drem);
        size_t line_len = le ? (size_t)(le - dp) : drem;
        FLUSH_IF_NEEDED(line_len + 8);

        size_t max_line = BATCH_SIZE - bpos - 8;
        if (line_len > max_line) line_len = max_line;
        bpos +=
            (size_t)snprintf(batch + bpos, BATCH_SIZE - bpos, "data: %.*s\n", (int)line_len, dp);
        dp += line_len;
        drem -= line_len;

        if (drem > 0 && *dp == '\n') {
            dp++;
            drem--;
        }
    }

    if (ss_is_valid(evt->id)) {
        FLUSH_IF_NEEDED(evt->id.len + 5);
        bpos += (size_t)snprintf(batch + bpos, BATCH_SIZE - bpos, "id: %.*s\n", (int)evt->id.len,
                                 evt->id.data);
    }

    FLUSH_IF_NEEDED(1);
    batch[bpos++] = '\n';
    if (bpos > 0) conn_write_chunk(conn, batch, bpos);
#undef FLUSH_IF_NEEDED
}

void conn_end_chunked_transfer(PulsarConn* conn) { conn_write_chunk(conn, NULL, 0); }
void conn_end_sse(PulsarConn* conn) { conn_write_chunk(conn, NULL, 0); }
