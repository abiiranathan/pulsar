#include "tcp/tcp_buffer.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define TCP_BUFFER_MIN_CAP 64

void tcp_buffer_init(tcp_buffer_t* b) {
    if (!b) return;
    b->data = NULL;
    b->cap = 0;
    b->head = 0;
    b->len = 0;
}

void tcp_buffer_free(tcp_buffer_t* b) {
    if (!b) return;
    free(b->data);
    b->data = NULL;
    b->cap = 0;
    b->head = 0;
    b->len = 0;
}

void tcp_buffer_compact(tcp_buffer_t* b) {
    if (!b || b->len == 0) {
        if (b) b->head = 0;
        return;
    }
    if (b->head == 0) return;
    memmove(b->data, b->data + b->head, b->len);
    b->head = 0;
}

static size_t grow_cap(size_t current, size_t needed) {
    size_t cap = current ? current : TCP_BUFFER_MIN_CAP;
    while (cap < needed) {
        if (cap > (size_t)-1 / 2) {
            cap = needed;
            break;
        }
        cap *= 2;
    }
    return cap;
}

int tcp_buffer_reserve(tcp_buffer_t* b, size_t extra) {
    if (!b) {
        errno = EINVAL;
        return -1;
    }
    if (extra <= b->cap - b->head - b->len) return 0;

    /* Try to reclaim the consumed prefix before growing. */
    if (b->head > 0) tcp_buffer_compact(b);
    if (extra <= b->cap - b->len) return 0;

    size_t needed = b->len + extra;
    size_t new_cap = grow_cap(b->cap, needed);

    uint8_t* new_data = realloc(b->data, new_cap);
    if (!new_data) {
        errno = ENOMEM;
        return -1;
    }
    b->data = new_data;
    b->cap = new_cap;
    return 0;
}

int tcp_buffer_append(tcp_buffer_t* b, const void* data, size_t n) {
    if (n == 0) return 0;
    if (!b || !data) {
        errno = EINVAL;
        return -1;
    }
    if (tcp_buffer_reserve(b, n) < 0) return -1;

    memcpy(b->data + b->head + b->len, data, n);
    b->len += n;
    return 0;
}

int tcp_buffer_appendv(tcp_buffer_t* b, const struct iovec* iov, int iovcnt) {
    if (iovcnt <= 0) return 0;
    if (!b || !iov) {
        errno = EINVAL;
        return -1;
    }

    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > (size_t)-1 - total) {
            errno = EOVERFLOW;
            return -1;
        }
        total += iov[i].iov_len;
    }

    if (tcp_buffer_reserve(b, total) < 0) return -1;

    uint8_t* dst = b->data + b->head + b->len;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len == 0) continue;
        memcpy(dst, iov[i].iov_base, iov[i].iov_len);
        dst += iov[i].iov_len;
    }
    b->len += total;
    return 0;
}

void tcp_buffer_consume(tcp_buffer_t* b, size_t n) {
    if (!b || n == 0) return;
    if (n >= b->len) {
        b->len = 0;
        b->head = 0;
        return;
    }
    b->head += n;
    b->len -= n;
}
