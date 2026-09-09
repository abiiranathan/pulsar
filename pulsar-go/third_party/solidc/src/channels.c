/**
 * @file channels.c
 * @brief Go-style typed channels: dynamically-grown ring buffer over the
 *        lock.h mutex/condvar primitives.
 *
 * Design notes
 * ------------
 * - One mutex guards all state. Two condition variables (readers, writers)
 *   avoid thundering-herd wakeups when one side is idle.
 * - close() broadcasts on both condvars so blocked senders fail fast and
 *   blocked receivers drain remaining values, then observe closure.
 * - The ring grows by doubling; on growth, live elements are re-linearized
 *   to the front of the new buffer. Growth happens under the lock, which is
 *   fine because it is amortized O(1) like a dynamic array.
 * - chan_send() grows without bound by default (Go semantics for unbuffered
 *   usage patterns); chan_new()'s capacity_hint only pre-sizes.
 */

#include "channels.h"

#include <stdlib.h>
#include <string.h>

struct Channel {
    unsigned char* buf; /* ring storage: capacity * value_size bytes */
    size_t value_size;  /* bytes per value                           */
    size_t capacity;    /* ring capacity in values (power of 2)      */
    size_t head;        /* index of oldest value                     */
    size_t count;       /* number of buffered values                 */

    bool closed;

    Lock lock;
    Condition not_empty; /* signaled on send / close */
    Condition not_full;  /* signaled on recv / close */
    bool cond_ready;     /* condvars initialized successfully */
};

/** Next power of two >= n (n >= 1). Honors small hints exactly so bounded
 * queues (e.g. pub/sub subscriber queues) keep their requested depth. */
static size_t chan_pow2(size_t n) {
    size_t c = 1;
    while (c < n) c <<= 1;
    return c;
}

Channel* chan_new(size_t value_size, size_t capacity_hint) {
    if (value_size == 0) return NULL;

    Channel* c = (Channel*)calloc(1, sizeof(Channel));
    if (!c) return NULL;

    c->value_size = value_size;
    c->capacity = chan_pow2(capacity_hint ? capacity_hint : 16);
    c->buf = (unsigned char*)malloc(c->capacity * value_size);
    if (!c->buf) {
        free(c);
        return NULL;
    }

    if (lock_init(&c->lock) != 0) {
        free(c->buf);
        free(c);
        return NULL;
    }
    if (cond_init(&c->not_empty) != 0 || cond_init(&c->not_full) != 0) {
        cond_free(&c->not_empty);
        cond_free(&c->not_full);
        lock_free(&c->lock);
        free(c->buf);
        free(c);
        return NULL;
    }
    c->cond_ready = true;
    return c;
}

/** Grows the ring to new_cap (a power of two, > capacity). Called with the lock held. */
static ChanStatus chan_grow(Channel* c, size_t new_cap) {
    unsigned char* nb = (unsigned char*)malloc(new_cap * c->value_size);
    if (!nb) return CHAN_NOMEM;

    /* Re-linearize: copy head..wrap into the front of the new buffer. */
    size_t tail_len = c->capacity - c->head;
    size_t first = (c->count < tail_len) ? c->count : tail_len;
    memcpy(nb, c->buf + c->head * c->value_size, first * c->value_size);
    if (c->count > first) {
        memcpy(nb + first * c->value_size, c->buf, (c->count - first) * c->value_size);
    }

    free(c->buf);
    c->buf = nb;
    c->capacity = new_cap;
    c->head = 0;
    return CHAN_OK;
}

ChanStatus chan_send(Channel* c, const void* value) {
    if (!c || !value) return CHAN_INVALID;

    ChanStatus st = CHAN_OK;
    lock_acquire(&c->lock);
    for (;;) {
        if (c->closed) {
            st = CHAN_CLOSED;
            goto out;
        }
        if (c->count < c->capacity) break;

        /* Grow unbounded (Go-like): senders never block on a full buffer. */
        st = chan_grow(c, c->capacity * 2);
        if (st != CHAN_OK) goto out;
        break;
    }

    size_t tail = (c->head + c->count) & (c->capacity - 1);
    memcpy(c->buf + tail * c->value_size, value, c->value_size);
    c->count++;
    cond_signal(&c->not_empty);
    st = CHAN_OK;

out:
    lock_release(&c->lock);
    return st;
}

bool chan_recv(Channel* c, void* out) { return chan_recv_timeout(c, out, -1) == CHAN_OK; }

ChanStatus chan_try_send(Channel* c, const void* value) {
    if (!c || !value) return CHAN_INVALID;

    ChanStatus st;
    lock_acquire(&c->lock);
    if (c->closed) {
        st = CHAN_CLOSED;
    } else if (c->count == c->capacity) {
        st = CHAN_FULL;
    } else {
        size_t tail = (c->head + c->count) & (c->capacity - 1);
        memcpy(c->buf + tail * c->value_size, value, c->value_size);
        c->count++;
        cond_signal(&c->not_empty);
        st = CHAN_OK;
    }
    lock_release(&c->lock);
    return st;
}

ChanStatus chan_try_recv(Channel* c, void* out) {
    if (!c || !out) return CHAN_INVALID;

    ChanStatus st;
    lock_acquire(&c->lock);
    if (c->count > 0) {
        memcpy(out, c->buf + c->head * c->value_size, c->value_size);
        c->head = (c->head + 1) & (c->capacity - 1);
        c->count--;
        cond_signal(&c->not_full);
        st = CHAN_OK;
    } else {
        st = c->closed ? CHAN_CLOSED : CHAN_EMPTY;
    }
    lock_release(&c->lock);
    return st;
}

ChanStatus chan_recv_timeout(Channel* c, void* out, int timeout_ms) {
    if (!c || !out) return CHAN_INVALID;

    ChanStatus st = CHAN_OK;
    lock_acquire(&c->lock);
    for (;;) {
        if (c->count > 0) {
            memcpy(out, c->buf + c->head * c->value_size, c->value_size);
            c->head = (c->head + 1) & (c->capacity - 1);
            c->count--;
            cond_signal(&c->not_full);
            st = CHAN_OK;
            break;
        }
        if (c->closed) {
            st = CHAN_CLOSED;
            break;
        }
        if (timeout_ms == 0) {
            st = CHAN_TIMEOUT;
            break;
        }
        if (cond_wait_timeout(&c->not_empty, &c->lock, timeout_ms) != 0) {
            /* Timed out (or rare spurious failure): re-check state once so a
             * value racing with the timeout is still delivered. */
            if (c->count > 0) continue;
            st = CHAN_TIMEOUT;
            break;
        }
        /* Woken: loop re-checks count/closed. */
    }
    lock_release(&c->lock);
    return st;
}

ChanStatus chan_close(Channel* c) {
    if (!c) return CHAN_INVALID;

    lock_acquire(&c->lock);
    ChanStatus st = CHAN_OK;
    if (c->closed) {
        st = CHAN_CLOSED; /* idempotent */
    } else {
        c->closed = true;
        cond_broadcast(&c->not_empty);
        cond_broadcast(&c->not_full);
    }
    lock_release(&c->lock);
    return st;
}

size_t chan_len(Channel* c) {
    if (!c) return 0;
    lock_acquire(&c->lock);
    size_t n = c->count;
    lock_release(&c->lock);
    return n;
}

size_t chan_cap(Channel* c) { return c ? c->capacity : 0; }

bool chan_is_closed(Channel* c) {
    if (!c) return true;
    lock_acquire(&c->lock);
    bool closed = c->closed;
    lock_release(&c->lock);
    return closed;
}

size_t chan_value_size(Channel* c) { return c ? c->value_size : 0; }

void chan_free(Channel* c) {
    if (!c) return;
    if (c->cond_ready) {
        cond_free(&c->not_empty);
        cond_free(&c->not_full);
    }
    lock_free(&c->lock);
    free(c->buf);
    free(c);
}
