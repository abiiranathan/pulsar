/**
 * @file chan_patterns.c
 * @brief Implementations for the pub/sub, worker-pool, and select
 *        abstractions declared in chan_patterns.h.
 */

#include "chan_patterns.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "thread.h"

/* NANOSLEEP comes from process.h */
#include "../include/process.h"

/* =========================================================================
 * Pub/Sub
 * ========================================================================= */

typedef struct {
    Channel* queue;
    bool active;
} ps_subscriber;

struct chan_pubsub {
    size_t value_size;
    size_t queue_depth;
    size_t max_subs;

    ps_subscriber* subs; /* fixed array of max_subs slots */
    size_t sub_count;    /* active subscribers            */

    bool closed;

    Lock lock;
};

chan_pubsub_t* chan_pubsub_new(size_t value_size, size_t max_subs, size_t queue_depth) {
    if (value_size == 0 || max_subs == 0 || max_subs > 1024 || queue_depth == 0) return NULL;

    chan_pubsub_t* ps = (chan_pubsub_t*)calloc(1, sizeof(chan_pubsub_t));
    if (!ps) return NULL;

    ps->subs = (ps_subscriber*)calloc(max_subs, sizeof(ps_subscriber));
    if (!ps->subs) {
        free(ps);
        return NULL;
    }

    ps->value_size = value_size;
    ps->queue_depth = queue_depth;
    ps->max_subs = max_subs;

    if (lock_init(&ps->lock) != 0) {
        free(ps->subs);
        free(ps);
        return NULL;
    }
    return ps;
}

size_t chan_pubsub_subscribe(chan_pubsub_t* ps) {
    if (!ps) return CHAN_PUBSUB_NO_SUB;

    size_t id = CHAN_PUBSUB_NO_SUB;
    lock_acquire(&ps->lock);
    if (!ps->closed && ps->sub_count < ps->max_subs) {
        for (size_t i = 0; i < ps->max_subs; i++) {
            if (!ps->subs[i].active) {
                /* Create the queue outside the lock to keep publish()
                 * contention low; mark the slot first so nobody else takes
                 * it. */
                ps->subs[i].active = true;
                id = i;
                break;
            }
        }
        if (id != CHAN_PUBSUB_NO_SUB) {
            /* Pre-increment so concurrent subscribe() calls pick other
             * slots while this one builds its queue. */
            ps->sub_count++;
        }
    }
    lock_release(&ps->lock);

    if (id == CHAN_PUBSUB_NO_SUB) return CHAN_PUBSUB_NO_SUB;

    Channel* q = chan_new(ps->value_size, ps->queue_depth);
    if (!q) {
        /* Roll the reservation back. */
        lock_acquire(&ps->lock);
        ps->subs[id].active = false;
        ps->sub_count--;
        lock_release(&ps->lock);
        return CHAN_PUBSUB_NO_SUB;
    }

    lock_acquire(&ps->lock);
    ps->subs[id].queue = q;
    lock_release(&ps->lock);
    return id;
}

ChanStatus chan_pubsub_publish(chan_pubsub_t* ps, const void* value) {
    if (!ps || !value) return CHAN_INVALID;

    ChanStatus overall = CHAN_OK;
    lock_acquire(&ps->lock);
    if (ps->closed) {
        lock_release(&ps->lock);
        return CHAN_CLOSED;
    }
    for (size_t i = 0; i < ps->max_subs; i++) {
        if (!ps->subs[i].active) continue;
        ChanStatus st = chan_try_send(ps->subs[i].queue, value);
        if (st != CHAN_OK && overall == CHAN_OK) overall = st;
    }
    lock_release(&ps->lock);
    return overall;
}

Channel* chan_pubsub_queue(chan_pubsub_t* ps, size_t id) {
    if (!ps || id >= ps->max_subs) return NULL;
    lock_acquire(&ps->lock);
    Channel* q = ps->subs[id].active ? ps->subs[id].queue : NULL;
    lock_release(&ps->lock);
    return q;
}

ChanStatus chan_pubsub_unsubscribe(chan_pubsub_t* ps, size_t id) {
    if (!ps || id >= ps->max_subs) return CHAN_INVALID;

    lock_acquire(&ps->lock);
    if (!ps->subs[id].active) {
        lock_release(&ps->lock);
        return CHAN_INVALID;
    }
    Channel* q = ps->subs[id].queue;
    ps->subs[id].queue = NULL;
    ps->subs[id].active = false;
    ps->sub_count--;
    lock_release(&ps->lock);

    /* Destroy outside the lock; the queue is now private to us. */
    chan_close(q);
    chan_free(q);
    return CHAN_OK;
}

ChanStatus chan_pubsub_close(chan_pubsub_t* ps) {
    if (!ps) return CHAN_INVALID;

    lock_acquire(&ps->lock);
    if (ps->closed) {
        lock_release(&ps->lock);
        return CHAN_OK;
    }
    ps->closed = true;
    for (size_t i = 0; i < ps->max_subs; i++) {
        if (ps->subs[i].active && ps->subs[i].queue) chan_close(ps->subs[i].queue);
    }
    lock_release(&ps->lock);
    return CHAN_OK;
}

size_t chan_pubsub_subscriber_count(chan_pubsub_t* ps) {
    if (!ps) return 0;
    lock_acquire(&ps->lock);
    size_t n = ps->sub_count;
    lock_release(&ps->lock);
    return n;
}

void chan_pubsub_free(chan_pubsub_t* ps) {
    if (!ps) return;
    for (size_t i = 0; i < ps->max_subs; i++) {
        if (ps->subs[i].queue) {
            chan_close(ps->subs[i].queue);
            chan_free(ps->subs[i].queue);
            ps->subs[i].queue = NULL;
        }
    }
    lock_free(&ps->lock);
    free(ps->subs);
    free(ps);
}

/* =========================================================================
 * Worker pool
 * ========================================================================= */

struct chan_workers {
    Channel* work;   /* shared work channel (values)          */
    chan_work_fn fn; /* user callback                          */
    void* user;      /* user context                           */
    size_t value_size;

    Thread* threads; /* worker_count handles                   */
    size_t worker_count;

    /* Pending = submitted and not yet completed. Workers debit the shared
     * counter after their callback returns, so shutdown() can drain
     * precisely. */
    Lock pending_lock;
    size_t pending;

    bool shutdown;
};

/** Worker thread main: pull items until the work channel closes and drains.
 * @param arg The chan_workers_t pointer itself. */
static void* chan_worker_main(void* arg) {
    chan_workers_t* w = (chan_workers_t*)arg;

    void* value = malloc(w->value_size);
    if (!value) return NULL;

    for (;;) {
        if (chan_recv(w->work, value)) {
            w->fn(value, w->user);
            lock_acquire(&w->pending_lock);
            w->pending--;
            lock_release(&w->pending_lock);
        } else {
            break; /* channel closed and drained */
        }
    }

    free(value);
    return NULL;
}

chan_workers_t* chan_workers_new(size_t worker_count, size_t value_size, size_t queue_depth, chan_work_fn fn,
                                 void* user) {
    if (worker_count == 0 || value_size == 0 || !fn) return NULL;

    chan_workers_t* w = (chan_workers_t*)calloc(1, sizeof(chan_workers_t));
    if (!w) return NULL;

    w->fn = fn;
    w->user = user;
    w->value_size = value_size;
    w->worker_count = worker_count;

    if (lock_init(&w->pending_lock) != 0) {
        free(w);
        return NULL;
    }

    w->work = chan_new(value_size, queue_depth);
    if (!w->work) {
        lock_free(&w->pending_lock);
        free(w);
        return NULL;
    }

    w->threads = (Thread*)calloc(worker_count, sizeof(Thread));
    if (!w->threads) {
        chan_free(w->work);
        lock_free(&w->pending_lock);
        free(w);
        return NULL;
    }

    size_t started = 0;
    for (; started < worker_count; started++) {
        if (thread_create(&w->threads[started], chan_worker_main, w) != 0) break;
    }

    if (started < worker_count) {
        /* Partial start: close so workers exit, join, then fail. */
        chan_close(w->work);
        for (size_t i = 0; i < started; i++) {
            void* ret;
            thread_join(w->threads[i], &ret);
        }
        free(w->threads);
        chan_free(w->work);
        lock_free(&w->pending_lock);
        free(w);
        return NULL;
    }

    return w;
}

ChanStatus chan_workers_submit(chan_workers_t* w, const void* value) {
    if (!w || !value) return CHAN_INVALID;
    ChanStatus st = chan_send(w->work, value);
    if (st != CHAN_OK) return st;
    lock_acquire(&w->pending_lock);
    w->pending++;
    lock_release(&w->pending_lock);
    return CHAN_OK;
}

size_t chan_workers_pending(chan_workers_t* w) {
    if (!w) return 0;
    lock_acquire(&w->pending_lock);
    size_t n = w->pending;
    lock_release(&w->pending_lock);
    return n;
}

ChanStatus chan_workers_shutdown(chan_workers_t* w) {
    if (!w) return CHAN_INVALID;

    lock_acquire(&w->pending_lock);
    if (w->shutdown) {
        lock_release(&w->pending_lock);
        return CHAN_OK;
    }
    w->shutdown = true;
    lock_release(&w->pending_lock);

    chan_close(w->work);
    for (size_t i = 0; i < w->worker_count; i++) {
        void* ret;
        thread_join(w->threads[i], &ret);
    }
    return CHAN_OK;
}

void chan_workers_free(chan_workers_t* w) {
    if (!w) return;
    free(w->threads);
    chan_free(w->work);
    lock_free(&w->pending_lock);
    free(w);
}

/* =========================================================================
 * Select
 * ========================================================================= */

int chan_select(Channel** channels, void** outs, size_t count, int timeout_ms) {
    if (!channels || count == 0 || count > CHAN_SELECT_MAX) return CHAN_SELECT_TIMEOUT;

    /* When outs is NULL the winning value is discarded: receive into a
     * scratch buffer sized for the largest channel. */
    void* scratch = NULL;
    if (!outs) {
        size_t max_sz = 0;
        for (size_t i = 0; i < count; i++) {
            size_t sz = chan_value_size(channels[i]);
            if (sz > max_sz) max_sz = sz;
        }
        if (max_sz == 0) max_sz = 1;
        scratch = malloc(max_sz);
        if (!scratch) return CHAN_SELECT_TIMEOUT;
    }

    int result = CHAN_SELECT_TIMEOUT;

    /* Phase 1: one immediate sweep in priority order. */
    for (size_t i = 0; i < count; i++) {
        void* target = outs ? outs[i] : scratch;
        ChanStatus st = chan_try_recv(channels[i], target);
        if (st == CHAN_OK) {
            result = (int)i;
            goto out;
        }
    }

    if (timeout_ms == 0) goto out;

    /* Phase 2: poll with an adaptive backoff until the budget expires. */
    int waited = 0;
    int slice = 1; /* ms; doubles up to 16 */
    while (timeout_ms < 0 || waited < timeout_ms) {
        int wait = (timeout_ms < 0) ? slice : ((slice < timeout_ms - waited) ? slice : timeout_ms - waited);
        NANOSLEEP(0, (long)wait * 1000000L);
        waited += wait;
        if (slice < 16) slice *= 2;

        for (size_t i = 0; i < count; i++) {
            void* target = outs ? outs[i] : scratch;
            ChanStatus st = chan_try_recv(channels[i], target);
            if (st == CHAN_OK) {
                result = (int)i;
                goto out;
            }
        }
    }

out:
    free(scratch);
    return result;
}

/* =========================================================================
 * Merge
 * ========================================================================= */

/** Per-source forwarder state. Lives in a shared heap context freed by the
 * last forwarder to exit. */
typedef struct {
    Channel* dest;
    Channel* src;
    size_t value_size;
    struct chan_merge_ctx* ctx;
} merger_arg;

/** Shared merge state: per-source args plus a live-forwarder counter. The
 * last forwarder out frees the context and closes dest. */
typedef struct chan_merge_ctx {
    merger_arg* args;
    atomic_int live;
} chan_merge_ctx;

/** Forwarder thread: moves values from one source into dest until the
 * source closes and drains. */
static void* chan_merger_main(void* arg) {
    merger_arg* m = (merger_arg*)arg;
    chan_merge_ctx* ctx = m->ctx;

    void* value = malloc(m->value_size);
    if (value) {
        while (chan_recv(m->src, value)) {
            /* Forward; if dest fails (OOM growth), drop the value rather
             * than deadlock the source. */
            chan_send(m->dest, value);
        }
        free(value);
    }

    /* Last forwarder out: free the shared context and close dest. */
    if (atomic_fetch_sub(&ctx->live, 1) == 1) {
        chan_close(m->dest);
        free(ctx->args);
        free(ctx);
    }
    return NULL;
}

ChanStatus chan_merge(Channel* dest, Channel** sources, size_t count) {
    if (!dest || !sources || count == 0 || count > CHAN_SELECT_MAX) return CHAN_INVALID;
    for (size_t i = 0; i < count; i++) {
        if (!sources[i]) return CHAN_INVALID;
        if (chan_value_size(sources[i]) != chan_value_size(dest)) return CHAN_INVALID;
    }

    chan_merge_ctx* ctx = (chan_merge_ctx*)calloc(1, sizeof(chan_merge_ctx));
    if (!ctx) return CHAN_NOMEM;
    ctx->args = (merger_arg*)calloc(count, sizeof(merger_arg));

    atomic_store(&ctx->live, count);

    Thread* threads = (Thread*)calloc(count, sizeof(Thread));
    if (!ctx->args || !threads) {
        free(ctx->args);
        free(threads);
        free(ctx);
        return CHAN_NOMEM;
    }

    size_t started = 0;
    for (; started < count; started++) {
        ctx->args[started].dest = dest;
        ctx->args[started].src = sources[started];
        ctx->args[started].value_size = chan_value_size(dest);
        ctx->args[started].ctx = ctx;
        if (thread_create(&threads[started], chan_merger_main, &ctx->args[started]) != 0) break;
        /* Forwarders are fire-and-forget: detached so they reclaim
         * themselves when the source closes (no join API needed). */
        thread_detach(threads[started]);
    }

    if (started < count) {
        if (started == 0) {
            /* No forwarder running: nobody will free the context. */
            free(ctx->args);
            free(ctx);
            free(threads);
            return CHAN_NOMEM;
        }
        /* Partial start: close the sources with running forwarders so they
         * exit; the last one frees the context and closes dest. Slots that
         * never started must not hold the counter open. */
        atomic_fetch_sub(&ctx->live, (int)(count - started));
        for (size_t i = 0; i < started; i++) chan_close(sources[i]);
        for (size_t i = 0; i < started; i++) {
            void* ret;
            thread_join(threads[i], &ret);
        }
        free(threads);
        return CHAN_NOMEM;
    }

    free(threads); /* forwarders are self-managing from here */
    return CHAN_OK;
}
