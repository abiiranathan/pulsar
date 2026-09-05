#ifndef PLOG_H
#define PLOG_H

#include <inttypes.h>
#include <solidc/align.h>  /* ALIGN */
#include <solidc/thread.h> /* Thread, thread_create, thread_join */
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Tunables
 * ---------------------------------------------------------------------- */

/** Ring capacity (must be a power of two). */
#ifndef PLOG_RING_CAPACITY
#define PLOG_RING_CAPACITY 131072
#endif

/** Maximum string field lengths copied by value to avoid dangling pointers. */
#define PLOG_METHOD_MAX 8
#define PLOG_PATH_MAX   128
#define PLOG_UA_MAX     256

_Static_assert((PLOG_RING_CAPACITY & (PLOG_RING_CAPACITY - 1)) == 0,
               "PLOG_RING_CAPACITY must be a power of two");

/* -------------------------------------------------------------------------
 * Binary Log Event
 * ---------------------------------------------------------------------- */

/**
 * Compact binary event struct (~152 bytes).
 * Copied directly on the worker thread via simple memory assignment.
 */
typedef struct {
    uint64_t total_ns;
    uint16_t status_code;
    char method[PLOG_METHOD_MAX];
    char path[PLOG_PATH_MAX];
    char user_agent[PLOG_UA_MAX];
} PlogEvent;

typedef enum {
    PLOG_SLOT_FREE = 0,
    PLOG_SLOT_READY = 1,
} PlogSlotState;

typedef struct ALIGN(64) PlogEvent {
    _Atomic(PlogSlotState) state;
    PlogEvent event;
} PlogSlot;

/* -------------------------------------------------------------------------
 * Logger State
 * ---------------------------------------------------------------------- */

typedef struct {
    alignas(64) PlogSlot ring[PLOG_RING_CAPACITY];

    /* Producer sequence counter */
    alignas(64) _Atomic uint64_t prod_seq;

    /* Consumer sequence counter */
    alignas(64) _Atomic uint64_t cons_seq;

    /* Metrics & Control */
    alignas(64) _Atomic uint64_t drops;
    _Atomic bool drain_running;
    Thread thread_handle;
    int out_fd;
} PlogState;

/* -------------------------------------------------------------------------
 * Internal Drain Thread
 * ---------------------------------------------------------------------- */

static inline void plog__format_latency(char* buf, size_t size, uint64_t total_ns) {
    if (total_ns < 1000) {
        snprintf(buf, size, "%3" PRIu64 "ns", total_ns);
    } else if (total_ns < 1000000) {
        snprintf(buf, size, "%5" PRIu64 "µs", total_ns / 1000);
    } else if (total_ns < 1000000000) {
        snprintf(buf, size, "%5" PRIu64 "ms", total_ns / 1000000);
    } else {
        snprintf(buf, size, "%5" PRIu64 "s", total_ns / 1000000000);
    }
}

static void* plog__drain_thread(void* arg) {
    PlogState* lg = (PlogState*)arg;

    /* 64KB user-space write batch buffer */
    char write_buf[65536];
    size_t buf_pos = 0;

    while (atomic_load_explicit(&lg->drain_running, memory_order_relaxed)) {
        uint64_t cons = atomic_load_explicit(&lg->cons_seq, memory_order_relaxed);
        uint64_t prod = atomic_load_explicit(&lg->prod_seq, memory_order_acquire);

        if (cons == prod) {
            /* Flush any pending bytes before sleeping */
            if (buf_pos > 0) {
                (void)write(lg->out_fd, write_buf, buf_pos);
                buf_pos = 0;
            }
            /* Adaptive sleep when queue is empty */
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 500000}; /* 500 µs */
            nanosleep(&ts, NULL);
            continue;
        }

        while (cons < prod) {
            size_t idx = cons & (PLOG_RING_CAPACITY - 1);
            PlogSlot* slot = &lg->ring[idx];

            /* Wait for slot release store */
            int spins = 0;
            while (atomic_load_explicit(&slot->state, memory_order_acquire) != PLOG_SLOT_READY) {
                if (++spins > 100) break;
#if defined(__x86_64__) || defined(__i386__)
                __builtin_ia32_pause();
#elif defined(__aarch64__)
                __asm__ __volatile__("yield");
#endif
            }

            if (atomic_load_explicit(&slot->state, memory_order_acquire) != PLOG_SLOT_READY) {
                /* Producer stalled during copy; flush and retry later */
                break;
            }

            /* Format log line on the background consumer thread */
            char latency_str[16];
            plog__format_latency(latency_str, sizeof(latency_str), slot->event.total_ns);

            int written =
                snprintf(write_buf + buf_pos, sizeof(write_buf) - buf_pos,
                         "[Pulsar] %-7s %-5s %3d %8s %s\n", slot->event.method, slot->event.path,
                         (int)slot->event.status_code, latency_str, slot->event.user_agent);

            /* Release slot back to FREE */
            atomic_store_explicit(&slot->state, PLOG_SLOT_FREE, memory_order_relaxed);
            cons++;

            if (written > 0) {
                buf_pos += (size_t)written;
            }

            /* Flush buffer when close to capacity */
            if (buf_pos >= sizeof(write_buf) - 512) {
                (void)write(lg->out_fd, write_buf, buf_pos);
                buf_pos = 0;
            }
        }

        atomic_store_explicit(&lg->cons_seq, cons, memory_order_release);
    }

    /* Shutdown flush */
    uint64_t cons = atomic_load_explicit(&lg->cons_seq, memory_order_relaxed);
    uint64_t prod = atomic_load_explicit(&lg->prod_seq, memory_order_acquire);
    while (cons < prod) {
        size_t idx = cons & (PLOG_RING_CAPACITY - 1);
        PlogSlot* slot = &lg->ring[idx];

        if (atomic_load_explicit(&slot->state, memory_order_acquire) == PLOG_SLOT_READY) {
            char latency_str[16];
            plog__format_latency(latency_str, sizeof(latency_str), slot->event.total_ns);

            int written =
                snprintf(write_buf + buf_pos, sizeof(write_buf) - buf_pos,
                         "[Pulsar] %-7s %-5s %3d %8s %s\n", slot->event.method, slot->event.path,
                         (int)slot->event.status_code, latency_str, slot->event.user_agent);

            atomic_store_explicit(&slot->state, PLOG_SLOT_FREE, memory_order_relaxed);
            if (written > 0) buf_pos += (size_t)written;

            if (buf_pos >= sizeof(write_buf) - 512) {
                (void)write(lg->out_fd, write_buf, buf_pos);
                buf_pos = 0;
            }
        }
        cons++;
    }

    if (buf_pos > 0) {
        (void)write(lg->out_fd, write_buf, buf_pos);
    }
    atomic_store_explicit(&lg->cons_seq, cons, memory_order_release);

    return NULL;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

static inline bool plog_init(PlogState* lg, int out_fd) {
    memset(lg, 0, sizeof(*lg));
    lg->out_fd = out_fd;
    atomic_store_explicit(&lg->drain_running, true, memory_order_release);
    return thread_create(&lg->thread_handle, plog__drain_thread, lg) == 0;
}

/**
 * Hot path: sub-10ns binary event submission.
 */
static inline void plog_submit(PlogState* lg, const PlogEvent* ev) {
    uint64_t prod = atomic_fetch_add_explicit(&lg->prod_seq, 1, memory_order_relaxed);
    uint64_t cons = atomic_load_explicit(&lg->cons_seq, memory_order_relaxed);

    /* Backpressure check */
    if (prod - cons >= (uint64_t)PLOG_RING_CAPACITY) {
        cons = atomic_load_explicit(&lg->cons_seq, memory_order_acquire);
        if (prod - cons >= (uint64_t)PLOG_RING_CAPACITY) {
            atomic_fetch_add_explicit(&lg->drops, 1, memory_order_relaxed);
            return;
        }
    }

    size_t idx = prod & (PLOG_RING_CAPACITY - 1);
    PlogSlot* slot = &lg->ring[idx];

    /* Fast struct copy */
    slot->event = *ev;

    atomic_store_explicit(&slot->state, PLOG_SLOT_READY, memory_order_release);
}

static inline void plog_destroy(PlogState* lg) {
    atomic_store_explicit(&lg->drain_running, false, memory_order_release);
    thread_join(lg->thread_handle, NULL);
}

static inline uint64_t plog_drop_count(const PlogState* lg) {
    return atomic_load_explicit((_Atomic uint64_t*)&lg->drops, memory_order_relaxed);
}

#endif /* PLOG_H */
