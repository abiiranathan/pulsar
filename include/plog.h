#ifndef PLOG_H
#define PLOG_H

#include <errno.h>
#include <inttypes.h>
#include <solidc/align.h>  /* ALIGN */
#include <solidc/thread.h> /* Thread, thread_create, thread_join */
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "constants.h"

/* -------------------------------------------------------------------------
 * Tunables & Shard Configuration
 * ---------------------------------------------------------------------- */

#ifndef PLOG_NUM_SHARDS
#ifdef NUM_WORKERS
#define PLOG_NUM_SHARDS NUM_WORKERS
#else
#define PLOG_NUM_SHARDS 16
#endif
#endif

/**
 * Capacity per shard (must be a power of two).
 * 32,768 entries * 16 shards = 524,288 total buffered entries.
 * At 500K req/sec, this provides > 1.0 seconds of burst absorption.
 */
#ifndef PLOG_SHARD_CAPACITY
#define PLOG_SHARD_CAPACITY 32768
#endif

_Static_assert((PLOG_SHARD_CAPACITY & (PLOG_SHARD_CAPACITY - 1)) == 0,
               "PLOG_SHARD_CAPACITY must be a power of two");

/**
 * 1 = Security-critical mode: never drop logs. If full, workers briefly pause
 *     until the consumer drains slots.
 * 0 = Lossy mode: drops entries on backpressure.
 */
#ifndef PLOG_LOSSLESS
#define PLOG_LOSSLESS 1
#endif

#define PLOG_METHOD_MAX 8
#define PLOG_PATH_MAX   64
#define PLOG_UA_MAX     128
#define PLOG_WRITE_BUF  (16 * 1024) /* 16KB buffer for writev() batching. */

/**
 * Idle backoff tuning for the drain thread. The loop starts by spinning
 * (cheap, low-latency) and escalates to increasingly longer nanosleep()
 * calls the longer it stays idle, capping at PLOG_IDLE_SLEEP_MAX_NS. This
 * prevents the drain thread from pegging a core when there is no log
 * traffic, while still reacting quickly when bursts arrive.
 */
#ifndef PLOG_IDLE_SPIN_LIMIT
#define PLOG_IDLE_SPIN_LIMIT 64 /* Pure spin iterations before first sleep. */
#endif
#ifndef PLOG_IDLE_SLEEP_MIN_NS
#define PLOG_IDLE_SLEEP_MIN_NS 50000L /* 50 microseconds. */
#endif
#ifndef PLOG_IDLE_SLEEP_MAX_NS
#define PLOG_IDLE_SLEEP_MAX_NS 20000000L /* 20 milliseconds. */
#endif

/**
 * Backpressure spin tuning for the lossless producer path. If the consumer
 * cannot keep up, producers spin briefly, then fall back to short sleeps so
 * a stalled or dead drain thread cannot pin worker threads at 100% CPU
 * indefinitely.
 */
#ifndef PLOG_BACKPRESSURE_SPIN_LIMIT
#define PLOG_BACKPRESSURE_SPIN_LIMIT 1000
#endif
#ifndef PLOG_BACKPRESSURE_SLEEP_NS
#define PLOG_BACKPRESSURE_SLEEP_NS 20000L /* 20 microseconds. */
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define PLOG_THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#define PLOG_THREAD_LOCAL __thread
#else
#define PLOG_THREAD_LOCAL _Thread_local
#endif

/* -------------------------------------------------------------------------
 * Binary Log Event
 * ---------------------------------------------------------------------- */

typedef struct {
    uint64_t total_ns;
    uint16_t status_code;
    char method[PLOG_METHOD_MAX];
    char path[PLOG_PATH_MAX];
    char user_agent[PLOG_UA_MAX];
} PlogEvent;

/* -------------------------------------------------------------------------
 * SPSC Shard (Zero False-Sharing Layout)
 * ---------------------------------------------------------------------- */

typedef struct {
    /* Producer cache line: written exclusively by worker thread */
    alignas(64) _Atomic uint64_t prod_seq;
    uint64_t cached_cons; /* Local copy: avoids reading cons_seq across cores */

    /* Consumer cache line: written exclusively by drain thread */
    alignas(64) _Atomic uint64_t cons_seq;

    /* Metrics */
    alignas(64) _Atomic uint64_t drops;

    /* SPSC Ring buffer */
    alignas(64) PlogEvent ring[PLOG_SHARD_CAPACITY];
} PlogShard;

typedef struct {
    PlogShard* shards[PLOG_NUM_SHARDS];
    _Atomic uint32_t shard_allocator;
    _Atomic bool drain_running;
    Thread thread_handle;
    int out_fd;
} PlogState;

/* -------------------------------------------------------------------------
 * Ultra-Fast Direct Serialization (~15ns vs ~1500ns in snprintf)
 * ---------------------------------------------------------------------- */

static const char g_plog_digits100[] =
    "0001020304050607080910111213141516171819"
    "2021222324252627282930313233343536373839"
    "4041424344454647484950515253545556575859"
    "6061626364656667686970717273747576777879"
    "8081828384858687888990919293949596979899";

static inline size_t plog__format_line(char* dst, const PlogEvent* ev) {
    char* p = dst;

    /* 1. Prefix: "[Pulsar] " (9 bytes) */
    memcpy(p, "[Pulsar] ", 9);
    p += 9;

    /* 2. Method: %-7s */
    size_t m_len = 0;
    while (m_len < PLOG_METHOD_MAX && ev->method[m_len] != '\0') {
        p[m_len] = ev->method[m_len];
        m_len++;
    }
    p += m_len;
    while (m_len < 7) {
        *p++ = ' ';
        m_len++;
    }
    *p++ = ' ';

    /* 3. Path: %-5s */
    size_t path_len = 0;
    while (path_len < PLOG_PATH_MAX && ev->path[path_len] != '\0') {
        p[path_len] = ev->path[path_len];
        path_len++;
    }
    p += path_len;
    while (path_len < 5) {
        *p++ = ' ';
        path_len++;
    }
    *p++ = ' ';

    /* 4. Status Code: %3d (branchless table lookup) */
    uint32_t sc = (uint32_t)ev->status_code;
    if (__builtin_expect(sc >= 100 && sc <= 999, 1)) {
        p[0] = (char)('0' + (sc / 100));
        uint32_t rem = (sc % 100) * 2;
        p[1] = g_plog_digits100[rem];
        p[2] = g_plog_digits100[rem + 1];
        p += 3;
    } else {
        p[0] = ' ';
        p[1] = ' ';
        p[2] = ' ';
        p += 3;
    }
    *p++ = ' ';

    /* 5. Latency: %8s (always exactly 8 bytes) */
    uint64_t ns = ev->total_ns;
    if (ns < 1000) {
        /* %3lluns -> 3 spaces + 3 digits + "ns" */
        p[0] = ' ';
        p[1] = ' ';
        p[2] = ' ';
        uint32_t v = (uint32_t)ns;
        p[3] = (v >= 100) ? (char)('0' + (v / 100)) : ' ';
        p[4] = (v >= 10) ? (char)('0' + ((v / 10) % 10)) : ' ';
        p[5] = (char)('0' + (v % 10));
        p[6] = 'n';
        p[7] = 's';
        p += 8;
    } else if (ns < 1000000) {
        /* %5lluµs -> 5 digits/spaces + "\xc2\xb5s" = 8 bytes */
        uint32_t us = (uint32_t)(ns / 1000);
        for (int i = 4; i >= 0; i--) {
            if (us > 0 || i == 4) {
                p[i] = (char)('0' + (us % 10));
                us /= 10;
            } else {
                p[i] = ' ';
            }
        }
        p[5] = (char)0xC2;
        p[6] = (char)0xB5;
        p[7] = 's';
        p += 8;
    } else if (ns < 1000000000) {
        /* %5llums -> 1 space + 5 digits + "ms" = 8 bytes */
        p[0] = ' ';
        uint32_t ms = (uint32_t)(ns / 1000000);
        for (int i = 5; i >= 1; i--) {
            if (ms > 0 || i == 5) {
                p[i] = (char)('0' + (ms % 10));
                ms /= 10;
            } else {
                p[i] = ' ';
            }
        }
        p[6] = 'm';
        p[7] = 's';
        p += 8;
    } else {
        /* %5llus -> 2 spaces + 5 digits + "s" = 8 bytes */
        p[0] = ' ';
        p[1] = ' ';
        uint32_t s = (uint32_t)(ns / 1000000000);
        for (int i = 6; i >= 2; i--) {
            if (s > 0 || i == 6) {
                p[i] = (char)('0' + (s % 10));
                s /= 10;
            } else {
                p[i] = ' ';
            }
        }
        p[7] = 's';
        p += 8;
    }
    *p++ = ' ';

    /* 6. User Agent: %s */
    size_t ua_len = 0;
    while (ua_len < PLOG_UA_MAX && ev->user_agent[ua_len] != '\0') {
        p[ua_len] = ev->user_agent[ua_len];
        ua_len++;
    }
    if (ua_len == 0) {
        *p++ = '-';
    } else {
        p += ua_len;
    }

    *p++ = '\n';
    return (size_t)(p - dst);
}

static inline void plog__write_all(int fd, const char* buf, size_t count) {
    while (count > 0) {
        ssize_t n = write(fd, buf, count);
        if (__builtin_expect(n > 0, 1)) {
            buf += n;
            count -= (size_t)n;
        } else if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        } else {
            break; /* Unrecoverable error on out_fd */
        }
    }
}

/**
 * Sleeps for the given number of nanoseconds, retrying on EINTR.
 * Used by the idle backoff paths below; never propagates an error since a
 * spurious wake or interrupted sleep is harmless for backoff purposes.
 */
static inline void plog__backoff_sleep(long nanoseconds) {
    struct timespec ts = {.tv_sec = nanoseconds / 1000000000L,
                          .tv_nsec = nanoseconds % 1000000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
        /* Remaining time is written back into ts; keep sleeping it out. */
    }
}

/**
 * Emits one CPU-pause/yield instruction. Cheap, low-latency spin primitive
 * used while waiting for a small amount of work to appear.
 */
static inline void plog__cpu_relax(void) {
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

/* -------------------------------------------------------------------------
 * Background Drain Thread
 * ---------------------------------------------------------------------- */

static void* plog__drain_thread(void* arg) {
    PlogState* lg = (PlogState*)arg;
    char write_buf[PLOG_WRITE_BUF];
    size_t buf_pos = 0;

    /* Progressive idle backoff state. idle_cycles counts consecutive
     * iterations with no work across all shards; it only resets when work
     * is found. This replaces a fixed spin-then-100us-sleep cycle (which
     * repeated forever and kept the thread mostly spinning) with a real
     * escalation: spin briefly, then sleep for increasingly longer
     * intervals up to PLOG_IDLE_SLEEP_MAX_NS while traffic stays idle. */
    uint64_t idle_cycles = 0;
    long sleep_ns = PLOG_IDLE_SLEEP_MIN_NS;

    while (atomic_load_explicit(&lg->drain_running, memory_order_relaxed)) {
        bool had_work = false;

        for (size_t i = 0; i < PLOG_NUM_SHARDS; i++) {
            PlogShard* s = lg->shards[i];

            uint64_t cons = atomic_load_explicit(&s->cons_seq, memory_order_relaxed);
            uint64_t prod = atomic_load_explicit(&s->prod_seq, memory_order_acquire);

            if (cons == prod) continue;
            had_work = true;

            while (cons < prod) {
                const PlogEvent* ev = &s->ring[cons & (PLOG_SHARD_CAPACITY - 1)];

                buf_pos += plog__format_line(write_buf + buf_pos, ev);
                cons++;

                if (buf_pos >= sizeof(write_buf) - 512) {
                    plog__write_all(lg->out_fd, write_buf, buf_pos);
                    buf_pos = 0;
                }
            }

            atomic_store_explicit(&s->cons_seq, cons, memory_order_release);
        }

        if (!had_work) {
            if (buf_pos > 0) {
                plog__write_all(lg->out_fd, write_buf, buf_pos);
                buf_pos = 0;
            }

            idle_cycles++;

            if (idle_cycles <= PLOG_IDLE_SPIN_LIMIT) {
                /* Short idle gap: spin for low-latency pickup of new work. */
                plog__cpu_relax();
            } else {
                /* Sustained idle period: back off with exponentially
                 * growing sleeps, capped at PLOG_IDLE_SLEEP_MAX_NS, so the
                 * thread stops consuming CPU while there is no traffic. */
                plog__backoff_sleep(sleep_ns);
                if (sleep_ns < PLOG_IDLE_SLEEP_MAX_NS) {
                    sleep_ns *= 2;
                    if (sleep_ns > PLOG_IDLE_SLEEP_MAX_NS) {
                        sleep_ns = PLOG_IDLE_SLEEP_MAX_NS;
                    }
                }
            }
        } else {
            idle_cycles = 0;
            sleep_ns = PLOG_IDLE_SLEEP_MIN_NS;
        }
    }

    /* Shutdown Flush */
    for (size_t i = 0; i < PLOG_NUM_SHARDS; i++) {
        PlogShard* s = lg->shards[i];
        uint64_t cons = atomic_load_explicit(&s->cons_seq, memory_order_relaxed);
        uint64_t prod = atomic_load_explicit(&s->prod_seq, memory_order_acquire);

        while (cons < prod) {
            const PlogEvent* ev = &s->ring[cons & (PLOG_SHARD_CAPACITY - 1)];
            buf_pos += plog__format_line(write_buf + buf_pos, ev);
            cons++;

            if (buf_pos >= sizeof(write_buf) - 512) {
                plog__write_all(lg->out_fd, write_buf, buf_pos);
                buf_pos = 0;
            }
        }
        atomic_store_explicit(&s->cons_seq, cons, memory_order_release);
    }

    if (buf_pos > 0) {
        plog__write_all(lg->out_fd, write_buf, buf_pos);
    }

    return NULL;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

static inline bool plog_init(PlogState* lg, int out_fd) {
    memset(lg, 0, sizeof(*lg));
    lg->out_fd = out_fd;
    atomic_store_explicit(&lg->shard_allocator, 0, memory_order_relaxed);
    atomic_store_explicit(&lg->drain_running, true, memory_order_release);

    for (size_t i = 0; i < PLOG_NUM_SHARDS; i++) {
        void* ptr = NULL;
        if (posix_memalign(&ptr, 64, sizeof(PlogShard)) != 0 || !ptr) {
            for (size_t j = 0; j < i; j++) free(lg->shards[j]);
            return false;
        }
        memset(ptr, 0, sizeof(PlogShard));
        lg->shards[i] = (PlogShard*)ptr;
    }

    if (thread_create(&lg->thread_handle, plog__drain_thread, lg) != 0) {
        for (size_t i = 0; i < PLOG_NUM_SHARDS; i++) free(lg->shards[i]);
        return false;
    }
    return true;
}

static inline void plog__submit_shard(PlogShard* s, const PlogEvent* ev) {
    uint64_t prod = atomic_load_explicit(&s->prod_seq, memory_order_relaxed);

    /* Backpressure check */
    if (__builtin_expect((prod - s->cached_cons) >= (uint64_t)PLOG_SHARD_CAPACITY, 0)) {
        s->cached_cons = atomic_load_explicit(&s->cons_seq, memory_order_acquire);

        /* Bounded spin count before falling back to sleeping. This keeps
         * the fast path (drain thread catching up quickly) low-latency
         * while ensuring a stalled or dead drain thread cannot pin this
         * worker thread at 100% CPU forever. */
        unsigned spins = 0;

        while ((prod - s->cached_cons) >= (uint64_t)PLOG_SHARD_CAPACITY) {
#if PLOG_LOSSLESS
            /* Security/lossless mode: never drop audit events. Spin briefly,
             * then sleep in short increments while waiting for the drain
             * thread to free up ring slots. */
            if (spins < PLOG_BACKPRESSURE_SPIN_LIMIT) {
                plog__cpu_relax();
                spins++;
            } else {
                plog__backoff_sleep(PLOG_BACKPRESSURE_SLEEP_NS);
            }
            s->cached_cons = atomic_load_explicit(&s->cons_seq, memory_order_acquire);
#else
            /* Lossy fallback */
            atomic_fetch_add_explicit(&s->drops, 1, memory_order_relaxed);
            return;
#endif
        }
    }

    s->ring[prod & (PLOG_SHARD_CAPACITY - 1)] = *ev;
    atomic_store_explicit(&s->prod_seq, prod + 1, memory_order_release);
}

/**
 * Hot path: sub-5ns lock-free submission on the worker thread.
 */
static inline void plog_submit(PlogState* lg, const PlogEvent* ev) {
    static PLOG_THREAD_LOCAL int tl_shard_idx = -1;

    if (__builtin_expect(tl_shard_idx < 0, 0)) {
        tl_shard_idx =
            (int)(atomic_fetch_add_explicit(&lg->shard_allocator, 1, memory_order_relaxed) %
                  PLOG_NUM_SHARDS);
    }

    plog__submit_shard(lg->shards[tl_shard_idx], ev);
}

static inline void plog_submit_worker(PlogState* lg, int worker_id, const PlogEvent* ev) {
    if (__builtin_expect((unsigned)worker_id >= (unsigned)PLOG_NUM_SHARDS, 0)) {
        worker_id = (int)((unsigned)worker_id % (unsigned)PLOG_NUM_SHARDS);
    }
    plog__submit_shard(lg->shards[worker_id], ev);
}

static inline void plog_destroy(PlogState* lg) {
    atomic_store_explicit(&lg->drain_running, false, memory_order_release);
    thread_join(lg->thread_handle, NULL);
    for (size_t i = 0; i < PLOG_NUM_SHARDS; i++) {
        if (lg->shards[i]) {
            free(lg->shards[i]);
            lg->shards[i] = NULL;
        }
    }
}

static inline uint64_t plog_drop_count(const PlogState* lg) {
    uint64_t total = 0;
    for (size_t i = 0; i < PLOG_NUM_SHARDS; i++) {
        total +=
            atomic_load_explicit((_Atomic uint64_t*)&lg->shards[i]->drops, memory_order_relaxed);
    }
    return total;
}

#endif /* PLOG_H */
