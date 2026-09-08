/**
 * bench_plog.c — Producer-side throughput/latency benchmark for plog.h.
 *
 * Measures plog_submit() cost under concurrent load without needing an
 * HTTP server or wrk: N producer threads call plog_submit() in a tight
 * loop for a fixed duration, each recording its own per-call latency in
 * a preallocated histogram (no locking, no malloc on the measured path).
 *
 * Usage:
 *   ./bench_plog [threads] [seconds] [out_fd_path]
 *
 *   threads      Number of concurrent producer threads (default: 8)
 *   seconds      Benchmark duration in seconds (default: 5)
 *   out_fd_path  Where plog's drain thread writes formatted lines
 *                (default: /dev/null, so drain I/O never becomes the
 *                bottleneck being measured — pass a real path if you
 *                specifically want to study drain-side I/O cost)
 *
 * Build (see build.sh for full flags):
 *   cc -O2 -march=native -pthread bench_plog.c -o bench_plog
 *
 * Analyze with perf (no wrk needed):
 *   perf stat -e task-clock,context-switches,cache-misses,cache-references,\
 *       instructions,cycles,branch-misses ./bench_plog 8 5
 *
 *   perf record -F 999 -g -- ./bench_plog 8 5
 *   perf report
 *
 * @note This measures plog_submit() cost in isolation. It intentionally
 *       does not model a real request (no parsing, no I/O on the producer
 *       side) — that is the point: it isolates the logger's own overhead
 *       from everything else a request handler does, so perf attributes
 *       samples to plog_submit()/plog__submit_shard() specifically rather
 *       than mixing them with unrelated server code.
 */

#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "plog.h"

/** Per-thread sample cap. Bounds memory; oldest samples are simply not
 *  overwritten once full (the count kept is used, not clamped away, when
 *  reporting so percentiles remain honest about how many were captured). */
#define BENCH_MAX_SAMPLES_PER_THREAD (1u << 22) /* 4,194,304 samples/thread */

/** Only 1-in-SAMPLE_STRIDE calls are timestamped. At the latency scale
 *  plog_submit() runs at (tens of ns), timing every call would measure
 *  clock_gettime()'s own cost as much as the function's — confirmed via
 *  perf, where __vdso_clock_gettime showed ~7.5% of total cycles when
 *  every call was timed. Sampling keeps percentiles representative while
 *  keeping instrumentation overhead a small fraction of cycles spent. */
#define SAMPLE_STRIDE_REPORT 8

/** Shared configuration read-only after setup; avoids passing many args
 *  through pthread's single void* per thread. */
typedef struct {
    PlogState* logger;
    int num_threads;
    double duration_sec;
    _Atomic bool start_flag; /* release-gates all threads to begin together */
    _Atomic bool stop_flag;  /* set by main() after duration_sec elapses    */
} BenchConfig;

/** Per-thread result, filled in by the thread itself and read by main()
 *  only after pthread_join() (no concurrent access, no atomics needed). */
typedef struct {
    uint64_t* latencies_ns;   /* sampled subset of plog_submit() calls timed */
    uint64_t count;           /* number of entries actually filled in latencies_ns */
    uint64_t capacity;        /* size of the latencies_ns allocation           */
    uint64_t total_submitted; /* every plog_submit() call this thread made,
                               * timed or not — the real throughput count */
} BenchResult;

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/** Builds a representative PlogEvent so plog_submit() copies a realistic
 *  payload size rather than an all-zero struct (which some memcpy paths
 *  could special-case away under aggressive optimization). */
static void make_sample_event(PlogEvent* ev, uint32_t iteration) {
    memset(ev, 0, sizeof(*ev));
    ev->total_ns = 1000 + (iteration % 50000); /* varies latency-format branch taken */
    ev->status_code = (uint16_t)(200 + (iteration % 4) * 100);
    memcpy(ev->method, "GET", 3);
    snprintf(ev->path, PLOG_PATH_MAX, "/api/v1/resource/%u", iteration % 1000);
    memcpy(ev->user_agent, "bench-agent/1.0", 15);
}

typedef struct {
    BenchConfig* cfg;
    BenchResult* result;
    int thread_index;
} ThreadArg;

static void* producer_thread(void* arg) {
    ThreadArg* targ = (ThreadArg*)arg;
    BenchConfig* cfg = targ->cfg;
    BenchResult* res = targ->result;

    /* Wait for the synchronized start so all threads ramp up together,
     * giving perf a clean, fully-loaded steady-state window to sample. */
    while (!atomic_load_explicit(&cfg->start_flag, memory_order_acquire)) {
        /* spin; this is setup, not part of the measured window */
    }

    uint32_t iter = 0;
    PlogEvent ev;

    /* Every call counts toward throughput regardless of whether it is
     * timed; only a sampled subset is timestamped, since clock_gettime()
     * itself costs a meaningful fraction of a ~40ns plog_submit() call and
     * timing every single call would measure the timer more than the
     * function. Sampling 1-in-SAMPLE_STRIDE_REPORT keeps the latency
     * percentiles representative while keeping instrumentation overhead a
     * small fraction of total cycles spent. */
    uint64_t total_submitted = 0;

    while (!atomic_load_explicit(&cfg->stop_flag, memory_order_relaxed)) {
        make_sample_event(&ev, iter++);

        if (iter % SAMPLE_STRIDE_REPORT == 0 && res->count < res->capacity) {
            uint64_t t0 = now_ns();
            plog_submit(cfg->logger, &ev);
            uint64_t t1 = now_ns();
            res->latencies_ns[res->count++] = t1 - t0;
        } else {
            plog_submit(cfg->logger, &ev);
        }
        total_submitted++;
        /* Latency recording stops once res->capacity sampled entries are
         * collected (still generously sized above realistic sampled
         * counts for the default duration), but total_submitted keeps
         * counting every call for the whole run, so throughput reporting
         * is never truncated by the sampling cap. */
    }

    res->total_submitted = total_submitted;
    return NULL;
}

static int cmp_u64(const void* a, const void* b) {
    uint64_t ua = *(const uint64_t*)a, ub = *(const uint64_t*)b;
    return (ua > ub) - (ua < ub);
}

static uint64_t percentile(uint64_t* sorted, uint64_t n, double p) {
    if (n == 0) return 0;
    double rank = p * (double)(n - 1);
    uint64_t lo = (uint64_t)floor(rank);
    uint64_t hi = (uint64_t)ceil(rank);
    if (hi >= n) hi = n - 1;
    double frac = rank - (double)lo;
    return (uint64_t)((double)sorted[lo] * (1.0 - frac) + (double)sorted[hi] * frac);
}

int main(int argc, char** argv) {
    int num_threads = (argc > 1) ? atoi(argv[1]) : 8;
    double duration_sec = (argc > 2) ? atof(argv[2]) : 5.0;
    const char* out_path = (argc > 3) ? argv[3] : "/dev/null";

    if (num_threads <= 0) {
        fprintf(stderr, "error: thread count must be positive, got %d\n", num_threads);
        return EXIT_FAILURE;
    }
    if (duration_sec <= 0.0) {
        fprintf(stderr, "error: duration must be positive, got %f\n", duration_sec);
        return EXIT_FAILURE;
    }

    int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("open(out_path)");
        return EXIT_FAILURE;
    }

    PlogState logger;
    if (!plog_init(&logger, out_fd)) {
        fprintf(stderr, "error: plog_init failed\n");
        close(out_fd);
        return EXIT_FAILURE;
    }

    BenchConfig cfg = {
        .logger = &logger,
        .num_threads = num_threads,
        .duration_sec = duration_sec,
        .start_flag = false,
        .stop_flag = false,
    };

    pthread_t* threads = calloc((size_t)num_threads, sizeof(pthread_t));
    ThreadArg* targs = calloc((size_t)num_threads, sizeof(ThreadArg));
    BenchResult* results = calloc((size_t)num_threads, sizeof(BenchResult));
    if (!threads || !targs || !results) {
        fprintf(stderr, "error: allocation failure setting up %d threads\n", num_threads);
        free(threads);
        free(targs);
        free(results);
        plog_destroy(&logger);
        close(out_fd);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < num_threads; i++) {
        results[i].capacity = BENCH_MAX_SAMPLES_PER_THREAD;
        results[i].latencies_ns = malloc(results[i].capacity * sizeof(uint64_t));
        if (!results[i].latencies_ns) {
            fprintf(stderr, "error: failed to allocate latency buffer for thread %d\n", i);
            for (int j = 0; j < i; j++) free(results[j].latencies_ns);
            free(threads);
            free(targs);
            free(results);
            plog_destroy(&logger);
            close(out_fd);
            return EXIT_FAILURE;
        }
        results[i].count = 0;
        targs[i] = (ThreadArg){.cfg = &cfg, .result = &results[i], .thread_index = i};
    }

    printf("plog_submit() benchmark: %d threads, %.1fs, out_fd=%s\n", num_threads, duration_sec,
           out_path);

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, producer_thread, &targs[i]) != 0) {
            fprintf(stderr, "error: pthread_create failed for thread %d\n", i);
            /* Signal any already-started threads to stop and unwind cleanly
             * rather than leaking them or leaving stop_flag unset. */
            atomic_store_explicit(&cfg.stop_flag, true, memory_order_release);
            atomic_store_explicit(&cfg.start_flag, true, memory_order_release);
            for (int j = 0; j < i; j++) pthread_join(threads[j], NULL);
            for (int j = 0; j < num_threads; j++) free(results[j].latencies_ns);
            free(threads);
            free(targs);
            free(results);
            plog_destroy(&logger);
            close(out_fd);
            return EXIT_FAILURE;
        }
    }

    /* Release all producer threads together so the measured window is a
     * clean, fully-concurrent steady state — useful for perf record, which
     * benefits from a stable, saturated workload rather than a ramp-up. */
    uint64_t t_start = now_ns();
    atomic_store_explicit(&cfg.start_flag, true, memory_order_release);

    struct timespec sleep_ts = {
        .tv_sec = (time_t)duration_sec,
        .tv_nsec = (long)((duration_sec - (double)(time_t)duration_sec) * 1e9),
    };
    nanosleep(&sleep_ts, NULL);

    atomic_store_explicit(&cfg.stop_flag, true, memory_order_release);
    uint64_t t_end = now_ns();

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    double wall_sec = (double)(t_end - t_start) / 1e9;
    uint64_t total_submitted = 0;
    uint64_t total_sampled = 0;
    for (int i = 0; i < num_threads; i++) {
        total_submitted += results[i].total_submitted;
        total_sampled += results[i].count;
    }

    /* Merge all threads' SAMPLED latency entries into one array for
     * aggregate percentiles. Fine to allocate here: this happens after the
     * measured window closes, so it cannot perturb the benchmark itself.
     * Note this array holds total_sampled entries, not total_submitted —
     * percentiles are computed over the sampled subset, while throughput
     * below is computed over every call that was actually made. */
    uint64_t* merged = malloc(total_sampled * sizeof(uint64_t));
    if (!merged) {
        fprintf(stderr, "error: failed to allocate %" PRIu64 " entries for merged results\n",
                total_sampled);
        for (int i = 0; i < num_threads; i++) free(results[i].latencies_ns);
        free(threads);
        free(targs);
        free(results);
        plog_destroy(&logger);
        close(out_fd);
        return EXIT_FAILURE;
    }
    uint64_t pos = 0;
    for (int i = 0; i < num_threads; i++) {
        memcpy(merged + pos, results[i].latencies_ns, results[i].count * sizeof(uint64_t));
        pos += results[i].count;
    }
    qsort(merged, total_sampled, sizeof(uint64_t), cmp_u64);

    double req_per_sec = (double)total_submitted / wall_sec;
    uint64_t drops = plog_drop_count(&logger);

    printf("\n--- Results ---\n");
    printf("Wall time:        %.3f s\n", wall_sec);
    printf("Total submits:    %" PRIu64 " (latency sampled on %" PRIu64 " of them)\n",
           total_submitted, total_sampled);
    printf("Throughput:       %.0f submits/sec\n", req_per_sec);
    printf("Dropped (if any): %" PRIu64 "\n", drops);
    printf("\nplog_submit() latency distribution (ns, sampled 1-in-%u calls):\n",
           SAMPLE_STRIDE_REPORT);
    printf("  p50:  %" PRIu64 "\n", percentile(merged, total_sampled, 0.50));
    printf("  p75:  %" PRIu64 "\n", percentile(merged, total_sampled, 0.75));
    printf("  p90:  %" PRIu64 "\n", percentile(merged, total_sampled, 0.90));
    printf("  p99:  %" PRIu64 "\n", percentile(merged, total_sampled, 0.99));
    printf("  p999: %" PRIu64 "\n", percentile(merged, total_sampled, 0.999));
    printf("  max:  %" PRIu64 "\n", merged[total_sampled - 1]);

    if (drops > 0) {
        printf(
            "\nNOTE: drop count is non-zero, which should not happen with "
            "PLOG_LOSSLESS=1 unless the drop path was compiled out — if you "
            "see drops here, check PLOG_LOSSLESS is actually 1 in this "
            "build, since lossless mode should spin rather than drop.\n");
    }

    /* Flush and drain fully before reporting completion, so 'perf stat'
     * wall-clock numbers for the whole process include drain-thread
     * teardown rather than looking artificially short. */
    plog_destroy(&logger);
    close(out_fd);

    free(merged);
    for (int i = 0; i < num_threads; i++) free(results[i].latencies_ns);
    free(threads);
    free(targs);
    free(results);

    return EXIT_SUCCESS;
}
