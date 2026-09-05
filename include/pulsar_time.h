#ifndef PULSAR_TIME_H
#define PULSAR_TIME_H

#include <errno.h>
#include <stdint.h>
#include <time.h>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

/* Precomputed fixed-point scale factor: (ns << 32) / cycles.
 * When 0, calibration failed / not yet run: pulsar_now_ns() falls back
 * to clock_gettime(CLOCK_MONOTONIC) so time never garbage-crashes. */
extern uint64_t g_tsc_mult;
extern uint64_t g_tsc_base_cycles;
/* Monotonic nanoseconds (CLOCK_MONOTONIC) at calibration. Basis for
 * pulsar_now_ns() and all timeout / duration math. */
extern uint64_t g_tsc_base_ns;
/* Wall-clock nanoseconds (CLOCK_REALTIME) captured at the same instant as
 * g_tsc_base_ns. Basis for HTTP Date headers via pulsar_wall_sec(). */
extern uint64_t g_wall_base_ns;

/* -------------------------------------------------------------------------
 * Hardware Cycle Counter (1 instruction, ~1-2 ns)
 * ---------------------------------------------------------------------- */
static inline uint64_t pulsar_rdtsc(void) {
#if defined(__x86_64__) || defined(__i386__)
    return __rdtsc();
#elif defined(__aarch64__)
    uint64_t val;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/* -------------------------------------------------------------------------
 * Absolute Monotonic Nanoseconds (~3 ns, 0 syscalls)
 * Safe to call every tick of the event loop.
 * ---------------------------------------------------------------------- */
static inline uint64_t pulsar_now_ns(void) {
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__)
    if (g_tsc_mult == 0) {
        /* Uncalibrated (or calibration failed): pay the vDSO syscall
         * rather than scaling by a bogus factor. */
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
    uint64_t cycles = pulsar_rdtsc();
    /* Guard cross-core TSC skew: an unsynced core may read slightly behind
     * the calibration core. Unsigned wrap would yield ~2^64 delta and
     * garbage timestamps, so clamp to zero instead. */
    uint64_t delta = (cycles > g_tsc_base_cycles) ? (cycles - g_tsc_base_cycles) : 0;
    /* (delta * mult) >> 32 using 128-bit product (single mul instruction) */
    return g_tsc_base_ns + (uint64_t)(((unsigned __int128)delta * g_tsc_mult) >> 32);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/**
 * Monotonic seconds since boot (uptime domain). Use for keep-alive
 * timeouts and last_activity stamps: immune to NTP / wall-clock jumps.
 */
static inline time_t pulsar_mono_sec(void) { return (time_t)(pulsar_now_ns() / 1000000000ULL); }

/**
 * Wall-clock nanoseconds since the Unix epoch, derived from the TSC plus
 * the realtime anchor captured at init. Zero syscalls after calibration.
 */
static inline uint64_t pulsar_wall_ns(void) {
    if (g_wall_base_ns == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
    uint64_t now_mono = pulsar_now_ns();
    uint64_t elapsed = (now_mono > g_tsc_base_ns) ? (now_mono - g_tsc_base_ns) : 0;
    return g_wall_base_ns + elapsed;
}

/**
 * Fast Unix timestamp in seconds for HTTP Date headers.
 * Replaces time(NULL) wherever wall-clock time is required.
 */
static inline time_t pulsar_wall_sec(void) { return (time_t)(pulsar_wall_ns() / 1000000000ULL); }

/**
 * Legacy alias kept for compatibility. Returns WALL-clock seconds (Unix
 * epoch), NOT monotonic uptime. Do not use for timeouts; use
 * pulsar_mono_sec() for last_activity / conn_timedout math.
 */
static inline time_t pulsar_now_sec(void) { return pulsar_wall_sec(); }

/* Capture matching monotonic + wall anchors. Must be called right after
 * the TSC base is established so the two domains stay aligned. */
static inline void pulsar_capture_wall_anchor(void) {
    struct timespec mono, wall;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_REALTIME, &wall);
    g_tsc_base_ns = (uint64_t)mono.tv_sec * 1000000000ULL + (uint64_t)mono.tv_nsec;
    g_wall_base_ns = (uint64_t)wall.tv_sec * 1000000000ULL + (uint64_t)wall.tv_nsec;
    g_tsc_base_cycles = pulsar_rdtsc();
}

/* -------------------------------------------------------------------------
 * One-time Startup Calibration (runs before worker threads spawn)
 * ---------------------------------------------------------------------- */
static inline void pulsar_time_init(void) {
#if defined(__aarch64__)
    uint64_t freq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    if (freq == 0) {
        /* Broken counter: fall back to clock_gettime path (mult == 0). */
        g_tsc_mult = 0;
        pulsar_capture_wall_anchor();
        return;
    }
    g_tsc_mult = (uint64_t)(((unsigned __int128)1000000000ULL << 32) / freq);
    pulsar_capture_wall_anchor();
    /* Re-anchor the cycle base after the two clock reads so delta starts at 0. */
    g_tsc_base_cycles = pulsar_rdtsc();
#elif defined(__x86_64__) || defined(__i386__)
    uint64_t elapsed_cycles = 0;
    int64_t elapsed_ns = 0;
    struct timespec t0, t1;
    uint64_t c0 = 0, c1 = 0;

    /* Retry so an EINTR-interrupted (or VM-stalled) 10 ms sleep that yields
     * c1 == c0 can never cause a divide-by-zero SIGFPE. */
    for (int attempt = 0; attempt < 3; attempt++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        c0 = pulsar_rdtsc();

        /* 10ms sleep to calibrate CPU crystal frequency (EINTR-resilient). */
        struct timespec req = {.tv_sec = 0, .tv_nsec = 10000000};
        struct timespec rem;
        while (nanosleep(&req, &rem) != 0) {
            if (errno == EINTR) {
                req = rem;
            } else {
                break;
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        c1 = pulsar_rdtsc();

        elapsed_cycles = (c1 > c0) ? (c1 - c0) : 0;
        int64_t sec = (int64_t)t1.tv_sec - (int64_t)t0.tv_sec;
        int64_t nsec = (int64_t)t1.tv_nsec - (int64_t)t0.tv_nsec;
        elapsed_ns = sec * 1000000000LL + nsec;
        if (elapsed_cycles != 0 && elapsed_ns > 0) break;
        elapsed_cycles = 0; /* force retry / fallback */
    }

    if (elapsed_cycles == 0 || elapsed_ns <= 0) {
        /* Calibration failed: use clock_gettime fallback instead of crashing. */
        g_tsc_mult = 0;
        pulsar_capture_wall_anchor();
        return;
    }

    g_tsc_mult = (uint64_t)(((unsigned __int128)(uint64_t)elapsed_ns << 32) / elapsed_cycles);
    g_tsc_base_cycles = c1;
    g_tsc_base_ns = (uint64_t)t1.tv_sec * 1000000000ULL + (uint64_t)t1.tv_nsec;

    struct timespec wall;
    clock_gettime(CLOCK_REALTIME, &wall);
    g_wall_base_ns = (uint64_t)wall.tv_sec * 1000000000ULL + (uint64_t)wall.tv_nsec;
#else
    /* No TSC: anchor both domains directly. */
    g_tsc_mult = 0;
    pulsar_capture_wall_anchor();
#endif
}

#endif /* PULSAR_TIME_H */
