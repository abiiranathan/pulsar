#include "internal.h"

#define SERVER_NAME "PULSAR/1.0 (Unix)"

/* ================================================================
 * TSC / Wall-clock Calibration Anchors
 *
 * Declared extern in pulsar_time.h; defined here (the time-domain TU) so
 * every translation unit shares the same anchors.
 * ================================================================ */

ALIGN(64) uint64_t g_tsc_mult = 0;
ALIGN(64) uint64_t g_tsc_base_cycles = 0;
ALIGN(64) uint64_t g_tsc_base_ns = 0;
ALIGN(64) uint64_t g_wall_base_ns = 0;

/* ================================================================
 * Preformatted Date Header Cache
 * ================================================================ */

static const char DAYS[7][5] = {"Sun,", "Mon,", "Tue,", "Wed,", "Thu,", "Fri,", "Sat,"};
static const char MONTHS[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/* Fixed for the process lifetime. Valid only because SERVER_NAME is a
 * compile-time constant and DAYS[]/MONTHS[]/the %02d/%04d fields are all
 * fixed-width — format_date_header() therefore always produces the same
 * length. If SERVER_NAME ever becomes runtime-configurable, this must be
 * recomputed in publish_date_header() on every refresh, not just at startup. */
ALIGN(64) uint16_t g_date_hdr_len = 0;

ALIGN(64) DateSlot g_date_slots[2];
ALIGN(64) _Atomic int g_date_cur = 0;
ALIGN(64) _Atomic uint32_t g_date_gen = 0;
ALIGN(64) _Atomic unsigned g_date_refresh_sec = PULSAR_DATE_REFRESH_SEC;

/* Condvar for prompt wake on interval change or shutdown, replacing the
 * previous 100 ms poll loop. Reduces idle wakeups from a fixed 10/sec to
 * one per refresh interval, with immediate response to
 * pulsar_set_date_refresh_interval() or shutdown instead of waiting out
 * a stale 100 ms slice.
 * NOTE: whatever code sets server_running = 0 must also signal
 * g_date_cv, or date_updater_thread will sleep out its current
 * deadline (up to 86400s) before checking server_running again. */
static pthread_mutex_t g_date_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_date_cv = PTHREAD_COND_INITIALIZER;

void pulsar_set_date_refresh_interval(unsigned seconds) {
    if (seconds < 1) seconds = 1;
    if (seconds > 86400) seconds = 86400;
    atomic_store_explicit(&g_date_refresh_sec, seconds, memory_order_relaxed);

    /* Wake the updater thread immediately so a shortened interval takes
     * effect right away rather than after the previous deadline elapses. */
    pthread_mutex_lock(&g_date_mu);
    pthread_cond_signal(&g_date_cv);
    pthread_mutex_unlock(&g_date_mu);
}

unsigned pulsar_get_date_refresh_interval(void) {
    return atomic_load_explicit(&g_date_refresh_sec, memory_order_relaxed);
}

/* Fixed prefix and suffix; formatted once so publish_date_header()/
 * refresh_date_header_now() need only fill the date field. Avoids
 * snprintf's format-string parsing on every refresh (measured ~6x
 * faster on this build/CPU: ~75 vs ~447 cycles/call for the full header). */
static const char DATE_HDR_PREFIX[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: " SERVER_NAME
    "\r\n"
    "Date: ";
static const size_t DATE_HDR_PREFIX_LEN = sizeof(DATE_HDR_PREFIX) - 1;
static const char DATE_HDR_SUFFIX[] = " GMT\r\n";
static const size_t DATE_HDR_SUFFIX_LEN = sizeof(DATE_HDR_SUFFIX) - 1;

/* Write a 2-digit zero-padded field. Returns p advanced by 2. */
static inline char* put_u2(char* p, int v) {
    p[0] = (char)('0' + (v / 10) % 10);
    p[1] = (char)('0' + v % 10);
    return p + 2;
}

/* Write a 4-digit zero-padded field. Returns p advanced by 4. */
static inline char* put_u4(char* p, int v) {
    p[0] = (char)('0' + (v / 1000) % 10);
    p[1] = (char)('0' + (v / 100) % 10);
    p[2] = (char)('0' + (v / 10) % 10);
    p[3] = (char)('0' + v % 10);
    return p + 4;
}

/* Format the shared prefix for wall-clock second t into buf.
 * Returns formatted length, or 0 on failure. */
static int format_date_header(time_t t, char* buf, size_t cap) {
    struct tm tm;
    if (gmtime_r(&t, &tm) == NULL) return 0;
    if (tm.tm_wday < 0 || tm.tm_wday > 6) return 0;
    if (tm.tm_mon < 0 || tm.tm_mon > 11) return 0;

    /* Single prebuilt prefix: status line + Server + Date. Copied with one
     * memcpy per request in process_request, saving separate status stores.
     * Fixed-width date field: "Www DD Mon YYYY HH:MM:SS". */
    const size_t date_field_len = 4 + 1 + 2 + 1 + 3 + 1 + 4 + 1 + 2 + 1 + 2 + 1 + 2;
    const size_t total = DATE_HDR_PREFIX_LEN + date_field_len + DATE_HDR_SUFFIX_LEN;
    if (total >= cap) return 0;

    char* p = buf;
    memcpy(p, DATE_HDR_PREFIX, DATE_HDR_PREFIX_LEN);
    p += DATE_HDR_PREFIX_LEN;

    memcpy(p, DAYS[tm.tm_wday], 4);
    p += 4;
    *p++ = ' ';
    p = put_u2(p, tm.tm_mday);
    *p++ = ' ';
    memcpy(p, MONTHS[tm.tm_mon], 3);
    p += 3;
    *p++ = ' ';
    p = put_u4(p, tm.tm_year + 1900);
    *p++ = ' ';
    p = put_u2(p, tm.tm_hour);
    *p++ = ':';
    p = put_u2(p, tm.tm_min);
    *p++ = ':';
    p = put_u2(p, tm.tm_sec);

    memcpy(p, DATE_HDR_SUFFIX, DATE_HDR_SUFFIX_LEN);
    p += DATE_HDR_SUFFIX_LEN;

    return (int)(p - buf);
}

/* Single-writer publish: format into the inactive slot, then flip the
 * active index with a release store. Called only by the date thread
 * (and once synchronously at startup). Bumps g_date_gen last so readers
 * that observe the new generation are guaranteed to observe the new
 * index + slot contents. */
static void publish_date_header(time_t t) {
    int cur = atomic_load_explicit(&g_date_cur, memory_order_relaxed);
    if ((unsigned)cur > 1u) cur = 0;
    int inactive = cur ^ 1;

    char buf[DATE_HDR_MAX];
    int n = format_date_header(t, buf, sizeof(buf));
    if (n <= 0) return;

    memcpy(g_date_slots[inactive].data, buf, (size_t)n);
    g_date_slots[inactive].len = (uint16_t)n;
    atomic_store_explicit(&g_date_cur, inactive, memory_order_release);
    atomic_fetch_add_explicit(&g_date_gen, 1u, memory_order_release);
}

void refresh_date_header_now(void) {
    char buf[DATE_HDR_MAX];
    int n = format_date_header(pulsar_wall_sec(), buf, sizeof(buf));
    if (n <= 0) return;

    g_date_hdr_len = (uint16_t)n; /* fixed length for the process lifetime */
    memcpy(g_date_slots[0].data, buf, (size_t)n);
    g_date_slots[0].len = (uint16_t)n;
    memcpy(g_date_slots[1].data, buf, (size_t)n);
    g_date_slots[1].len = (uint16_t)n;
    atomic_store_explicit(&g_date_cur, 0, memory_order_release);
    /* Start at 1; per-connection date_gen == 0 means "nothing staged". */
    atomic_store_explicit(&g_date_gen, 1u, memory_order_release);
}

/* Background thread: refresh the cached header every N seconds.
 * Waits on a condvar with a deadline instead of polling in 100 ms
 * slices, so shutdown via server_running and interval changes via
 * pulsar_set_date_refresh_interval() are both immediate rather than
 * bounded by a fixed poll granularity. Re-reads the interval each tick
 * so pulsar_set_date_refresh_interval() takes effect without a restart. */
void* date_updater_thread(void* arg) {
    (void)arg;
    time_t last = 0;

    while (server_running) {
        unsigned interval = atomic_load_explicit(&g_date_refresh_sec, memory_order_relaxed);
        if (interval < 1) interval = 1;

        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += interval;

        pthread_mutex_lock(&g_date_mu);
        if (server_running) {
            /* Return value is ignored: whether this wakes on the
             * deadline, a signal, or spuriously, the loop below
             * re-checks server_running and re-reads the interval,
             * so no branch on rc is needed. */
            pthread_cond_timedwait(&g_date_cv, &g_date_mu, &deadline);
        }
        pthread_mutex_unlock(&g_date_mu);

        if (!server_running) break;

        time_t now = pulsar_wall_sec();
        if (now == last) continue;
        last = now;
        publish_date_header(now);
    }
    return NULL;
}
