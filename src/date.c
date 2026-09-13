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

void pulsar_set_date_refresh_interval(unsigned seconds) {
    if (seconds < 1) seconds = 1;
    if (seconds > 86400) seconds = 86400;
    atomic_store_explicit(&g_date_refresh_sec, seconds, memory_order_relaxed);
}

unsigned pulsar_get_date_refresh_interval(void) {
    return atomic_load_explicit(&g_date_refresh_sec, memory_order_relaxed);
}

/* Format the shared prefix for wall-clock second t into buf.
 * Returns formatted length, or 0 on failure. */
static int format_date_header(time_t t, char* buf, size_t cap) {
    struct tm tm;
    if (gmtime_r(&t, &tm) == NULL) return 0;
    if (tm.tm_wday < 0 || tm.tm_wday > 6) return 0;
    if (tm.tm_mon < 0 || tm.tm_mon > 11) return 0;

    /* Single prebuilt prefix: status line + Server + Date. Copied with one
     * memcpy per request in process_request, saving separate status stores. */
    int n = snprintf(buf, cap,
                     "HTTP/1.1 200 OK\r\n"
                     "Server: " SERVER_NAME
                     "\r\n"
                     "Date: %s %02d %s %04d %02d:%02d:%02d GMT\r\n",
                     DAYS[tm.tm_wday], tm.tm_mday, MONTHS[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour,
                     tm.tm_min, tm.tm_sec);
    if (n <= 0 || n >= (int)cap) return 0;
    return n;
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
 * Sleeps in 100 ms slices so shutdown via server_running stays prompt
 * even for large intervals. Re-reads the interval each tick so
 * pulsar_set_date_refresh_interval() takes effect without a restart. */
void* date_updater_thread(void* arg) {
    (void)arg;
    time_t last = 0;
    while (server_running) {
        unsigned interval = atomic_load_explicit(&g_date_refresh_sec, memory_order_relaxed);
        if (interval < 1) interval = 1;

        unsigned slices = interval * 10u;
        for (unsigned i = 0; i < slices; i++) {
            if (!server_running) return NULL;
            usleep(100 * 1000);
        }
        if (!server_running) break;

        time_t now = pulsar_wall_sec();
        if (now == last) continue;
        last = now;
        publish_date_header(now);
    }
    return NULL;
}
