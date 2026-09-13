#include "internal.h"

/* ================================================================
 * Asynchronous Request Logger
 * ================================================================ */

ALIGN(64) static PlogState PLOG_STATE;
ALIGN(64) static int LOG_FD = -1;
/* Non-static: request_complete() on the core request path reads it. */
ALIGN(64) PulsarCallback LOGGER_CALLBACK = NULL;

bool pulsar_set_callback(PulsarCallback cb, int fd) {
#if ENABLE_LOGGING
    if ((LOGGER_CALLBACK && cb) || (LOG_FD != -1 && fd != -1)) {
        LOG_ERROR("Pulsar callback already set. Only one callback can be registered.");
        return false;
    }
    LOGGER_CALLBACK = cb;
    LOG_FD = fd;
    return plog_init(&PLOG_STATE, LOG_FD);
#else
    (void)cb;
    (void)fd;
    (void)PLOG_STATE;
    (void)LOG_FD;
    (void)LOGGER_CALLBACK;
    return true;
#endif
}

__attribute__((destructor)) void cleanup_logger(void) {
#if ENABLE_LOGGING
    if (LOG_FD != -1) {
        uint64_t drops = plog_drop_count(&PLOG_STATE);
        if (drops > 0) {
            fprintf(stderr,
                    "[Pulsar] Warning: Dropped %" PRIu64 " log entries due to backpressure.\n",
                    drops);
        }
        plog_destroy(&PLOG_STATE);
        LOG_FD = -1;
    }
#endif
}

INLINE void copy_str(char* restrict dest, size_t dest_size, const char* restrict src) {
    size_t len = strlen(src);
    size_t copy_len = len < dest_size - 1 ? len : dest_size - 1;
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
}

void pulsar_logger(PulsarCtx* ctx, uint64_t total_ns) {
    PulsarConn* conn = ctx->conn;

    PlogEvent ev;
    ev.total_ns = total_ns;
    ev.status_code = conn->response.status_code;
    const char* method = conn->request.method;
    const char* path = conn->request.path;
    const char* user_agent = req_header_get(conn, "User-Agent");

    ASSERT(method && path && "method and path must not be NULL");

    copy_str(ev.method, sizeof(ev.method), method);
    copy_str(ev.path, sizeof(ev.path), path);
    copy_str(ev.user_agent, sizeof(ev.user_agent), user_agent ? user_agent : "-");

    plog_submit(&PLOG_STATE, &ev);
}
