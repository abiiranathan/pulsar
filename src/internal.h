#ifndef PULSAR_INTERNAL_H
#define PULSAR_INTERNAL_H

/*
 * Internal cross-translation-unit declarations for the pulsar runtime.
 *
 * This header is NOT part of the public API. It exposes the symbols that
 * the split source files exchange, plus the small amount of shared state
 * that used to live as file-local statics in the monolithic pulsar.c.
 *
 * Convention: hot-path helpers stay `INLINE` in the .c file that owns them;
 * only the state they read and the cold/registration entry points are
 * exported here. Writable state is declared `extern` and defined in exactly
 * one .c file so a multi-TU build cannot silently duplicate it.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#include "../include/events.h"
#include "../include/pulsar.h"
#include "../include/pulsar_syscall.h"
#include "fastparse.h"
#include "keepalive.h"
#include "plog.h"
#include "pulsar_time.h"

/* Enforce that the response header block never spills into the inline body
 * staging area. Kept as a macro so every header writer inlines the check. */
#define ensure_headers_capacity(res, required) \
    ASSERT(((size_t)(res)->headers_len) + (required) < RESP_BODY_OFFSET);

/* ----------------------------------------------------------------
 * Connection lifecycle (connection.c)
 * ---------------------------------------------------------------- */

void free_response_body(response_t* resp);
bool init_connection(PulsarConn* conn, Arena* arena, int client_fd, int worker_id);
bool reset_connection(PulsarConn* conn);

/* close_connection() is declared in keepalive.h (it is part of the
 * keep-alive teardown contract). */

/* ----------------------------------------------------------------
 * Request parsing helpers (request.c)
 * ---------------------------------------------------------------- */

void ensure_headers_parsed(PulsarConn* conn);

/* ----------------------------------------------------------------
 * Date header cache (date.c)
 *
 * snapshot_date_header() is hot and lives in the core TU (server.c); the
 * state it snapshots from is owned by date.c.
 * ---------------------------------------------------------------- */

#define DATE_HDR_MAX 128

typedef struct __attribute__((aligned(64))) {
    char data[DATE_HDR_MAX];
    uint16_t len;
} DateSlot;

extern uint16_t g_date_hdr_len;
extern DateSlot g_date_slots[2];
extern _Atomic int g_date_cur;
extern _Atomic uint32_t g_date_gen;
extern _Atomic unsigned g_date_refresh_sec;

void refresh_date_header_now(void);
void* date_updater_thread(void* arg);

/* ----------------------------------------------------------------
 * Middleware registry (middleware.c)
 *
 * execute_all_middleware() runs on the request path and is kept INLINE in
 * server.c, so the registry itself is exported.
 * ---------------------------------------------------------------- */

extern HttpHandler global_middleware[MAX_GLOBAL_MIDDLEWARE];
extern size_t global_mw_count;
extern void* g_handler_userdata;

/* ----------------------------------------------------------------
 * Async logger state (logging.c)
 *
 * request_complete() runs on the hot path and stays INLINE in server.c, so
 * the callback pointer is exported.
 * ---------------------------------------------------------------- */

extern PulsarCallback LOGGER_CALLBACK;

/* ----------------------------------------------------------------
 * Slow worker pool (slowworker.c)
 *
 * The struct is exported because pulsar_run() (server.c) owns thread
 * creation/join for the pool.
 * ---------------------------------------------------------------- */

#if ENABLE_SLOW_WORKERS
typedef struct SlowWorker {
    pthread_t thread;
    event_queue_t queue;
    int id;
    KeepAliveState ka_state;
} SlowWorker;

extern SlowWorker slow_workers[NUM_SLOW_WORKERS];
void* slow_worker_thread(void* arg);
#endif

#endif /* PULSAR_INTERNAL_H */
