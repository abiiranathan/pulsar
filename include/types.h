#ifndef __PULSAR_TYPES_H__
#define __PULSAR_TYPES_H__

#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <solidc/arena.h>
#include <solidc/filepath.h>
#include <solidc/str_to_num.h>

#include "constants.h"
#include "headers.h"
#include "locals.h"
#include "method.h"
#include "status.h"

#define RESP_BUFFER_SIZE   4096
#define RESP_BODY_OFFSET   1024
#define RESP_BODY_CAPACITY (RESP_BUFFER_SIZE - RESP_BODY_OFFSET)

typedef enum {
    HTTP_CONTENT_TYPE_SET = (1 << 0),
    HTTP_HEADERS_WRITTEN = (1 << 1),
    HTTP_RANGE_REQUEST = (1 << 2),
    HTTP_CHUNKED_TRANSFER = (1 << 3),
    HTTP_WRITE_PENDING = (1 << 4),
    HTTP_HEAP_ALLOCATED = (1 << 5)
} bit_flags;

#define HAS_CONTENT_TYPE(flags)     (((flags) & HTTP_CONTENT_TYPE_SET) != 0)
#define HAS_HEADERS_WRITTEN(flags)  (((flags) & HTTP_HEADERS_WRITTEN) != 0)
#define HAS_RANGE_REQUEST(flags)    (((flags) & HTTP_RANGE_REQUEST) != 0)
#define HAS_CHUNKED_TRANSFER(flags) (((flags) & HTTP_CHUNKED_TRANSFER) != 0)

#define SET_CONTENT_TYPE(flags)     ((flags) |= HTTP_CONTENT_TYPE_SET)
#define SET_HEADERS_WRITTEN(flags)  ((flags) |= HTTP_HEADERS_WRITTEN)
#define SET_RANGE_REQUEST(flags)    ((flags) |= HTTP_RANGE_REQUEST)
#define SET_CHUNKED_TRANSFER(flags) ((flags) |= HTTP_CHUNKED_TRANSFER)

#define HAS_WRITE_PENDING(flags) (((flags) & HTTP_WRITE_PENDING) != 0)
#define SET_WRITE_PENDING(flags) ((flags) |= HTTP_WRITE_PENDING)
#define CLR_WRITE_PENDING(flags) ((flags) &= ~HTTP_WRITE_PENDING)

#define HAS_HEAP_ALLOCATED(flags) (((flags) & HTTP_HEAP_ALLOCATED) != 0)
#define SET_HEAP_ALLOCATED(flags) ((flags) |= HTTP_HEAP_ALLOCATED)
#define CLR_HEAP_ALLOCATED(flags) ((flags) &= (uint8_t)~HTTP_HEAP_ALLOCATED)

/* Unified HTTP Response Structure */
struct response_t {
    /* Offsets & lengths (hot) */
    uint32_t out_len;     /* Total bytes to send */
    uint32_t out_sent;    /* Bytes sent so far */
    uint32_t headers_len; /* Current end of headers in buf */
    uint32_t body_len;    /* Length of body */

    uint16_t status_code; /* HTTP status code */
    uint8_t status_len;   /* Length of status line */
    uint8_t flags;        /* Bit flags */

    /* Generation of the prebuilt Date prefix currently staged in buf[0..).
     * Matches g_date_gen when buf starts with the current global prefix,
     * else 0 (invalid). Lets keep-alive requests skip the per-request
     * memcpy entirely when the Date second hasn't rolled over. */
    uint32_t date_gen;

    /* File sending support */
    int file_fd;
    uint32_t file_size;
    int64_t file_offset;
    uint32_t range_end;

    /* Heap fallback for large bodies (> RESP_BODY_CAPACITY) */
    uint32_t body_capacity;
    uint32_t body_sent;
    union {
        uint8_t* heap;
    } body;

    /* Single buffer: status, headers and inline small body (4KB cold tail) */
    char buf[RESP_BUFFER_SIZE];
};

/* HTTP Request Structure */
struct request_t {
    /* Hot scalar metadata placed first */
    HttpMethod method_type;
    size_t content_length;
    struct route_t* route;
    /* Raw header block for lazy parsing. The hot path (safe method,
     * non-static route) skips table fill + Content-Length/Range scans and
     * only extracts keep-alive; the full parse is materialized on first
     * header access via ensure_headers_parsed(). Slices point into the
     * worker read buffer with the same lifetime as the eager table had. */
    const char* hdr_data;
    size_t hdr_len_raw;
    bool headers_parsed;
    char method[8];
    char* body;
    StrSlice range_hdr;

    headers_t headers;
    headers_t query_params;
    char path[MAX_PATH_LEN];
};

struct pulsar_conn;

typedef struct PulsarOffloadHandler {
    void (*on_read)(struct pulsar_conn* conn);
    void (*on_write)(struct pulsar_conn* conn);
    void (*on_close)(struct pulsar_conn* conn);
} PulsarOffloadHandler;

/* Connection State Structure */
struct pulsar_conn {
    /* ---- CACHE LINE 0 (0..63): Extremely hot per-event / per-request state ---- */
    int client_fd;
    int worker_id;
    uint32_t pending_len;
    bool closing;
    bool keep_alive;
    bool abort;
    bool in_keep_alive;
    /* Set by every request-scoped arena allocation site; reset_connection
     * only pays arena_reset's two dependent header loads when the request
     * actually allocated (perf: the dirty-check itself was the #1 hot spot
     * on keep-alive microbenchmarks where most requests never allocate). */
    bool arena_dirty;
    uint8_t _pad[3];
    time_t last_activity;
    struct pulsar_conn *next, *prev; /* Keep-alive list head / tail links */
    Arena* arena;
    char* read_buf;                     /* Points to static_read_buf during processing */
    struct event_queue* owner_queue;
    void* owner_ka_state;
#if ENABLE_LOGGING
    uint64_t start;
#endif

    /* ---- Hot Request and Response structures ---- */
    struct request_t request;
    struct response_t response;

    /* ---- Cold state at the end ---- */
    Locals locals;
    char pending_buf[READ_BUFFER_SIZE]; /* Dedicated partial read buffer (cold) */
#if ENABLE_SLOW_WORKERS
    struct PulsarOffloadHandler offload_hooks;
    bool offloaded;
#endif
};

#if ENABLE_SLOW_WORKERS
bool pulsar_handoff(struct pulsar_conn* conn, PulsarOffloadHandler handlers);
#endif

#endif /* __PULSAR_TYPES_H__ */
