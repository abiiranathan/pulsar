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

typedef enum {
    // Indicates that the Content-Type header has been set for the response.
    HTTP_CONTENT_TYPE_SET = (1 << 0),  // 0x01 (1)

    // Indicates that the response status line and headers have been written to the socket.
    HTTP_HEADERS_WRITTEN = (1 << 1),  // 0x02 (2)

    // Indicates that the client sent a Range header and the response is a partial content response.
    HTTP_RANGE_REQUEST = (1 << 2),  // 0x04 (4)

    // Indicates that the response is using chunked transfer encoding. When this flag
    HTTP_CHUNKED_TRANSFER = (1 << 3),  // 0x08 (8)

    /* Write-pending flag to track deferred non-blocking writes */
    HTTP_WRITE_PENDING = (1 << 4),  // 0x10 (16)

    /* Body overflowed the inline stack buffer and lives on the heap */
    HTTP_HEAP_ALLOCATED = (1 << 5)  // 0x20 (32)
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

// HTTP Response structure
struct response_t {
    // --- Hot: pointers (24 B) ---
    char* headers_buf;  // Buffer for the headers
    char* out_buf;      // Contiguous buffer for single-write responses
    char* status_buf;   // Buffer for status line

    // --- Hot: lengths / progress (24 B) ---
    uint32_t body_len;     // Actual length of body
    uint32_t out_len;      // Total bytes in contiguous output buffer
    uint32_t out_sent;     // Bytes sent from contiguous output buffer
    uint32_t out_cap;      // Total capacity of contiguous output buffer
    uint32_t headers_len;  // Actual length of headers
    uint32_t headers_cap;  // Available capacity for the headers

    // --- Hot: status / flags (4 B) ---
    uint16_t status_code;  // HTTP status code (all codes < 512)
    uint8_t status_len;    // Actual length of status line
    uint8_t flags;         // All bit_flags incl. heap-allocated bit

    // --- Warm: heap body progress (8 B) ---
    uint32_t body_capacity;  // Capacity of heap body buffer (valid iff heap)
    uint32_t body_sent;      // Bytes of heap body sent

    // --- Cold: file-serve state (16 B + 8 B offset) ---
    int file_fd;          // File descriptor for file to send
    uint32_t file_size;   // Size of file to send (files > 4 GiB rejected)
    int64_t file_offset;  // Offset in file for sendfile
    uint32_t range_end;   // Exclusive end offset for Range sends (== file_size when no range)

    // --- Bulky inline buffer last (512 B) ---
    union {
        uint8_t stack[STACK_BUFFER_SIZE];  // Stack buffer for smaller responses
        uint8_t* heap;                     // Dynamically allocated body buffer (aligned)
    } body;                                // Response body
};

// Hot prefix (everything before the inline body) must stay within two
// cache lines so small responses never touch more than that plus the
// stack buffer actually used. Whole struct must stay comfortably inside
// L2 (and even L1) working set.
_Static_assert(sizeof(struct response_t) <= 616,
               "response_t grew past budget; re-check field sizes");
_Static_assert(__builtin_offsetof(struct response_t, body) <= 128,
               "response_t hot fields spilled past 2 cache lines");
_Static_assert(__builtin_offsetof(struct response_t, body) % 8 == 0,
               "response_t body union must stay 8-byte aligned");

// HTTP Request structure
struct request_t {
    char* path;               // Request path (fixed buffer allocated)
    char method[8];           // HTTP method (GET, POST etc.)
    HttpMethod method_type;   // MethodType Enum
    char* body;               // Request body (dynamically allocated)
    size_t content_length;    // Content-Length header value
    headers_t* headers;       // Request headers
    headers_t* query_params;  // Query parameters
    struct route_t* route;    // Matched route (has static lifetime)
    StrSlice range_hdr;       // Range header value view (NULL data when absent)
};

/* ================================================================
 * Slow Connection Offloader Types and API
 * ================================================================ */
struct pulsar_conn;  // Forward declaration.

/**
 * @brief User-defined hooks for managing the state of offloaded connections.
 */
typedef struct PulsarOffloadHandler {
    void (*on_read)(struct pulsar_conn* conn);  // Invoked when data arrives (useful for WebSockets)
    void (*on_write)(struct pulsar_conn* conn);  // Invoked when the socket is writable
    void (*on_close)(
        struct pulsar_conn* conn);  // Invoked when the client disconnects or an error occurs
} PulsarOffloadHandler;

// Connection state structure
struct pulsar_conn {
    char* read_buf;      // Buffer for incoming data.
    Arena* arena;        // Memory arena for allocations
    size_t pending_len;  // Bytes of a partial request buffered across reads.
    int client_fd;       // Client socket file descriptor
    int worker_id;       // ID of the current worker running the thread.
    bool closing, keep_alive, abort, in_keep_alive;  // Connection flags.
    bool arena_dirty;      // True if conn->arena was used this request (skip reset when false).
    time_t last_activity;  // Monotonic seconds (pulsar_mono_sec) of last I/O; see conn_timedout

    /* ---- Per-request state ---- */
    Locals locals;               // Per-request context variables set by the user.
    struct request_t request;    // HTTP request data
    struct response_t response;  // HTTP response data

#if ENABLE_LOGGING
    uint64_t start;  // Timestamp counter at the start of request processing.
#endif

    /* ----  Linked list nodes for keep-alive tracking ---- */
    struct pulsar_conn *next, *prev;

    /* ---- Background worker ownership ---- */
    struct Poller* owner_queue;                 // The event queue of its current owner
    void* owner_ka_state;                       // Reference to the owner's KeepAliveState
    struct PulsarOffloadHandler offload_hooks;  // Registered lifecycle callbacks
    bool offloaded;                             // Flag indicating ownership transfer
};

/**
 * @brief Transitions a connection from the main worker pool to the slow pool.
 *
 * @param conn The current connection context.
 * @param handlers A struct containing lifecycle callbacks for the connection.
 * @return true if the handover succeeded, false otherwise.
 */
bool pulsar_handoff(struct pulsar_conn* conn, PulsarOffloadHandler handlers);

#endif /* __PULSAR_TYPES_H__ */
