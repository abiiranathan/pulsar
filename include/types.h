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
    HTTP_WRITE_PENDING = (1 << 4)  // 0x10 (16)
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

// HTTP Response structure
typedef struct response_t {
    // 8-Byte Fields
    size_t body_len;       // Actual length of body
    size_t body_capacity;  // Capacity of body buffer
    size_t body_sent;      // Bytes of body sent

    // 1-Byte Fields
    bool heap_allocated;  // If heap allocation is used
    uint8_t status_len;   // Actual length of status line
    uint8_t flags;        // 4 bytes for all flags
    uint8_t status_sent;  // Bytes of status line sent

    // 4-Byte Fields
    http_status status_code;  // HTTP status code (enum)
    int file_fd;              // File descriptor for file to send
    uint32_t file_size;       // Size of file to send
    uint32_t file_offset;     // Offset in file for sendfile
    uint32_t max_range;       // Maximum range of requested bytes

    char* status_buf;         //  Buffer for status line

    // 2-Byte Fields
    uint16_t headers_len;                  // Actual length of headers
    uint16_t headers_sent;                 // Bytes of headers sent
    char* headers_buf;                     // Buffer for the for headers
    union {
        uint8_t stack[STACK_BUFFER_SIZE];  // Stack buffer for smaller responses
        uint8_t* heap;                     // Dynamically allocated body buffer (aligned)
    } body;                                // Response body
} response_t;

// HTTP Request structure
typedef struct request_t {
    char* path;               // Request path (arena allocated)
    char method[8];           // HTTP method (GET, POST etc.)
    HttpMethod method_type;   // MethodType Enum
    char* body;               // Request body (dynamically allocated)
    size_t content_length;    // Content-Length header value
    headers_t* headers;       // Request headers
    headers_t* query_params;  // Query parameters
    struct route_t* route;    // Matched route (has static lifetime)
} request_t;

// Connection state structure
struct pulsar_conn {
    int client_fd;                    // Client socket file descriptor
    char* read_buf;                   // Buffer for incoming data.
    Locals locals;                    // Per-request context variables set by the user.
    struct request_t request;         // HTTP request data (arena allocated)
    response_t response;              // HTTP response data (arena allocated)
    Arena* arena;                     // Memory arena for allocations
#if ENABLE_LOGGING
    struct timespec start;            // Timestamp of first request
#endif
    time_t last_activity;             // Timestamp of last I/O activity
    struct pulsar_conn *next, *prev;  // Linked list nodes for keep-alive tracking.
    bool closing, keep_alive, abort, in_keep_alive;  // Connection flags.
    int worker_id;                                   // ID of the current worker running the thread.
};

#endif /* __PULSAR_TYPES_H__ */
