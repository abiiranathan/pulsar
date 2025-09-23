#ifndef COMMON_H
#define COMMON_H

#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/types.h>

// Platform-specific includes
#if defined(__linux__)
#include <malloc.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#elif defined(__FreeBSD__)
#include <sys/cpuset.h>
#include <sys/event.h>
#include <sys/param.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <sys/event.h>
#include <sys/param.h>
#endif

#include <solidc/arena.h>
#include <solidc/filepath.h>
#include <solidc/str_to_num.h>
#include "../include/constants.h"
#include "../include/headers.h"
#include "../include/locals.h"
#include "../include/method.h"
#include "../include/mimetype.h"
#include "../include/status_code.h"

typedef enum {
    HTTP_CONTENT_TYPE_SET = (1 << 0),  // 0x01 (1)
    HTTP_HEADERS_WRITTEN  = (1 << 1),  // 0x02 (2)
    HTTP_RANGE_REQUEST    = (1 << 2),  // 0x04 (4)
    HTTP_CHUNKED_TRANSFER = (1 << 3),  // 0x08 (8)
} bit_flags;

#define HAS_CONTENT_TYPE(flags)     (((flags) & HTTP_CONTENT_TYPE_SET) != 0)
#define HAS_HEADERS_WRITTEN(flags)  (((flags) & HTTP_HEADERS_WRITTEN) != 0)
#define HAS_RANGE_REQUEST(flags)    (((flags) & HTTP_RANGE_REQUEST) != 0)
#define HAS_CHUNKED_TRANSFER(flags) (((flags) & HTTP_CHUNKED_TRANSFER) != 0)

#define SET_CONTENT_TYPE(flags)     ((flags) |= HTTP_CONTENT_TYPE_SET)
#define SET_HEADERS_WRITTEN(flags)  ((flags) |= HTTP_HEADERS_WRITTEN)
#define SET_RANGE_REQUEST(flags)    ((flags) |= HTTP_RANGE_REQUEST)
#define SET_CHUNKED_TRANSFER(flags) ((flags) |= HTTP_CHUNKED_TRANSFER)

// HTTP Response structure
typedef struct response_t {
    http_status status_code;             // HTTP status code.
    char status_buf[STATUS_LINE_SIZE];   // Null-terminated buffer for status line.
    char headers_buf[HEADERS_BUF_SIZE];  // Null-terminated buffer for headers.
    bool heap_allocated;                 // If heap allocation is used.
    union {
        uint8_t stack[STACK_BUFFER_SIZE];  // stack buffer for smaller responses
        uint8_t* heap;  // Dynamically allocated body buffer. (not null-terminated)
    } body;             // Response body.

    // Pre-computed lengths of status line, headers, body.
    size_t body_len;       // Actual length of body
    size_t body_capacity;  // Capacity of body buffer.
    uint16_t headers_len;  // Actual length of headers
    uint8_t status_len;    // Actual length of status line
    uint8_t flags;         // 4 bytes for all flags.

    // Event retry state.
    uint8_t status_sent;    // Bytes of status line sent
    uint16_t headers_sent;  // Bytes of headers sent
    size_t body_sent;       // Bytes of body sent

    // File response state.
    uint32_t file_size;    // Size of file to send (if applicable)
    uint32_t file_offset;  // Offset in file for sendfile
    uint32_t max_range;    // Maximum range of requested bytes in range request.
    int file_fd;           // File descriptor for file to send (if applicable)
} response_t;

// HTTP Request structure
typedef struct __attribute__((aligned(64))) request_t {
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
typedef struct connection_t {
    int client_fd;              // Client socket file descriptor
    char* read_buf;             // Buffer for incoming data.
    Locals* locals;             // Per-request context variables set by the user.
    response_t* response;       // HTTP response data (arena allocated)
    struct request_t* request;  // HTTP request data (arena allocated)
    Arena* arena;               // Memory arena for allocations
#if ENABLE_LOGGING
    struct timespec start;  // Timestamp of first request
#endif
    time_t last_activity;  // Timestamp of last I/O activity

    // Linked List nodes.
    struct connection_t* next;
    struct connection_t* prev;
    bool closing;        // Server closing because of an error.
    bool keep_alive;     // Keep-alive flag
    bool abort;          // Abort handler/middleware processing
    bool in_keep_alive;  // Flag for a tracked connection
} connection_t;

#endif /* COMMON_H */
