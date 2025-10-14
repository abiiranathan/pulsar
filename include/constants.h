#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stddef.h>
#include <stdint.h>

// Include helper macros
#include "macros.h"

// Per-connection arena memory.
#ifndef ARENA_CAPACITY
#define ARENA_CAPACITY 8 * 1024UL
#endif

// Enable logging callback.
#ifndef ENABLE_LOGGING
#define ENABLE_LOGGING 1
#endif

// If "truthy", server headers are written to the response.
// This includes "Server" and "Date" headers.
#ifndef WRITE_SERVER_HEADERS
#define WRITE_SERVER_HEADERS 1
#endif

// Number of workers. Should be ideally == ncpus.
#ifndef NUM_WORKERS
#define NUM_WORKERS 8U
#endif

// maximum path length
#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 1024
#endif

// Maximum events for epoll->ready queue
#ifndef MAX_EVENTS
#define MAX_EVENTS 1024UL
#endif

// Buffer size for incoming request excluding body.
#ifndef READ_BUFFER_SIZE
#define READ_BUFFER_SIZE 1024UL
#endif

// Default buffer to allocate for the response if the response size exceeds STACK_BUFFER_SIZE.
#ifndef WRITE_BUFFER_SIZE
#define WRITE_BUFFER_SIZE 4096UL
#endif

// Default buffer size for response body above which allocation happens, allocating
// WRITE_BUFFER_SIZE.
#ifndef STACK_BUFFER_SIZE
#define STACK_BUFFER_SIZE 1024UL
#endif

// Keep-Alive connection timeout in seconds.
#ifndef CONNECTION_TIMEOUT
#define CONNECTION_TIMEOUT 30
#endif

// Max Request body allowed. Default 10 MB
// You need to increase this to allow large file uploads.
#ifndef MAX_BODY_SIZE
#define MAX_BODY_SIZE (size_t)(10 << 20)
#endif

/**
 * @def MAX_FILE_SIZE
 * @brief Maximum allowed file size (25KB default) in multipart forms.
 */
#ifndef MAX_FILE_SIZE
#define MAX_FILE_SIZE 25UL * 1024
#endif

// Maximum number of non-static routes to support.
#ifndef MAX_ROUTES
#define MAX_ROUTES 128U
#endif

// maximum number of static routes to support.
#ifndef MAX_STATIC_ROUTES
#define MAX_STATIC_ROUTES 4U
#endif

// Maximum number of global middleware
#ifndef MAX_GLOBAL_MIDDLEWARE
#define MAX_GLOBAL_MIDDLEWARE 16U
#endif

// Maximum number of route middleware
#ifndef MAX_ROUTE_MIDDLEWARE
#define MAX_ROUTE_MIDDLEWARE 2
#endif

// Maximum number of headers in a request.
#ifndef HEADERS_CAPACITY
#define HEADERS_CAPACITY 32
#endif

// Maximum capacity of the locals key.
#ifndef LOCALS_KEY_CAPACITY
#define LOCALS_KEY_CAPACITY 16
#endif

// Constants
#define STATUS_LINE_SIZE 128
#define HEADERS_BUF_SIZE 1024
#define CACHE_LINE_SIZE  64

// Assertions for all constants

// Make sure they fit in uint8_t and uint16_t
static_assert(STATUS_LINE_SIZE <= UINT8_MAX);
static_assert(HEADERS_BUF_SIZE <= UINT16_MAX);
static_assert(LOCALS_KEY_CAPACITY >= 4);

static_assert(ARENA_CAPACITY >= (unsigned long)(4 * 1024), "ARENA_CAPACITY must be > 4KB");
static_assert(NUM_WORKERS > 0, "NUM_WORKERS must be > 0");
static_assert(MAX_EVENTS > 0, "MAX_EVENTS must be > 0");
static_assert(MAX_ROUTES > 0, "MAX_ROUTES must be > 0");
static_assert(MAX_GLOBAL_MIDDLEWARE > 0, "MAX_GLOBAL_MIDDLEWARE must be > 0");
static_assert(MAX_ROUTE_MIDDLEWARE > 0, "MAX_ROUTE_MIDDLEWARE must be > 0");
static_assert(HEADERS_CAPACITY > 0, "HEADERS_CAPACITY must be > 0");

// Ensure buffer sizes are reasonable
static_assert(READ_BUFFER_SIZE >= 1024, "READ_BUFFER_SIZE must be at least 1KB");
static_assert(WRITE_BUFFER_SIZE >= 1024, "WRITE_BUFFER_SIZE must be at least 1KB");

// Ensure timeouts are reasonable
static_assert(CONNECTION_TIMEOUT >= 5, "CONNECTION_TIMEOUT must be at least 5 seconds");

// Ensure body size is reasonable
static_assert(MAX_BODY_SIZE > 0, "MAX_BODY_SIZE must be > 0");
static_assert(MAX_FILE_SIZE > 0, "MAX_FILE_SIZE must be > 0");
static_assert(MAX_FILE_SIZE <= MAX_BODY_SIZE, "MAX_FILE_SIZE must be <= MAX_BODY_SIZE");

#endif /* CONSTANTS_H */
