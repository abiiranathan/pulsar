#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stddef.h>

// Include helper macros
#include "macros.h"

// Per-connection arena memory.
#ifndef ARENA_CAPACITY
#define ARENA_CAPACITY 16 * 1024
#endif

// Enable logging callback.
#ifndef ENABLE_LOGGING
#define ENABLE_LOGGING 0
#endif

// If "truthy", server headers are written to the response.
// This includes "Server" and "Date" headers.
#ifndef WRITE_SERVER_HEADERS
#define WRITE_SERVER_HEADERS 0
#endif

// Number of workers. Should be ideally == ncpus.
#ifndef NUM_WORKERS
#define NUM_WORKERS 8
#endif

// maximum path length
#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 1024
#endif

// Maximum events for epoll->ready queue
#ifndef MAX_EVENTS
#define MAX_EVENTS 2048
#endif

// Buffer size for incoming request excluding body.
#ifndef READ_BUFFER_SIZE
#define READ_BUFFER_SIZE 1024
#endif

// Default buffer to allocate for the response if the response size exceeds STACK_BUFFER_SIZE.
#ifndef WRITE_BUFFER_SIZE
#define WRITE_BUFFER_SIZE 4096
#endif

// Default buffer size for response body above which allocation happens, allocating
// WRITE_BUFFER_SIZE.
#ifndef STACK_BUFFER_SIZE
#define STACK_BUFFER_SIZE 1024
#endif

// Keep-Alive connection timeout in seconds.
#ifndef CONNECTION_TIMEOUT
#define CONNECTION_TIMEOUT 30
#endif

// Max Request body allowed. Default 2 MB
// You need to increase this to allow large file uploads.
#ifndef MAX_BODY_SIZE
#define MAX_BODY_SIZE (2 << 20)
#endif

/**
 * @def MAX_FILE_SIZE
 * @brief Maximum allowed file size (25KB default) in multipart forms.
 */
#ifndef MAX_FILE_SIZE
#define MAX_FILE_SIZE (25 * 1024)
#endif

// Maximum number of routes to support.
#ifndef MAX_ROUTES
#define MAX_ROUTES 64
#endif

// Maximum number of global middleware
#ifndef MAX_GLOBAL_MIDDLEWARE
#define MAX_GLOBAL_MIDDLEWARE 32
#endif

// Maximum number of route middleware
#ifndef MAX_ROUTE_MIDDLEWARE
#define MAX_ROUTE_MIDDLEWARE 4
#endif

// Maximum number of headers in a request.
#ifndef HEADERS_CAPACITY
#define HEADERS_CAPACITY 32
#endif

// Timeout in seconds for graceful shutdown on SIGINT/SIGTERM before forceful shutdown.
#ifndef SHUTDOWN_TIMEOUT_SECONDS
#define SHUTDOWN_TIMEOUT_SECONDS 5
#endif

// Maximum number of connection context variables set by the user.
#ifndef LOCALS_CAPACITY
#define LOCALS_CAPACITY 32
#endif

// Maximum capacity of the locals key.
#ifndef LOCALS_KEY_CAPACITY
#define LOCALS_KEY_CAPACITY 16
#endif

static_assert(LOCALS_KEY_CAPACITY >= 4);

// Assertions for all constants
static_assert(ARENA_CAPACITY > 4 * 1024, "ARENA_CAPACITY must be > 4KB");
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

// Ensure shutdown timeout is reasonable
static_assert(SHUTDOWN_TIMEOUT_SECONDS > 0, "SHUTDOWN_TIMEOUT_SECONDS must be > 0");

#endif /* CONSTANTS_H */
