#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stddef.h>

// Number of workers
#ifndef NUM_WORKERS
#define NUM_WORKERS 8
#endif

// Maximum events for epoll->ready queue
#ifndef MAX_EVENTS
#define MAX_EVENTS 4096
#endif

// Buffer size for incoming statusline + headers +/-(part/all of body)
#ifndef READ_BUFFER_SIZE
#define READ_BUFFER_SIZE 4096
#endif

// Default buffer size for status + headers + body.
// This resizable with realloc.
#ifndef WRITE_BUFFER_SIZE
#define WRITE_BUFFER_SIZE 8192
#endif

// Keep-Alive connection timeout in seconds
#ifndef CONNECTION_TIMEOUT
#define CONNECTION_TIMEOUT 30
#endif

// Max Request body allowed. Default 2 MB
#ifndef MAX_BODY_SIZE
#define MAX_BODY_SIZE (2 << 20)
#endif

// Arena memory per connection.
#ifndef ARENA_CAPACITY
#define ARENA_CAPACITY (4 * 1024)
#endif

// Maximum number of routes
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

// Assertions for all constants
static_assert(NUM_WORKERS > 0, "NUM_WORKERS must be > 0");
static_assert(MAX_EVENTS > 0, "MAX_EVENTS must be > 0");
static_assert(MAX_ROUTES > 0, "MAX_ROUTES must be > 0");
static_assert(MAX_GLOBAL_MIDDLEWARE > 0, "MAX_GLOBAL_MIDDLEWARE must be > 0");
static_assert(MAX_ROUTE_MIDDLEWARE > 0, "MAX_ROUTE_MIDDLEWARE must be > 0");
static_assert(HEADERS_CAPACITY > 0, "HEADERS_CAPACITY must be > 0");

// Ensure arena capacity is reasonable
static_assert(ARENA_CAPACITY >= 1024, "ARENA_CAPACITY must be >= 1024");
static_assert(ARENA_CAPACITY <= 1024 * 1024, "ARENA_CAPACITY must be <= 1MB");

// Ensure buffer sizes are reasonable
static_assert(READ_BUFFER_SIZE >= 1024, "READ_BUFFER_SIZE must be at least 1KB");
static_assert(WRITE_BUFFER_SIZE >= 8192, "WRITE_BUFFER_SIZE must be at least 8KB");

// Ensure timeouts are reasonable
static_assert(CONNECTION_TIMEOUT >= 10, "CONNECTION_TIMEOUT must be at least 10 seconds");

// Ensure body size is reasonable
static_assert(MAX_BODY_SIZE > 0, "MAX_BODY_SIZE must be > 0");

#endif /* CONSTANTS_H */
