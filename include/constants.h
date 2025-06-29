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

// Default buffer size (adjust based on expected max headers)
#define RESPONSE_BUFFER_DEFAULT_SIZE 8192  // 8KB total buffer

// Keep-Alive connection timeout in seconds
#ifndef CONNECTION_TIMEOUT
#define CONNECTION_TIMEOUT 30
#endif

// Max Request body allowed. Default 2 MB
#ifndef MAX_BODY_SIZE
#define MAX_BODY_SIZE (2 << 20)
#endif

// Arena memory per connection(16KB).
#ifndef ARENA_CAPACITY
#define ARENA_CAPACITY (16 * 1024)
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

#ifndef HEADERS_CAPACITY
#define HEADERS_CAPACITY 32
#endif

#endif /* CONSTANTS_H */
