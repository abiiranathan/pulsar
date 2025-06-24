#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stddef.h>

#define NUM_WORKERS 8             // Number of workers.
#define MAX_EVENTS 2048           // Maximum events for epoll->ready queue.
#define READ_BUFFER_SIZE 819      // Buffer size for incoming statusline + headers +/-(part/all of body)
#define CONNECTION_TIMEOUT 30     // Keep-Alive connection timeout in seconds
#define MAX_BODY_SIZE (2 << 20)   // Max Request body allowed.
#define ARENA_CAPACITY 8 * 1024   // Arena memory per connection(8KB). Expand to 16 KB if required.
#define MAX_ROUTES 64             // Maximum number of routes
#define MAX_GLOBAL_MIDDLEWARE 32  // maximum number of global middleware.
#define MAX_ROUTE_MIDDLEWARE 4    // Maximum number of route middleware.

#endif /* CONSTANTS_H */
