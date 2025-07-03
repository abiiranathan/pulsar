# Pulsar - A High Performance C Webserver

Pulsar is a lightweight, high-performance web server written in C designed for building fast HTTP services and APIs. It uses modern Linux system calls like `epoll` and `sendfile` for optimal performance.

## Key Features

- **Multi-threaded** with worker thread pool (8 workers by default)
- **Event-driven** architecture using epoll for high concurrency
- **Zero-copy file transfers** with sendfile
- **Memory efficient** with arena allocation per connection
- **Simple routing API** with path parameters
- **Middleware support** (global and per-route)
- **Keep-alive connections** with timeout
- **Static file serving** with directory traversal protection
- **Query parameter parsing**
- **Request/response abstractions**

## Benchmarks
***pulsar reaches*** ~ **400k - 500k requests / sec** on a HelloWorld web server.

## Architecture

Pulsar follows these key architectural principles:

1. **Multi-threaded with epoll**: 
   - Uses a thread pool (8 workers by default)
   - Each worker has its own epoll instance
   - Uses EPOLLEXCLUSIVE to avoid thundering herd

2. **Connection lifecycle**:
   - Each connection is handled by a single worker.
   - Connections can be kept alive (Keep-Alive)
   - Timeout for idle connections

3. **Memory management**:
   - Per-connection memory arena (8KB initially)
   - Zero-copy file transfers with sendfile
   - Minimal allocations after connection setup

4. **Request processing**:
   - Header parsing with minimal copying
   - Query parameter extraction
   - Path parameter matching
   - Middleware chaining

## API Reference

### Server Management

```c
int pulsar_run(const char *addr, int port);
```
Starts the server on the specified address (or IP address) and port. 
Runs until SIGINT/SIGTERM is received and then graceful shutdown is performed.

### Routing

```c
route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler);
```
Registers a route with a URL pattern, HTTP method, and handler function.

```c
route_t* register_static_route(const char* pattern, const char* dir);
```
Registers a static file serving route for a directory.

### Request Handling

```c
const char* req_method(connection_t* conn);
const char* req_path(connection_t* conn); 
const char* req_body(connection_t* conn);
size_t req_content_len(connection_t* conn);
```
Access request method, path, body and content length.

### Query Parameters

```c 
const char* query_get(connection_t* conn, const char* name);
headers_t* query_params(connection_t* conn);
```
Access query parameters by name or get all parameters.

### Path Parameters

```c
const char* get_path_param(connection_t* conn, const char* name);
```
Get path parameter value by name (for routes like `/users/{id}`).

### Response Writing

```c
void conn_set_status(connection_t* conn, http_status code);
bool conn_writeheader(connection_t* conn, const char* name, const char* value);
int conn_write(connection_t* conn, const void* data, size_t len);
int conn_write_string(connection_t* conn, const char* str);
int conn_writef(connection_t* conn, const char* fmt, ...);
bool conn_servefile(connection_t* conn, const char* filename);
```
Functions to set status code, headers, and write response data.

### Middleware

```c
void use_global_middleware(HttpHandler *middleware, size_t count);
void use_route_middleware(route_t* route, HttpHandler *middleware, size_t count);
```

Register global or route-specific middleware functions.

### User Data

```c
void set_userdata(connection_t* conn, void* ptr, void (*free_func)(void* ptr));
void* get_userdata(connection_t* conn);
```
Store and retrieve per-request user data.

## Example Usage

```c
#include "pulsar.h"

bool hello_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, "text/plain");
    conn_write_string(conn, "Hello World!");
    return true;
}

bool auth_middleware(connection_t* conn) {
    const char* token = req_header_get(conn, "Authorization");
    if (!token) {
        conn_set_status(conn, StatusUnauthorized);
        return false;
    }
    return true;
}

int main() {
    // Register routes
    route_t* hello_route = route_register("/hello", HTTP_GET, hello_handler);
    use_route_middleware(hello_route, 1, auth_middleware);
    
    // Serve static files
    register_static_route("/static/", "./public");
    
    // Start server
    return pulsar_run(NULL, 8080);
}
```

## Performance Considerations

- Uses non-blocking I/O throughout
- Minimal memory copies
- sendfile for zero-copy file transfers
- Arena allocation reduces malloc/free overhead
- Sorted routes for efficient matching
- Keep-alive connections reduce TCP overhead

## Limitations

- Linux-only (uses epoll, sendfile)
- No HTTPS support (could be added with OpenSSL)
- Limited to HTTP/1.1

## Building the Library

Clone the repository:

```bash
git clone https://github.com/abiiranathan/pulsar
cd pulsar

# Build everything (executable and both libraries)
make all

# Build just the static library
make static

# Build just the shared library
make shared

# Build both libraries
make lib

# Install to system
sudo make install

# Clean build artifacts
make clean
```

## Linking
Link your binary with `-lpulsar` flag after installation.

# Configuration

Here's a comprehensive README section documenting these constants:

---

## Configuration Constants

This document explains the compile-time configuration options available in the server.

## Table of Contents
1. [Performance Tuning](#performance-tuning)
2. [Memory Management](#memory-management)
3. [Network Settings](#network-settings)
4. [Security Limits](#security-limits)
5. [Middleware & Routing](#middleware--routing)
6. [Debugging Features](#debugging-features)

---

## Performance Tuning

| Constant             | Default | Description                                         |
| -------------------- | ------- | --------------------------------------------------- |
| `NUM_WORKERS`        | 8       | Number of worker processes (should match CPU cores) |
| `MAX_EVENTS`         | 1024    | Maximum ready events processed per epoll iteration  |
| `CONNECTION_TIMEOUT` | 30      | Keep-Alive timeout in seconds                       |

**Recommendations:**
- Set `NUM_WORKERS` to your CPU core count
- Increase `MAX_EVENTS` for high connection loads (requires more RAM)

---

## Memory Management

| Constant            | Default | Description                                    |
| ------------------- | ------- | ---------------------------------------------- |
| `READ_BUFFER_SIZE`  | 4096    | Buffer for incoming request headers (bytes)    |
| `WRITE_BUFFER_SIZE` | 8192    | Initial buffer for responses (grows as needed) |
| `ARENA_CAPACITY`    | 4096    | Per-connection memory pool size (bytes)        |

**Constraints:**
```c
static_assert(READ_BUFFER_SIZE >= 1024);
static_assert(WRITE_BUFFER_SIZE >= 8192);
static_assert(ARENA_CAPACITY between 1KB-1MB);
```

---

## Network Settings

| Constant                   | Default | Description                       |
| -------------------------- | ------- | --------------------------------- |
| `MAX_BODY_SIZE`            | 2MB     | Maximum allowed request body size |
| `SHUTDOWN_TIMEOUT_SECONDS` | 10      | Graceful shutdown window          |

**Security Note:**
- `MAX_BODY_SIZE` prevents memory exhaustion attacks
- Minimum 10-second shutdown ensures clean exit

---

## Middleware & Routing

| Constant                | Default | Description                |
| ----------------------- | ------- | -------------------------- |
| `MAX_ROUTES`            | 64      | Maximum registered routes  |
| `MAX_GLOBAL_MIDDLEWARE` | 32      | Global middleware slots    |
| `MAX_ROUTE_MIDDLEWARE`  | 4       | Per-route middleware slots |
| `HEADERS_CAPACITY`      | 32      | Maximum request headers    |

**Architecture:**
- Middleware executes in registration order
- Exceeding header capacity returns `431 Request Header Fields Too Large`

---

## Debugging Features

| Constant                       | Default | Description                       |
| ------------------------------ | ------- | --------------------------------- |
| `DETECT_DUPLICATE_RES_HEADERS` | 0       | Filter duplicate response headers |
| `WRITE_SERVER_HEADERS`         | 0       | Auto-add Server/Date headers      |

**Performance Tradeoffs:**
```text
DETECT_DUPLICATE_RES_HEADERS=1 adds ~2% overhead
WRITE_SERVER_HEADERS=1 adds ~1% overhead
```

---

## Build Configuration

Override defaults during compilation:
```bash
# Example: 16 workers, 8MB max body
make CFLAGS="-DNUM_WORKERS=16 -DMAX_BODY_SIZE=$((8<<20))"
```


---

See [constants.h](src/constants.h) for implementation details.

## Kernel Tuning (sysctl)

```txt
# TCP Performance Tuning
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_fastopen = 3

# Socket buffer tuning
net.core.netdev_max_backlog = 30000
net.core.somaxconn = 1024
net.ipv4.tcp_max_syn_backlog = 1024

# Connection reuse
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 1  # Warning: Disable if behind NAT
```


## License

MIT License
