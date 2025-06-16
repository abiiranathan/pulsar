#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#define MAX_EVENTS         2048
#define BUFFER_SIZE        4096
#define PORT               8080
#define CONNECTION_TIMEOUT 30
#define NUM_WORKERS        8
#define MAX_BODY_SIZE      (2 << 20)
#define MAX_HEADERS        64
#define CONN_ARENA_MEM     8 * 1024

// Connection states
typedef enum { STATE_READING_REQUEST, STATE_WRITING_RESPONSE, STATE_CLOSING } connection_state;

typedef struct {
    char* name;
    char* value;
} header_t;

typedef struct {
    header_t items[MAX_HEADERS];
    size_t count;
} headers_t;

// HTTP Request structure
typedef struct {
    char method[8];         // HTTP method (GET, POST etc.)
    char* path;             // Requested path
    size_t content_length;  // Content-Length header value
    char* body;             // Request body
    size_t body_received;   // Bytes of body received
    size_t headers_len;     // Length of headers text in connection buffer. ie offset
    headers_t* headers;     // Request headers
} request_t;

// HTTP Response structure
typedef struct {
    char* buffer;          // Buffer for outgoing data
    size_t bytes_to_send;  // Total bytes to write
    size_t bytes_sent;     // Bytes already sent
    size_t buffer_size;    // Bytes allocated for buffer

    // New fields for simplified API
    int status_code;          // HTTP status code
    char status_message[64];  // HTTP status message
    headers_t* headers;       // Custom headers
    char* body_data;          // Response body data
    size_t body_size;         // Current body size
    size_t body_capacity;     // Body buffer capacity
    int headers_written;      // Flag to track if headers are written
} response_t;

typedef enum {
    HTTP_INVALID = -1,
    HTTP_OPTIONS,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_PATCH,
    HTTP_DELETE,
} HttpMethod;

typedef struct {
    uint8_t* memory;   // Arena memory
    size_t allocated;  // Allocated memory
    size_t capacity;   // Capacity of the arena
} Arena;

// Connection structure
typedef struct {
    int fd;                      // Client socket file descriptor
    connection_state state;      // Current connection state
    time_t last_activity;        // Timestamp of last I/O activity
    int keep_alive;              // Keep-alive flag
    char read_buf[BUFFER_SIZE];  // Buffer for incoming data
    size_t read_bytes;           // Bytes currently in read buffer
    request_t* request;          // HTTP request data
    response_t* response;        // HTTP response data
    Arena* arena;                // Connection arena.
} connection_t;

typedef bool (*HttpHandler)(connection_t* conn);

typedef struct {
    char* pattern;        // dynamically allocated route pattern
    HttpMethod method;    // Http method.
    HttpHandler handler;  // Handler function pointer
} route_t;

// Worker thread data
typedef struct {
    int epoll_fd;
    int worker_id;
    int server_fd;
} worker_data_t;

// Global flag to keep all workers running.
static volatile sig_atomic_t server_running = 1;

#define MAX_ROUTES 64
static route_t global_routes[MAX_ROUTES];
static size_t global_count = 0;

// ================== Signal handler    ========================
void handle_sigint(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        server_running = 0;
    }
}

static void install_signal_handler(void) {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    // See man 2 sigaction for more information.
    sigaction(SIGINT, &sa, NULL);

    // Ignore SIGPIPE signal when writing to a closed socket or pipe.
    // Potential causes:
    // https://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
    signal(SIGPIPE, SIG_IGN);
}

// =================== Arena functions   ========================
Arena* arena_create(size_t capacity) {
    assert(capacity > 0);
    Arena* arena = malloc(sizeof(Arena));
    if (!arena) {
        return NULL;
    }

    arena->memory = calloc(1, capacity);
    if (!arena->memory) {
        free(arena);
        return NULL;
    }
    arena->allocated = 0;
    arena->capacity  = capacity;
    return arena;
}

void arena_destroy(Arena* arena) {
    if (!arena) return;
    free(arena->memory);
    free(arena);
}

void* arena_alloc(Arena* arena, size_t size) {
    if (arena->allocated + size > arena->capacity) {
        fprintf(stderr, "Arena out of memory\n");
        return NULL;
    }

    void* ptr = &arena->memory[arena->allocated];
    arena->allocated += size;
    return ptr;
}

char* arena_strdup(Arena* arena, const char* str) {
    size_t cap = strlen(str) + 1;
    char* dst  = arena_alloc(arena, cap);
    if (!dst) {
        return NULL;
    }

    // copy string including NULL terminator.
    (void)strlcpy(dst, str, cap);
    return dst;
}

static inline void arena_reset(Arena* arena) {
    assert(arena->capacity > 0);

    arena->allocated = 0;
    memset(arena->memory, 0, arena->capacity);
}

// ==================== Header API functions ===================
headers_t* headers_new(Arena* arena) {
    headers_t* headers = arena_alloc(arena, sizeof(headers_t));
    if (!headers) return NULL;
    headers->count = 0;
    memset(headers->items, 0, sizeof(headers->items));
    return headers;
}

bool headers_append(Arena* arena, headers_t* headers, const char* name, const char* value) {
    // Check if header already exists.
    int index = -1;
    for (size_t i = 0; i < headers->count; i++) {
        if (strcasecmp(name, headers->items[i].name) == 0) {
            index = i;
            break;
        }
    }

    // if its a new header and no space for it, bail
    if (headers->count >= MAX_HEADERS && index == -1) return false;

    header_t hdr = {
        .name  = arena_strdup(arena, name),
        .value = arena_strdup(arena, value),
    };

    if (!hdr.name || !hdr.value) return false;

    // Insert in correct position
    size_t pos = (index != -1) ? index : headers->count;

    // Increment counter if new header.
    if (index == -1) headers->count++;

    headers->items[pos] = hdr;
    return true;
}

// =================== New API Functions ========================

// Set HTTP status code and message
void conn_set_status(connection_t* conn, int code, const char* message) {
    if (!conn || !conn->response) return;

    conn->response->status_code = code;
    strlcpy(conn->response->status_message, message ? message : "", sizeof(conn->response->status_message));
}

// Add a custom header
bool conn_writeheader(connection_t* conn, const char* name, const char* value) {
    if (!conn || !name || !value) return false;
    return headers_append(conn->arena, conn->response->headers, name, value);
}

// Write data to response body
int conn_write(connection_t* conn, const void* data, size_t len) {
    if (!conn || !conn->response || !data || len == 0) return 0;

    response_t* resp = conn->response;

    // Ensure we have enough capacity
    size_t required_size = resp->body_size + len;
    if (required_size > resp->body_capacity) {
        size_t new_capacity = resp->body_capacity == 0 ? 1024 : resp->body_capacity;
        while (new_capacity < required_size) {
            new_capacity *= 2;
        }

        char* new_buffer = realloc(resp->body_data, new_capacity);
        if (!new_buffer) {
            return 0;  // Failed to allocate memory
        }

        resp->body_data     = new_buffer;
        resp->body_capacity = new_capacity;
    }

    // Copy data to body buffer
    memcpy(resp->body_data + resp->body_size, data, len);
    resp->body_size += len;

    return len;
}

// Build the complete HTTP response
void finalize_response(connection_t* conn) {
    response_t* resp = conn->response;
    if (!resp || resp->headers_written) return;

    // Set default status if not set
    if (resp->status_code == 0) {
        resp->status_code = 200;
        strcpy(resp->status_message, "OK");
    }

    // Calculate total response size
    size_t header_size = 512;  // Base headers
    for (size_t i = 0; i < resp->headers->count; i++) {
        // +4, reserve for \r\n and colon and space.
        header_size += strlen(resp->headers->items[i].name) + strlen(resp->headers->items[i].value) + 4;
    }

    size_t total_size = header_size + resp->body_size;
    resp->buffer      = malloc(total_size);
    if (!resp->buffer) {
        perror("malloc");
        conn->state = STATE_CLOSING;
        return;
    }

    resp->buffer_size = total_size;

    // Build headers
    int offset =
        snprintf(resp->buffer, header_size,
                 "HTTP/1.1 %d %s\r\n"
                 "Connection: %s\r\n"
                 "Content-Length: %zu\r\n",
                 resp->status_code, resp->status_message, conn->keep_alive ? "keep-alive" : "close", resp->body_size);

    // Add custom headers
    for (size_t i = 0; i < resp->headers->count; i++) {
        offset += snprintf(resp->buffer + offset, header_size - offset, "%s: %s\r\n", resp->headers->items[i].name,
                           resp->headers->items[i].value);
    }

    // End headers
    offset += snprintf(resp->buffer + offset, header_size - offset, "\r\n");

    // Add body if present
    if (resp->body_size > 0 && resp->body_data) {
        memcpy(resp->buffer + offset, resp->body_data, resp->body_size);
        offset += resp->body_size;
    }

    resp->bytes_to_send   = offset;
    resp->bytes_sent      = 0;
    resp->headers_written = 1;
}

// =================== Routing ========================
bool http_method_valid(HttpMethod method) {
    return method > HTTP_INVALID && method <= HTTP_DELETE;
}

const char* http_method_to_string(const HttpMethod method) {
    switch (method) {
        case HTTP_GET:
            return "GET";
        case HTTP_POST:
            return "POST";
        case HTTP_PUT:
            return "PUT";
        case HTTP_PATCH:
            return "PATCH";
        case HTTP_OPTIONS:
            return "OPTIONS";
        case HTTP_DELETE:
            return "DELETE";
        default:
            return "";
    }
}

HttpMethod http_method_from_string(const char* method) {
    if (!method) return HTTP_INVALID;
    if (strcmp(method, "GET") == 0) return HTTP_GET;
    if (strcmp(method, "POST") == 0) return HTTP_POST;
    if (strcmp(method, "PUT") == 0) return HTTP_PUT;
    if (strcmp(method, "PATCH") == 0) return HTTP_PATCH;
    if (strcmp(method, "DELETE") == 0) return HTTP_DELETE;
    if (strcmp(method, "OPTIONS") == 0) return HTTP_OPTIONS;
    return HTTP_INVALID;
}

void route_register(const char* pattern, HttpMethod method, HttpHandler handler) {
    assert(global_count < MAX_ROUTES && http_method_valid(method) && pattern && handler);

    route_t* r = &global_routes[global_count++];
    r->pattern = strdup(pattern);
    r->method  = method;
    r->handler = handler;

    assert(r->pattern);
}

route_t* route_match(const char* url, HttpMethod method) {
    for (size_t i = 0; i < global_count; i++) {
        route_t* r = &global_routes[i];
        if (r->method == method && strcmp(url, r->pattern) == 0) {
            return r;
        }
    }
    return NULL;
}

// ====================================================

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        exit(EXIT_FAILURE);
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
        perror("fcntl F_SETFL");
        exit(EXIT_FAILURE);
    }
}

int create_server_socket(int port) {
    int fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return fd;
}

request_t* create_request(Arena* arena) {
    request_t* req = arena_alloc(arena, sizeof(request_t));
    if (!req) return NULL;
    memset(req, 0, sizeof(request_t));

    req->headers = headers_new(arena);
    if (!req->headers) {
        return NULL;
    }

    return req;
}

response_t* create_response(Arena* arena) {
    response_t* resp = arena_alloc(arena, sizeof(response_t));
    if (!resp) return NULL;

    memset(resp, 0, sizeof(response_t));

    resp->headers = headers_new(arena);
    if (!resp->headers) {
        return NULL;
    }
    return resp;
}

void free_request(request_t* req) {
    if (!req) return;
    if (req->body) free(req->body);
}

void free_response(response_t* resp) {
    if (!resp) return;

    if (resp->buffer) free(resp->buffer);
    if (resp->body_data) free(resp->body_data);
}

bool reset_connection(connection_t* conn) {
    conn->state         = STATE_READING_REQUEST;
    conn->read_bytes    = 0;
    conn->last_activity = time(NULL);
    conn->keep_alive    = 1;
    memset(conn->read_buf, 0, BUFFER_SIZE);

    if (conn->request) {
        free_request(conn->request);
    }

    if (conn->response) {
        free_response(conn->response);
    }

    // If we have an arena, reset the memory.
    if (conn->arena) {
        arena_reset(conn->arena);
    } else {
        // Create the and initialize arena.
        conn->arena = arena_create(CONN_ARENA_MEM);
        if (!conn->arena) return false;
    }

    conn->request  = create_request(conn->arena);
    conn->response = create_response(conn->arena);

    return (conn->request && conn->response);
}

int should_keep_alive(const char* request) {
    char* connection_hdr = strstr(request, "Connection:");
    if (!connection_hdr) {
        return 1;
    }

    char* value = connection_hdr + strlen("Connection:");
    while (*value == ' ' || *value == '\t')
        value++;

    if (strncasecmp(value, "close", 5) == 0) {
        return 0;
    }

    return 1;
}

int conn_accept(int server_fd, int worker_id) {
    (void)worker_id;  // might need it later for logging

    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("accept");
        }
        return -1;
    }

    set_nonblocking(client_fd);
    return client_fd;
}

void add_connection_to_worker(int epoll_fd, int client_fd) {
    connection_t* conn = malloc(sizeof(connection_t));
    if (!conn) {
        perror("malloc");
        close(client_fd);
        return;
    }

    memset(conn, 0, sizeof(connection_t));
    conn->fd = client_fd;

    if (!reset_connection(conn)) {
        fprintf(stderr, "Error in reset_connection\n");
        goto error;
    }

    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
    event.data.ptr = conn;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
        perror("epoll_ctl");
        goto error;
    }
    return;

error:
    if (conn->arena) arena_destroy(conn->arena);
    free(conn);
    close(client_fd);
}

static void copy_bodyfrom_buf(connection_t* conn) {
    if (conn->state == STATE_READING_REQUEST && conn->request->body &&
        conn->request->body_received < conn->request->content_length && conn->request->headers_len > 0) {
        size_t new_body = conn->read_bytes - conn->request->headers_len - conn->request->body_received;
        if (new_body > 0) {
            size_t copy_len = ((conn->request->body_received + new_body) > conn->request->content_length)
                                  ? conn->request->content_length - conn->request->body_received
                                  : new_body;

            // Copy partial body read in initial recv.
            memcpy(conn->request->body + conn->request->body_received,
                   conn->read_buf + conn->request->headers_len + conn->request->body_received, copy_len);
            conn->request->body_received += copy_len;
            conn->request->body[conn->request->body_received] = '\0';
        }
    }
}

static bool parse_request_headers(connection_t* conn) {
    const char* ptr = conn->read_buf;
    const char* end = ptr + conn->request->headers_len;

    while (ptr < end) {
        // Parse header name
        const char* colon = (const char*)memchr(ptr, ':', end - ptr);
        if (!colon) break;  // no more headers

        size_t name_len = colon - ptr;
        char* name      = arena_alloc(conn->arena, name_len + 1);
        if (!name) return false;

        memcpy(name, ptr, name_len);
        name[name_len] = '\0';

        // Move to header value
        ptr = colon + 1;
        while (ptr < end && *ptr == ' ')
            ptr++;

        // Parse header value
        const char* eol = (const char*)memchr(ptr, '\r', end - ptr);
        if (!eol || eol + 1 >= end || eol[1] != '\n') break;

        size_t value_len = eol - ptr;
        char* value      = arena_alloc(conn->arena, value_len + 1);
        if (!value) return false;

        memcpy(value, ptr, value_len);
        value[value_len] = '\0';

        if (!headers_append(conn->arena, conn->request->headers, name, value)) {
            return false;
        }

        ptr = eol + 2;  // Skip CRLF
    }

    return true;
}

static inline bool parse_content_length(connection_t* conn) {
    size_t length = conn->request->headers_len;
    char* ptr     = strcasestr(conn->read_buf, "Content-Length:");
    if (ptr) {
        // cl_ptr += strlen("Content-Length:");
        ptr += 15;  // move after colon.

        // Trim white space, keeping within blounds.
        while ((*ptr == ' ' || *ptr == '\t') && ptr < conn->read_buf + length)
            ptr++;

        // Parse content length into number
        conn->request->content_length = strtoul(ptr, NULL, 10);

        // Must be within allowed body size.
        if (conn->request->content_length > MAX_BODY_SIZE) {
            fprintf(stderr, "Body exceeds maximum allowed size: %lu bytes", (size_t)MAX_BODY_SIZE);
            return false;
        }
    }

    return true;
}

static bool parse_request_body(connection_t* conn, size_t headers_len) {
    size_t body_available = conn->read_bytes - headers_len;

    if (conn->request->content_length > 0) {
        conn->request->body = malloc(conn->request->content_length + 1);
        if (!conn->request->body) {
            perror("malloc body");
            return false;
        }

        size_t copy_len =
            (body_available > conn->request->content_length) ? conn->request->content_length : body_available;
        memcpy(conn->request->body, conn->read_buf + headers_len, copy_len);
        conn->request->body_received  = copy_len;
        conn->request->body[copy_len] = '\0';

        // copy part of body read with headers.
        copy_bodyfrom_buf(conn);

        // Read complete body.
        while (conn->request->body_received < conn->request->content_length) {
            size_t remaining = conn->request->content_length - conn->request->body_received;
            ssize_t count    = read(conn->fd, conn->request->body + conn->request->body_received, remaining);
            if (count == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;  // try again
                } else {
                    perror("read");
                    return false;
                }
            } else if (count == 0) {
                perror("read");
                return false;
            }
            conn->request->body_received += count;
        }
    }
    return true;
}

void process_request(connection_t* conn) {
    char* end_of_headers = strstr(conn->read_buf, "\r\n\r\n");
    if (!end_of_headers) return;  // still reading headers

    size_t headers_len         = end_of_headers - conn->read_buf + 4;
    conn->request->headers_len = headers_len;

    char path[1024];
    if (sscanf(conn->read_buf, "%7s %1023s", conn->request->method, path) != 2) {
        fprintf(stderr, "Failed to parse method and path\n");
        conn->state = STATE_CLOSING;
        return;
    }

    conn->request->path = arena_strdup(conn->arena, path);
    if (!conn->request->path) {
        perror("strdup");
        conn->state = STATE_CLOSING;
        return;
    }

    if (!parse_request_headers(conn)) {
        fprintf(stderr, "error parsing request headers\n");
        conn->state = STATE_CLOSING;
        return;
    };

    conn->keep_alive = should_keep_alive(conn->read_buf);

    if (!parse_content_length(conn)) {
        fprintf(stderr, "error parsing content length\n");
        conn->state = STATE_CLOSING;
        return;
    }

    if (!parse_request_body(conn, headers_len)) {
        fprintf(stderr, "error parsing request body\n");
        conn->state = STATE_CLOSING;
        return;
    }

    HttpMethod method = http_method_from_string(conn->request->method);
    route_t* route    = route_match(conn->request->path, method);

    bool handler_success = true;
    if (route) {
        handler_success = route->handler(conn);
    }

    if (!handler_success || !route) {
        // Handle error or 404
        if (!route) {
            conn_set_status(conn, 404, "Not Found");
            conn_writeheader(conn, "Content-Type", "text/plain");
            conn_write(conn, "404 Not Found", 13);
        } else {
            // Handler returned error
            conn_set_status(conn, 500, "Internal Server Error");
            conn_writeheader(conn, "Content-Type", "text/plain");
            conn_write(conn, "500 Internal Server Error", 25);
        }
    }

    // Finalize response after handler completes
    finalize_response(conn);

    if (conn->response->buffer) {
        conn->state         = STATE_WRITING_RESPONSE;
        conn->last_activity = time(NULL);
    } else {
        conn->state = STATE_CLOSING;
    }
}

void handle_read(int epoll_fd, connection_t* conn) {
    ssize_t count = read(conn->fd, conn->read_buf + conn->read_bytes, BUFFER_SIZE - conn->read_bytes - 1);
    if (count == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read");
            conn->state = STATE_CLOSING;
        }
        return;
    } else if (count == 0) {
        conn->state = STATE_CLOSING;
        return;
    }

    conn->last_activity = time(NULL);
    conn->read_bytes += count;
    conn->read_buf[conn->read_bytes] = '\0';

    process_request(conn);

    if (conn->state == STATE_WRITING_RESPONSE) {
        struct epoll_event event;
        event.events   = EPOLLOUT | EPOLLET | EPOLLRDHUP;
        event.data.ptr = conn;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &event) < 0) {
            perror("epoll_ctl mod to EPOLLOUT");
            conn->state = STATE_CLOSING;
        }
        return;
    }
}

void handle_write(int epoll_fd, connection_t* conn) {
    ssize_t count = write(conn->fd, conn->response->buffer + conn->response->bytes_sent,
                          conn->response->bytes_to_send - conn->response->bytes_sent);

    if (count == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("write");
            conn->state = STATE_CLOSING;
        }
        return;
    }

    conn->response->bytes_sent += count;
    conn->last_activity = time(NULL);

    if (conn->response->bytes_sent >= conn->response->bytes_to_send) {
        if (conn->keep_alive) {
            reset_connection(conn);

            struct epoll_event event;
            event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
            event.data.ptr = conn;

            if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &event) < 0) {
                perror("epoll_ctl mod to EPOLLIN");
                conn->state = STATE_CLOSING;
            }
        } else {
            conn->state = STATE_CLOSING;
        }
    }
}

void close_connection(int epoll_fd, connection_t* conn, int worker_id) {
    (void)worker_id;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);

    if (conn->request) free_request(conn->request);
    if (conn->response) free_response(conn->response);
    if (conn->arena) arena_destroy(conn->arena);
    free(conn);
}

void check_timeouts(connection_t* conn, int worker_id) {
    time_t now = time(NULL);
    if (now - conn->last_activity > CONNECTION_TIMEOUT) {
        printf("Worker %d: Connection fd %d timed out\n", worker_id, conn->fd);
        conn->state = STATE_CLOSING;
    }
}

void* worker_thread(void* arg) {
    worker_data_t* worker = (worker_data_t*)arg;
    int epoll_fd          = worker->epoll_fd;
    int worker_id         = worker->worker_id;
    int server_fd         = worker->server_fd;

    struct epoll_event server_event;
    server_event.events  = EPOLLIN | EPOLLEXCLUSIVE;
    server_event.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &server_event) < 0) {
        perror("epoll_ctl for server socket");
        return NULL;
    }

    struct epoll_event events[MAX_EVENTS];
    while (server_running) {
        int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (num_events == -1) {
            perror("epoll_wait");
            continue;
        }

        for (int i = 0; i < num_events; i++) {
            if (events[i].data.fd == server_fd) {
                int client_fd = conn_accept(server_fd, worker_id);
                if (client_fd >= 0) {
                    add_connection_to_worker(epoll_fd, client_fd);
                }
            } else {
                connection_t* conn = (connection_t*)events[i].data.ptr;

                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    conn->state = STATE_CLOSING;
                }

                switch (conn->state) {
                    case STATE_READING_REQUEST:
                        if (events[i].events & EPOLLIN) {
                            handle_read(epoll_fd, conn);
                        }
                        break;
                    case STATE_WRITING_RESPONSE:
                        if (events[i].events & EPOLLOUT) {
                            handle_write(epoll_fd, conn);
                        }
                        break;
                    default:
                        break;
                }

                check_timeouts(conn, worker_id);

                if (conn->state == STATE_CLOSING) {
                    close_connection(epoll_fd, conn, worker_id);
                }
            }
        }
    }

    return NULL;
}

int run() {
    int server_fd = create_server_socket(PORT);
    set_nonblocking(server_fd);

    pthread_t workers[NUM_WORKERS];
    worker_data_t worker_data[NUM_WORKERS];

    install_signal_handler();

    for (int i = 0; i < NUM_WORKERS; i++) {
        int epoll_fd = epoll_create1(0);
        if (epoll_fd == -1) {
            perror("epoll_create1");
            exit(EXIT_FAILURE);
        }

        worker_data[i].epoll_fd  = epoll_fd;
        worker_data[i].worker_id = i;
        worker_data[i].server_fd = server_fd;

        if (pthread_create(&workers[i], NULL, worker_thread, &worker_data[i])) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    printf("Server with %d workers listening on port %d\n", NUM_WORKERS, PORT);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    close(server_fd);

    printf("Terminated server gracefully\n");
    return 0;
}

// =================== Example Handlers Using New API ========================

bool hello_world_handler(connection_t* conn) {
    conn_set_status(conn, 200, "OK");
    conn_writeheader(conn, "Content-Type", "text/plain");
    conn_write(conn, "Hello, World!", 13);
    return true;
}

bool json_handler(connection_t* conn) {
    conn_set_status(conn, 200, "OK");
    conn_writeheader(conn, "Content-Type", "application/json");

    const char* json = "{\"message\": \"Hello from JSON API\", \"status\": \"success\"}";
    conn_write(conn, json, strlen(json));
    return true;
}

bool echo_handler(connection_t* conn) {
    conn_set_status(conn, 200, "OK");
    conn_writeheader(conn, "Content-Type", "text/plain");

    // Echo request method and path
    conn_write(conn, "Method: ", 8);
    conn_write(conn, conn->request->method, strlen(conn->request->method));
    conn_write(conn, "\nPath: ", 7);
    conn_write(conn, conn->request->path, strlen(conn->request->path));

    // Echo body if present
    if (conn->request->body && conn->request->body_received > 0) {
        conn_write(conn, "\nBody: ", 7);
        conn_write(conn, conn->request->body, conn->request->body_received);
    }

    return true;
}

__attribute__((destructor())) void cleanup(void) {
    for (size_t i = 0; i < global_count; i++) {
        free(global_routes[i].pattern);
    }
}

int main() {
    // Register routes using the new API
    route_register("/", HTTP_GET, hello_world_handler);
    route_register("/hello", HTTP_GET, hello_world_handler);
    route_register("/json", HTTP_GET, json_handler);
    route_register("/echo", HTTP_GET, echo_handler);
    route_register("/echo", HTTP_POST, echo_handler);

    return run();
}
