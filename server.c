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

#define MAX_EVENTS         1024
#define BUFFER_SIZE        4096
#define PORT               8080
#define CONNECTION_TIMEOUT 30
#define NUM_WORKERS        8
#define MAX_BODY_SIZE      (2 << 20)

// Connection states
typedef enum { STATE_READING_REQUEST, STATE_WRITING_RESPONSE, STATE_CLOSING } connection_state;

// HTTP Request structure
typedef struct {
    char method[8];         // HTTP method (GET, POST etc.)
    char* path;             // Requested path
    size_t content_length;  // Content-Length header value
    char* body;             // Request body
    size_t body_received;   // Bytes of body received
    size_t headers_len;     // Length of headers section
} request_t;

// HTTP Response structure
typedef struct {
    char* buffer;          // Buffer for outgoing data
    size_t bytes_to_send;  // Total bytes to write
    size_t bytes_sent;     // Bytes already sent
    size_t buffer_size;    // Bytes allocated for buffer
} response_t;

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
} connection_t;

// Worker thread data
typedef struct {
    int epoll_fd;
    int worker_id;
} worker_data_t;

int server_fd;

// Set socket to non-blocking mode
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

// Create and bind server socket
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

// Initialize a new request structure
request_t* create_request() {
    request_t* req = malloc(sizeof(request_t));
    if (!req) return NULL;

    memset(req, 0, sizeof(request_t));
    return req;
}

// Initialize a new response structure
response_t* create_response() {
    response_t* resp = malloc(sizeof(response_t));
    if (!resp) return NULL;

    memset(resp, 0, sizeof(response_t));
    return resp;
}

// Free request resources
void free_request(request_t* req) {
    if (!req) return;

    if (req->path) free(req->path);
    if (req->body) free(req->body);
    free(req);
}

// Free response resources
void free_response(response_t* resp) {
    if (!resp) return;

    if (resp->buffer) free(resp->buffer);
    free(resp);
}

// Reset connection for new request
void reset_connection(connection_t* conn) {
    conn->state         = STATE_READING_REQUEST;
    conn->read_bytes    = 0;
    conn->last_activity = time(NULL);
    conn->keep_alive    = 1;
    memset(conn->read_buf, 0, BUFFER_SIZE);

    // Reset or recreate request and response
    if (conn->request) {
        free_request(conn->request);
    }
    conn->request = create_request();

    if (conn->response) {
        free_response(conn->response);
    }
    conn->response = create_response();
}

// Check if connection should be kept alive
int should_keep_alive(const char* request) {
    char* connection_hdr = strstr(request, "Connection:");
    if (!connection_hdr) {
        return 1;  // HTTP/1.1 defaults to keep-alive
    }

    char* value = connection_hdr + strlen("Connection:");
    while (*value == ' ' || *value == '\t')
        value++;

    if (strncasecmp(value, "close", 5) == 0) {
        return 0;
    }

    return 1;
}

// Handle new connection with thread-safe accept
int safe_accept(int worker_id) {
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
    (void)worker_id;
    return client_fd;
}

// Add new connection to worker's epoll instance
void add_connection_to_worker(int epoll_fd, int client_fd) {
    connection_t* conn = malloc(sizeof(connection_t));
    if (!conn) {
        perror("malloc");
        close(client_fd);
        return;
    }

    memset(conn, 0, sizeof(connection_t));
    conn->fd       = client_fd;
    conn->request  = create_request();
    conn->response = create_response();
    reset_connection(conn);

    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
    event.data.ptr = conn;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
        perror("epoll_ctl");
        free_request(conn->request);
        free_response(conn->response);
        free(conn);
        close(client_fd);
    }
}

// Process HTTP request and prepare response
void process_request(connection_t* conn) {
    char* end_of_headers = strstr(conn->read_buf, "\r\n\r\n");
    if (!end_of_headers) return;

    size_t headers_len         = end_of_headers - conn->read_buf + 4;
    conn->request->headers_len = headers_len;

    // Parse method and path
    char path[1024];
    if (sscanf(conn->read_buf, "%7s %1023s", conn->request->method, path) != 2) {
        fprintf(stderr, "Failed to parse method and path\n");
        conn->state = STATE_CLOSING;
        return;
    }

    conn->request->path = strdup(path);
    if (!conn->request->path) {
        perror("strdup");
        conn->state = STATE_CLOSING;
        return;
    }

    conn->keep_alive = should_keep_alive(conn->read_buf);

    // Parse Content-Length
    char* cl = strcasestr(conn->read_buf, "Content-Length:");
    if (cl) {
        cl += strlen("Content-Length:");
        while (*cl == ' ' || *cl == '\t')
            cl++;
        conn->request->content_length = strtoul(cl, NULL, 10);

        if (conn->request->content_length > MAX_BODY_SIZE) {
            fprintf(stderr, "Body exceeds maximum allowed size: %lu bytes", (size_t)MAX_BODY_SIZE);
            conn->state = STATE_CLOSING;
            return;
        }
    }

    size_t body_available = conn->read_bytes - headers_len;
    if (conn->request->content_length > 0) {
        conn->request->body = malloc(conn->request->content_length + 1);
        if (!conn->request->body) {
            perror("malloc body");
            conn->state = STATE_CLOSING;
            return;
        }

        size_t copy_len =
            (body_available > conn->request->content_length) ? conn->request->content_length : body_available;
        memcpy(conn->request->body, conn->read_buf + headers_len, copy_len);
        conn->request->body_received  = copy_len;
        conn->request->body[copy_len] = '\0';

        // Wait for remaining body
        if (conn->request->body_received < conn->request->content_length) return;
    }

    // TODO: Add routing here

    // Prepare response
    const char* body    = "Hello, Dynamic World!";
    size_t body_len     = strlen(body);
    size_t response_len = 128 + body_len;

    conn->response->buffer = malloc(response_len);
    if (!conn->response->buffer) {
        perror("malloc response");
        conn->state = STATE_CLOSING;
        return;
    }

    conn->response->buffer_size   = response_len;
    conn->response->bytes_to_send = snprintf(conn->response->buffer, response_len,
                                             "HTTP/1.1 200 OK\r\n"
                                             "Content-Type: text/plain\r\n"
                                             "Connection: %s\r\n"
                                             "Content-Length: %zu\r\n"
                                             "\r\n"
                                             "%s",
                                             conn->keep_alive ? "keep-alive" : "close", body_len, body);

    conn->response->bytes_sent = 0;
    conn->state                = STATE_WRITING_RESPONSE;
    conn->last_activity        = time(NULL);
}

// Handle read event
void handle_read(int epoll_fd, connection_t* conn) {
    while (1) {
        ssize_t count = read(conn->fd, conn->read_buf + conn->read_bytes, BUFFER_SIZE - conn->read_bytes - 1);
        if (count == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("read");
                conn->state = STATE_CLOSING;
            }
            break;
        } else if (count == 0) {
            conn->state = STATE_CLOSING;
            break;
        }

        conn->last_activity = time(NULL);
        conn->read_bytes += count;
        conn->read_buf[conn->read_bytes] = '\0';

        // If we are expecting body
        if (conn->state == STATE_READING_REQUEST && conn->request->body &&
            conn->request->body_received < conn->request->content_length && conn->request->headers_len > 0) {
            size_t new_body = conn->read_bytes - conn->request->headers_len - conn->request->body_received;
            if (new_body > 0) {
                size_t copy_len = ((conn->request->body_received + new_body) > conn->request->content_length)
                                      ? conn->request->content_length - conn->request->body_received
                                      : new_body;

                memcpy(conn->request->body + conn->request->body_received,
                       conn->read_buf + conn->request->headers_len + conn->request->body_received, copy_len);
                conn->request->body_received += copy_len;
                conn->request->body[conn->request->body_received] = '\0';
            }

            if (conn->request->body_received < conn->request->content_length) return;
        }

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
}

// Handle write event
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

    // If we've sent the entire response
    if (conn->response->bytes_sent >= conn->response->bytes_to_send) {
        if (conn->keep_alive) {
            // Reset connection for next request
            reset_connection(conn);

            // Modify epoll events back to reading
            struct epoll_event event;
            event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
            event.data.ptr = conn;

            if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &event) < 0) {
                perror("epoll_ctl mod to EPOLLIN");
                conn->state = STATE_CLOSING;
            }
        } else {
            // Client requested connection close
            conn->state = STATE_CLOSING;
        }
    }
}

// Close connection and clean up
void close_connection(int epoll_fd, connection_t* conn, int worker_id) {
    (void)worker_id;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);

    if (conn->request) free_request(conn->request);
    if (conn->response) free_response(conn->response);
    free(conn);
}

// Check for timed out connections
void check_timeouts(connection_t* conn, int worker_id) {
    time_t now = time(NULL);
    if (now - conn->last_activity > CONNECTION_TIMEOUT) {
        printf("Worker %d: Connection fd %d timed out\n", worker_id, conn->fd);
        conn->state = STATE_CLOSING;
    }
}

// Worker thread function
void* worker_thread(void* arg) {
    worker_data_t* worker = (worker_data_t*)arg;
    int epoll_fd          = worker->epoll_fd;
    int worker_id         = worker->worker_id;

    printf("Worker %d starting\n", worker_id);

    // Add server socket to epoll with EPOLLEXCLUSIVE
    struct epoll_event server_event;
    server_event.events  = EPOLLIN | EPOLLEXCLUSIVE;
    server_event.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &server_event) < 0) {
        perror("epoll_ctl for server socket");
        return NULL;
    }

    struct epoll_event events[MAX_EVENTS];
    while (1) {
        int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (num_events == -1) {
            perror("epoll_wait");
            continue;
        }

        for (int i = 0; i < num_events; i++) {
            if (events[i].data.fd == server_fd) {
                int client_fd = safe_accept(worker_id);
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

int main() {
    server_fd = create_server_socket(PORT);
    set_nonblocking(server_fd);

    pthread_t workers[NUM_WORKERS];
    worker_data_t worker_data[NUM_WORKERS];

    // Create worker threads
    for (int i = 0; i < NUM_WORKERS; i++) {
        int epoll_fd = epoll_create1(0);
        if (epoll_fd == -1) {
            perror("epoll_create1");
            exit(EXIT_FAILURE);
        }

        worker_data[i].epoll_fd  = epoll_fd;
        worker_data[i].worker_id = i;

        if (pthread_create(&workers[i], NULL, worker_thread, &worker_data[i])) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    printf("Server with %d workers listening on port %d\n", NUM_WORKERS, PORT);

    // Wait for all worker threads
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    close(server_fd);
    return 0;
}
