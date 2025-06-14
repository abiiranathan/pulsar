#include <stdio.h>       //Standard I/O functions
#include <stdlib.h>      //Memory allocation and utility functions
#include <string.h>      // String manipulation functions
#include <unistd.h>      // POSIX API for system calls
#include <sys/socket.h>  //Socket programming interfaces
#include <netinet/in.h>  // Internet protocol family definitions
#include <arpa/inet.h>   // Internet address manipulation
#include <sys/epoll.h>   // Epoll I/O event notification interface
#include <fcntl.h>       // File control options
#include <errno.h>       // Error number definitions
#include <time.h>        // Time/date utilities
#include <pthread.h>     // POSIX threads

#define MAX_EVENTS         1024       // Maximum number of events epoll can return at once
#define BUFFER_SIZE        4096       //  Size of read buffer (4096 bytes)
#define PORT               8080       // Server listening port (8080)
#define CONNECTION_TIMEOUT 30         //  Inactive connection timeout in seconds (30)
#define NUM_WORKERS        8          // Number of worker threads
#define MAX_BODY_SIZE      (2 << 20)  // 2 MB

// Connection states
typedef enum {
    STATE_READING_REQUEST,   // Connection is reading HTTP request
    STATE_WRITING_RESPONSE,  // Connection is writing HTTP response
    STATE_CLOSING            // Connection is being closed
} connection_state;

// Connection data structure
typedef struct {
    int fd;                  // Client socket file descriptor
    connection_state state;  // Current connection state

    char read_buf[BUFFER_SIZE];  // Buffer for incoming data
    size_t read_bytes;           // Bytes currently in read buffer

    char* write_buf;     // Buffer for outgoing data
    size_t write_bytes;  // Total bytes to write
    size_t write_sent;   // Bytes already sent
    size_t write_alloc;  // Bytes allocated for write buffer

    char method[8];         // HTTP method (GET, POST etc.)
    char* path;             // Pointer to dynamically allocated requested path
    size_t content_length;  // Content-Length header value
    char* request_body;     // Pointer to dynamically allocated request body
    size_t headers_len;     // Length of headers section
    size_t body_received;   // Bytes of body received

    time_t last_activity;  // Timestamp of last I/O activity
    int keep_alive;        // Keep-alive flag
} connection_t;

// Worker thread data
typedef struct {
    int epoll_fd;   // Worker's epoll file descriptor
    int worker_id;  // Worker thread identifier
} worker_data_t;

// Global server socket
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

    // Create an Internet socket.
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // set port reuse option.
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family      = AF_INET;      // TCP internet Ipv4 address
    address.sin_addr.s_addr = INADDR_ANY;   // Bind on any interface
    address.sin_port        = htons(port);  // Set port (host-network)

    // Bind the socket.
    if (bind(fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections with backlog of SOMAXCONN
    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return fd;
}

// Reset connection for new request
void reset_connection(connection_t* conn) {
    conn->state          = STATE_READING_REQUEST;
    conn->read_bytes     = 0;
    conn->write_bytes    = 0;
    conn->write_sent     = 0;
    conn->write_alloc    = 0;
    conn->last_activity  = time(NULL);
    conn->content_length = 0;
    conn->body_received  = 0;
    conn->headers_len    = 0;
    conn->keep_alive     = 1;
    memset(conn->read_buf, 0, BUFFER_SIZE);
    memset(conn->method, 0, sizeof(conn->method));

    if (conn->write_buf) {
        free(conn->write_buf);
        conn->write_buf = NULL;
    }

    if (conn->request_body) {
        free(conn->request_body);
        conn->request_body = NULL;
    }

    if (conn->path) {
        free(conn->path);
        conn->path = NULL;
    }
}

// Check if connection should be kept alive
int should_keep_alive(const char* request) {
    char* connection_hdr = strstr(request, "Connection:");
    if (!connection_hdr) {
        // HTTP/1.1 defaults to keep-alive
        return 1;
    }

    // Find the value after Connection:
    char* value = connection_hdr + strlen("Connection:");
    while (*value == ' ' || *value == '\t')
        value++;

    // Check for "close"
    if (strncasecmp(value, "close", 5) == 0) {
        return 0;
    }

    // Otherwise assume keep-alive
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

    // printf("Worker %d accepted new connection from %s:%d (fd: %d)\n", worker_id, inet_ntoa(client_addr.sin_addr),
    //        ntohs(client_addr.sin_port), client_fd);

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
    conn->fd            = client_fd;
    conn->last_activity = time(NULL);
    reset_connection(conn);

    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
    event.data.ptr = conn;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
        perror("epoll_ctl");
        free(conn);
        close(client_fd);
    }
}

// Process HTTP request and prepare response
void process_request(connection_t* conn) {
    char* end_of_headers = strstr(conn->read_buf, "\r\n\r\n");
    if (!end_of_headers) return;

    size_t headers_len = end_of_headers - conn->read_buf + 4;
    conn->headers_len  = headers_len;

    // Read http method and path.
    char path[1024];
    if (sscanf(conn->read_buf, "%7s %1023s", conn->method, path) != 2) {
        fprintf(stderr, "Failed to parse method and path\n");
        conn->state = STATE_CLOSING;
        return;
    }

    // Copy the path
    conn->path = strdup(path);
    if (!conn->path) {
        perror("strdup");
        conn->state = STATE_CLOSING;
        return;
    }

    // Log method and path
    // printf("%s %s\n", conn->method, conn->path);

    conn->keep_alive = should_keep_alive(conn->read_buf);

    // Parse Content-Length
    char* cl = strcasestr(conn->read_buf, "Content-Length:");
    if (cl) {
        cl += strlen("Content-Length:");
        while (*cl == ' ' || *cl == '\t')
            cl++;
        conn->content_length = strtoul(cl, NULL, 10);

        if (conn->content_length > MAX_BODY_SIZE) {
            fprintf(stderr, "Body exceeds maximum allowed size: %lu bytes", (size_t)MAX_BODY_SIZE);
            conn->state = STATE_CLOSING;
            return;
        }
    }

    size_t body_available = conn->read_bytes - headers_len;
    if (conn->content_length > 0) {
        conn->request_body = malloc(conn->content_length + 1);
        if (!conn->request_body) {
            perror("malloc body");
            conn->state = STATE_CLOSING;
            return;
        }

        size_t copy_len = (body_available > conn->content_length) ? conn->content_length : body_available;
        memcpy(conn->request_body, conn->read_buf + headers_len, copy_len);
        conn->body_received          = copy_len;
        conn->request_body[copy_len] = '\0';

        // Wait for remaining body
        if (conn->body_received < conn->content_length) return;
    }

    // TODO: Add routing here

    // Prepare a dynamic response
    const char* body    = "Hello, Dynamic World!";
    size_t body_len     = strlen(body);
    size_t response_len = 128 + body_len;

    conn->write_buf = malloc(response_len);
    if (!conn->write_buf) {
        perror("malloc response");
        conn->state = STATE_CLOSING;
        return;
    }

    conn->write_alloc = response_len;
    conn->write_bytes = snprintf(conn->write_buf, response_len,
                                 "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: text/plain\r\n"
                                 "Connection: %s\r\n"
                                 "Content-Length: %zu\r\n"
                                 "\r\n"
                                 "%s",
                                 conn->keep_alive ? "keep-alive" : "close", body_len, body);

    conn->write_sent    = 0;
    conn->state         = STATE_WRITING_RESPONSE;
    conn->last_activity = time(NULL);
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
        if (conn->state == STATE_READING_REQUEST && conn->request_body && conn->body_received < conn->content_length &&
            conn->headers_len > 0) {
            size_t new_body = conn->read_bytes - conn->headers_len - conn->body_received;
            if (new_body > 0) {
                size_t copy_len = ((conn->body_received + new_body) > conn->content_length)
                                      ? conn->content_length - conn->body_received
                                      : new_body;

                memcpy(conn->request_body + conn->body_received,
                       conn->read_buf + conn->headers_len + conn->body_received, copy_len);
                conn->body_received += copy_len;
                conn->request_body[conn->body_received] = '\0';
            }

            if (conn->body_received < conn->content_length) return;
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
    ssize_t count = write(conn->fd, conn->write_buf + conn->write_sent, conn->write_bytes - conn->write_sent);

    if (count == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("write");
            conn->state = STATE_CLOSING;
        }
        return;
    }

    conn->write_sent += count;
    conn->last_activity = time(NULL);

    // If we've sent the entire response
    if (conn->write_sent >= conn->write_bytes) {
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
    // printf("Worker %d closing connection on fd %d\n", worker_id, conn->fd);
    (void)worker_id;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);

    if (conn->path) free(conn->path);
    if (conn->write_buf) free(conn->write_buf);
    if (conn->request_body) free(conn->request_body);
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

    // Add server socket to epoll with EPOLLEXCLUSIVE (only once)
    struct epoll_event server_event;
    server_event.events  = EPOLLIN | EPOLLEXCLUSIVE;
    server_event.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &server_event) < 0) {
        perror("epoll_ctl for server socket");
        return NULL;
    }

    struct epoll_event events[MAX_EVENTS];
    while (1) {
        int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);  // 1s timeout
        if (num_events == -1) {
            perror("epoll_wait");
            continue;
        }

        for (int i = 0; i < num_events; i++) {
            if (events[i].data.fd == server_fd) {
                // New connection - accept and add to our epoll
                int client_fd = safe_accept(worker_id);
                if (client_fd >= 0) {
                    add_connection_to_worker(epoll_fd, client_fd);
                }
            } else {
                // Existing connection
                connection_t* conn = (connection_t*)events[i].data.ptr;

                // Check for errors or hangup
                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    conn->state = STATE_CLOSING;
                }

                // Handle based on current state
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

                // Check for timeout in any state
                check_timeouts(conn, worker_id);

                // Close if needed
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

    // Wait for all worker threads (though they should run forever)
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    close(server_fd);
    return 0;
}
