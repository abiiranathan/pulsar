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

#define MAX_EVENTS         SOMAXCONN
#define BUFFER_SIZE        4096
#define PORT               8080
#define CONNECTION_TIMEOUT 30  // seconds
#define NUM_WORKERS        8   // Number of worker threads

// Connection states
typedef enum { STATE_READING_REQUEST, STATE_WRITING_RESPONSE, STATE_CLOSING } connection_state;

// Connection data structure
typedef struct {
    int fd;
    connection_state state;
    char read_buf[BUFFER_SIZE];
    size_t read_bytes;
    char write_buf[BUFFER_SIZE];
    size_t write_bytes;
    size_t write_sent;
    time_t last_activity;
    int keep_alive;
} connection_t;

// Worker thread data
typedef struct {
    int epoll_fd;
    int worker_id;
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

// Reset connection for new request
void reset_connection(connection_t* conn) {
    conn->state         = STATE_READING_REQUEST;
    conn->read_bytes    = 0;
    conn->write_bytes   = 0;
    conn->write_sent    = 0;
    conn->last_activity = time(NULL);
    memset(conn->read_buf, 0, BUFFER_SIZE);
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

    printf("Worker %d accepted new connection from %s:%d (fd: %d)\n", worker_id, inet_ntoa(client_addr.sin_addr),
           ntohs(client_addr.sin_port), client_fd);

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
    // Check for complete headers
    char* end_of_headers = strstr(conn->read_buf, "\r\n\r\n");
    if (!end_of_headers) {
        // Incomplete request, keep reading
        return;
    }

    // Check if we should keep the connection alive
    conn->keep_alive = should_keep_alive(conn->read_buf);

    // Prepare HTTP response
    const char* response_fmt =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: %s\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "Hello, World!";

    conn->write_bytes = snprintf(conn->write_buf, BUFFER_SIZE, response_fmt, conn->keep_alive ? "keep-alive" : "close");

    if (conn->write_bytes >= BUFFER_SIZE) {
        fprintf(stderr, "Response too large\n");
        conn->state = STATE_CLOSING;
        return;
    }

    conn->write_sent    = 0;
    conn->state         = STATE_WRITING_RESPONSE;
    conn->last_activity = time(NULL);
}

// Handle read event
void handle_read(int epoll_fd, connection_t* conn) {
    ssize_t count = read(conn->fd, conn->read_buf + conn->read_bytes, BUFFER_SIZE - conn->read_bytes - 1);

    if (count == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read");
            conn->state = STATE_CLOSING;
        }
        return;
    } else if (count == 0) {
        // Connection closed by client
        conn->state = STATE_CLOSING;
        return;
    }

    conn->read_bytes += count;
    conn->read_buf[conn->read_bytes] = '\0';
    conn->last_activity              = time(NULL);

    // Process the request if we have complete headers
    process_request(conn);

    // If we're now in writing state, modify epoll events
    if (conn->state == STATE_WRITING_RESPONSE) {
        struct epoll_event event;
        event.events   = EPOLLOUT | EPOLLET | EPOLLRDHUP;
        event.data.ptr = conn;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &event) < 0) {
            perror("epoll_ctl mod to EPOLLOUT");
            conn->state = STATE_CLOSING;
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
    printf("Worker %d closing connection on fd %d\n", worker_id, conn->fd);
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);
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
