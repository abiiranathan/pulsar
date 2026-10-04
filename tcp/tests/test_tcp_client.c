/* Integration tests for tcp_client: async connect, echo, backpressure,
 * adopt, multi-connection and cross-thread stop. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tcp/tcp.h"

static int g_failures = 0;
#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failures++;                                                 \
        }                                                                 \
    } while (0)

static unsigned char expected_byte(size_t i, unsigned seed) {
    return (unsigned char)((i * 131u + seed * 17u + 7u) & 0xffu);
}

static void clear_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

/* ----------------------------------------------------------------
 * Echo server: accepts and spawns one thread per connection.
 * ---------------------------------------------------------------- */

typedef struct {
    int listen_fd;
    volatile int stop;
} EchoServer;

static void* echo_conn(void* arg) {
    int c = *(int*)arg;
    free(arg);
    clear_nonblock(c);

    char buf[65536];
    for (;;) {
        ssize_t n = read(c, buf, sizeof(buf));
        if (n <= 0) break;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(c, buf + off, (size_t)(n - off));
            if (w <= 0) goto done;
            off += w;
        }
    }
done:
    close(c);
    return NULL;
}

static void* echo_server_thread(void* arg) {
    EchoServer* s = (EchoServer*)arg;
    struct pollfd pfd = {.fd = s->listen_fd, .events = POLLIN};
    while (!s->stop) {
        int r = poll(&pfd, 1, 50);
        if (r <= 0) continue;
        int c = tcp_accept(s->listen_fd, NULL, 0);
        if (c < 0) continue;
        int* pc = malloc(sizeof(int));
        if (!pc) {
            close(c);
            continue;
        }
        *pc = c;
        pthread_t t;
        if (pthread_create(&t, NULL, echo_conn, pc) != 0) {
            free(pc);
            close(c);
        } else {
            pthread_detach(t);
        }
    }
    return NULL;
}

static EchoServer* server_start(int* out_port) {
    tcp_listen_opts_t lo = tcp_listen_opts_default();
    int lfd = tcp_listen("127.0.0.1", 0, &lo);
    if (lfd < 0) return NULL;

    EchoServer* s = calloc(1, sizeof(*s));
    if (!s) {
        close(lfd);
        return NULL;
    }
    s->listen_fd = lfd;
    *out_port = tcp_local_port(lfd);

    pthread_t th;
    if (pthread_create(&th, NULL, echo_server_thread, s) != 0) {
        free(s);
        close(lfd);
        return NULL;
    }
    pthread_detach(th);
    return s;
}

static void server_stop(EchoServer* s) {
    if (!s) return;
    s->stop = 1;
    usleep(100 * 1000);
    close(s->listen_fd);
    free(s);
}

/* ----------------------------------------------------------------
 * Client driver
 * ---------------------------------------------------------------- */

typedef struct {
    tcp_client_t* cli;
    tcp_conn_t* conn;
    size_t to_send;
    size_t sent;
    size_t to_recv;
    size_t recv;
    unsigned seed;
    int connected;
    int closed;
    int close_err;
    int mismatch;
    int send_error;
} CState;

static void pump(CState* st) {
    const size_t chunk = 256 * 1024;
    static unsigned char buf[256 * 1024];

    while (st->sent < st->to_send) {
        size_t n = st->to_send - st->sent;
        if (n > chunk) n = chunk;
        for (size_t i = 0; i < n; i++) buf[i] = expected_byte(st->sent + i, st->seed);

        ssize_t w = tcp_conn_write(st->conn, buf, n);
        if (w < 0) {
            if (errno == ENOBUFS) return; /* wait for on_writable */
            st->send_error = 1;
            tcp_conn_close(st->conn);
            return;
        }
        st->sent += (size_t)w;
    }
}

static void on_connected(tcp_conn_t* c) {
    CState* st = tcp_conn_userdata(c);
    st->connected = 1;
    pump(st);
}

static void on_data(tcp_conn_t* c, const void* data, size_t len) {
    CState* st = tcp_conn_userdata(c);
    const unsigned char* p = data;

    if (st->recv + len > st->to_recv) {
        st->mismatch = 1;
        tcp_conn_close(c);
        return;
    }
    for (size_t i = 0; i < len; i++) {
        if (p[i] != expected_byte(st->recv + i, st->seed)) st->mismatch = 1;
    }
    st->recv += len;

    if (st->recv >= st->to_recv) tcp_conn_close(c);
}

static void on_writable(tcp_conn_t* c) {
    CState* st = tcp_conn_userdata(c);
    pump(st);
}

static void on_closed(tcp_conn_t* c, int err) {
    CState* st = tcp_conn_userdata(c);
    st->closed = 1;
    st->close_err = err;
    /* The loop exits on its own via exit_when_idle once every connection is
     * gone, so multiple concurrent connections are supported. */
}

static const tcp_conn_cbs_t echo_cbs = {
    .on_connected = on_connected,
    .on_data = on_data,
    .on_writable = on_writable,
    .on_closed = on_closed,
};

static void run_echo_roundtrip(size_t size, unsigned seed) {
    int port = 0;
    EchoServer* srv = server_start(&port);
    CHECK(srv != NULL);

    tcp_client_t* cli = tcp_client_create(NULL);
    CHECK(cli != NULL);

    CState st;
    memset(&st, 0, sizeof(st));
    st.cli = cli;
    st.to_send = size;
    st.to_recv = size;
    st.seed = seed;

    st.conn = tcp_client_connect(cli, "127.0.0.1", port, &st, &echo_cbs);
    CHECK(st.conn != NULL);

    int rc = tcp_client_run(cli);
    CHECK(rc == 0);
    CHECK(st.connected == 1);
    CHECK(st.closed == 1);
    CHECK(st.send_error == 0);
    CHECK(st.mismatch == 0);
    CHECK(st.recv == size);

    tcp_client_destroy(cli);
    server_stop(srv);
}

static void test_small_roundtrip(void) { run_echo_roundtrip(64 * 1024, 1); }
static void test_large_roundtrip(void) { run_echo_roundtrip(2 * 1024 * 1024, 2); }

static void test_connect_failure(void) {
    tcp_client_t* cli = tcp_client_create(NULL);
    CHECK(cli != NULL);

    CState st;
    memset(&st, 0, sizeof(st));
    st.cli = cli;

    /* Depends on nothing listening on port 1. */
    tcp_conn_t* c = tcp_client_connect(cli, "127.0.0.1", 1, &st, &echo_cbs);
    CHECK(c != NULL);

    int rc = tcp_client_run(cli);
    CHECK(rc == 0);
    CHECK(st.closed == 1);
    CHECK(st.close_err != 0);

    tcp_client_destroy(cli);
}

static void test_client_add(void) {
    int port = 0;
    EchoServer* srv = server_start(&port);
    CHECK(srv != NULL);

    int fd = tcp_connect("127.0.0.1", port, NULL);
    CHECK(fd >= 0);

    tcp_client_t* cli = tcp_client_create(NULL);
    CHECK(cli != NULL);

    CState st;
    memset(&st, 0, sizeof(st));
    st.cli = cli;
    st.to_send = 1024;
    st.to_recv = 1024;
    st.seed = 9;

    st.conn = tcp_client_add(cli, fd, &st, &echo_cbs);
    CHECK(st.conn != NULL);

    tcp_client_run(cli);
    CHECK(st.connected == 1);
    CHECK(st.closed == 1);
    CHECK(st.mismatch == 0);
    CHECK(st.recv == 1024);

    tcp_client_destroy(cli);
    server_stop(srv);
}

static void test_multiple_connections(void) {
    int port = 0;
    EchoServer* srv = server_start(&port);
    CHECK(srv != NULL);

    enum { N = 8, MSG = 32 * 1024 };
    tcp_client_t* cli = tcp_client_create(NULL);
    CHECK(cli != NULL);

    CState states[N];
    memset(states, 0, sizeof(states));
    for (int i = 0; i < N; i++) {
        states[i].cli = cli;
        states[i].to_send = MSG;
        states[i].to_recv = MSG;
        states[i].seed = (unsigned)(i + 1);
        states[i].conn = tcp_client_connect(cli, "127.0.0.1", port, &states[i], &echo_cbs);
        CHECK(states[i].conn != NULL);
    }

    tcp_client_run(cli);

    for (int i = 0; i < N; i++) {
        CHECK(states[i].closed == 1);
        CHECK(states[i].mismatch == 0);
        CHECK(states[i].recv == MSG);
    }

    tcp_client_destroy(cli);
    server_stop(srv);
}

static void* stopper_thread(void* arg) {
    tcp_client_t* cli = arg;
    usleep(150 * 1000);
    tcp_client_stop(cli);
    return NULL;
}

static void test_cross_thread_stop(void) {
    tcp_client_config_t cfg = tcp_client_config_default();
    cfg.exit_when_idle = 0; /* stay alive until explicitly stopped */

    tcp_client_t* cli = tcp_client_create(&cfg);
    CHECK(cli != NULL);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, stopper_thread, cli) == 0);

    int rc = tcp_client_run(cli);
    CHECK(rc == 0);

    pthread_join(th, NULL);
    tcp_client_destroy(cli);
}

int main(void) {
    test_small_roundtrip();
    test_large_roundtrip();
    test_connect_failure();
    test_client_add();
    test_multiple_connections();
    test_cross_thread_stop();

    if (g_failures) {
        fprintf(stderr, "test_tcp_client: %d failure(s)\n", g_failures);
        return 1;
    }
    printf("test_tcp_client: OK\n");
    return 0;
}
