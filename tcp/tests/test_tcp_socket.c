/* Integration tests for tcp_socket: listen, accept, connect, names. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tcp/tcp_socket.h"

static int g_failures = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failures++;                                               \
        }                                                               \
    } while (0)

static void clear_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

typedef struct {
    int listen_fd;
    int echo_bytes;
} EchoArgs;

static void* echo_once(void* arg) {
    EchoArgs* a = (EchoArgs*)arg;
    int c = -1;
    for (int i = 0; i < 100 && c < 0; i++) {
        struct pollfd pfd = {.fd = a->listen_fd, .events = POLLIN};
        if (poll(&pfd, 1, 50) == 1) c = tcp_accept(a->listen_fd, NULL, 0);
    }
    if (c < 0) return NULL;
    clear_nonblock(c);

    char buf[4096];
    int remaining = a->echo_bytes;
    while (remaining > 0) {
        ssize_t n = read(c, buf, sizeof(buf));
        if (n <= 0) break;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(c, buf + off, (size_t)(n - off));
            if (w <= 0) break;
            off += w;
        }
        remaining -= (int)n;
    }
    close(c);
    return NULL;
}

static void test_listen_accept_connect(void) {
    tcp_listen_opts_t lo = tcp_listen_opts_default();
    lo.reuse_port = 1;
    int lfd = tcp_listen("127.0.0.1", 0, &lo);
    CHECK(lfd >= 0);

    int port = tcp_local_port(lfd);
    CHECK(port > 0);

    EchoArgs args = {.listen_fd = lfd, .echo_bytes = 11};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, echo_once, &args) == 0);

    tcp_connect_opts_t co = tcp_connect_opts_default();
    int fd = tcp_connect("127.0.0.1", port, &co);
    CHECK(fd >= 0);

    const char* msg = "hello world";
    CHECK(write(fd, msg, 11) == 11);

    /* fd is non-blocking: wait for the echo before reading it. */
    char buf[64];
    size_t got = 0;
    while (got < 11) {
        struct pollfd rp = {.fd = fd, .events = POLLIN};
        int pr = poll(&rp, 1, 2000);
        CHECK(pr == 1);
        if (pr <= 0) break;
        ssize_t n = read(fd, buf + got, sizeof(buf) - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    CHECK(got == 11);
    CHECK(memcmp(buf, msg, 11) == 0);

    char local[64], peer[64];
    CHECK(tcp_local_name(fd, local, sizeof(local)) == 0);
    CHECK(tcp_peer_name(fd, peer, sizeof(peer)) == 0);
    CHECK(strncmp(local, "127.0.0.1:", 10) == 0);
    CHECK(strncmp(peer, "127.0.0.1:", 10) == 0);

    close(fd);
    pthread_join(th, NULL);
    close(lfd);
}

static void test_async_connect_and_accept_peer(void) {
    tcp_listen_opts_t lo = tcp_listen_opts_default();
    int lfd = tcp_listen("127.0.0.1", 0, &lo);
    CHECK(lfd >= 0);
    int port = tcp_local_port(lfd);
    CHECK(port > 0);

    int fd = tcp_connect_start("127.0.0.1", port, NULL);
    CHECK(fd >= 0);

    /* Wait for the listener to become readable, then accept with peer info. */
    struct pollfd pfd = {.fd = lfd, .events = POLLIN};
    CHECK(poll(&pfd, 1, 2000) == 1);

    char peer[64];
    int c = tcp_accept(lfd, peer, sizeof(peer));
    CHECK(c >= 0);
    CHECK(strncmp(peer, "127.0.0.1:", 10) == 0);

    struct pollfd wpfd = {.fd = fd, .events = POLLOUT};
    CHECK(poll(&wpfd, 1, 2000) == 1);
    CHECK(tcp_connect_check(fd) == 0);

    close(c);
    close(fd);
    close(lfd);
}

static void test_connect_refused(void) {
    /* Port 1 is almost certainly unused and privileged. */
    int fd = tcp_connect_start("127.0.0.1", 1, NULL);
    if (fd < 0) {
        CHECK(errno == ECONNREFUSED || errno == EACCES);
        return;
    }

    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    CHECK(poll(&pfd, 1, 2000) == 1);
    int st = tcp_connect_check(fd);
    CHECK(st == -1);
    CHECK(errno == ECONNREFUSED || errno == EACCES);
    close(fd);
}

static void test_listen_invalid_port(void) {
    CHECK(tcp_listen("127.0.0.1", -1, NULL) == -1);
    CHECK(tcp_listen("127.0.0.1", 70000, NULL) == -1);
}

int main(void) {
    test_listen_accept_connect();
    test_async_connect_and_accept_peer();
    test_connect_refused();
    test_listen_invalid_port();

    if (g_failures) {
        fprintf(stderr, "test_tcp_socket: %d failure(s)\n", g_failures);
        return 1;
    }
    printf("test_tcp_socket: OK\n");
    return 0;
}
