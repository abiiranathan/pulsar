/*
 * Minimal non-blocking TCP echo client built on the `tcp` package.
 *
 * Usage: echo_client <host> <port> <message>
 *
 * Connects, sends <message>, prints whatever the peer sends back, and exits
 * once the peer closes the connection. Demonstrates async connect, buffered
 * writes and the client event loop.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tcp/tcp.h"

typedef struct {
    tcp_client_t* cli;
    tcp_conn_t* conn;
    const char* message;
    size_t message_len;
    size_t sent;
    int received_any;
} State;

/* Send as much of the message as the socket accepts; on ENOBUFS/backpressure
 * return and let on_writable() resume. Half-close once everything is sent. */
static void send_all(tcp_conn_t* c, State* st) {
    while (st->sent < st->message_len) {
        ssize_t w = tcp_conn_write(c, st->message + st->sent, st->message_len - st->sent);
        if (w < 0) return; /* wait for the next on_writable */
        st->sent += (size_t)w;
    }
    tcp_conn_close(c);
}

static void on_connected(tcp_conn_t* c) {
    send_all(c, tcp_conn_userdata(c));
}

static void on_writable(tcp_conn_t* c) {
    send_all(c, tcp_conn_userdata(c));
}

static void on_data(tcp_conn_t* c, const void* data, size_t len) {
    State* st = tcp_conn_userdata(c);
    st->received_any = 1;
    fwrite(data, 1, len, stdout);
    fflush(stdout);
}

static void on_closed(tcp_conn_t* c, int err) {
    State* st = tcp_conn_userdata(c);
    if (err != 0) fprintf(stderr, "connection closed: %s\n", strerror(err));
    tcp_client_stop(st->cli);
}

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <host> <port> <message>\n", argv[0]);
        return 2;
    }

    int port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "invalid port: %s\n", argv[2]);
        return 2;
    }

    static const tcp_conn_cbs_t cbs = {
        .on_connected = on_connected,
        .on_data = on_data,
        .on_writable = on_writable,
        .on_closed = on_closed,
    };

    tcp_client_t* cli = tcp_client_create(NULL);
    if (!cli) {
        perror("tcp_client_create");
        return 1;
    }

    State st = {
        .cli = cli,
        .message = argv[3],
        .message_len = strlen(argv[3]),
    };

    st.conn = tcp_client_connect(cli, argv[1], port, &st, &cbs);
    if (!st.conn) {
        perror("tcp_client_connect");
        tcp_client_destroy(cli);
        return 1;
    }

    int rc = tcp_client_run(cli);
    tcp_client_destroy(cli);
    return rc == 0 && st.received_any ? 0 : 1;
}
