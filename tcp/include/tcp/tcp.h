/**
 * @file tcp.h
 * @brief Umbrella header for the standalone `tcp` package.
 *
 * The `tcp` package is a small, dependency-free (libc-only) set of primitives
 * for building high-performance, non-blocking TCP clients and servers on Linux
 * x86-64. It is deliberately independent of the HTTP layer so the same event
 * loop, socket helpers and connection machinery can drive any protocol.
 *
 * Layers:
 *   tcp_syscall.h     Raw Linux syscall wrappers (no glibc cancellation/TLS).
 *   tcp_events.h      Edge-triggered epoll event queue.
 *   tcp_socket.h      listen / accept / connect helpers.
 *   tcp_buffer.h      Growable byte buffer for output backpressure.
 *   tcp_connection.h  Generic non-blocking connection + callbacks.
 *   tcp_client.h      Single-threaded client event loop.
 *
 * Minimal client:
 * @code
 *   #include <tcp/tcp.h>
 *
 *   static void on_data(tcp_conn_t* c, const void* data, size_t len) {
 *       // Echo it back.
 *       tcp_conn_write(c, data, len);
 *   }
 *   static void on_closed(tcp_conn_t* c, int err) {
 *       tcp_client_stop(tcp_conn_userdata(c)); // stops the loop when done
 *   }
 *
 *   int main(void) {
 *       static const tcp_conn_cbs_t cbs = { .on_data = on_data, .on_closed = on_closed };
 *       tcp_client_t* cli = tcp_client_create(NULL);
 *       tcp_client_connect(cli, "127.0.0.1", 1234, cli, &cbs);
 *       tcp_client_run(cli);
 *       tcp_client_destroy(cli);
 *       return 0;
 *   }
 * @endcode
 */

#ifndef TCP_H
#define TCP_H

#include "tcp_buffer.h"
#include "tcp_client.h"
#include "tcp_connection.h"
#include "tcp_events.h"
#include "tcp_socket.h"
#include "tcp_syscall.h"

#endif /* TCP_H */
