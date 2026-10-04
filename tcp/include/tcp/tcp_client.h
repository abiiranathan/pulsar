/**
 * @file tcp_client.h
 * @brief Single-threaded, edge-triggered TCP client event loop.
 *
 * The client owns an epoll queue and any number of non-blocking connections.
 * Typical use:
 *
 *   tcp_client_t* cli = tcp_client_create(NULL);
 *   tcp_client_connect(cli, "example.com", 80, my_state, &my_cbs);
 *   tcp_client_run(cli);          // blocks until stopped / idle
 *   tcp_client_destroy(cli);
 *
 * Threading: the loop is single-threaded; callbacks run on the thread that
 * invoked tcp_client_run(). tcp_client_stop() is the only method safe to call
 * from another thread (it wakes the loop through an eventfd). Connections and
 * writes are single-threaded: do not call tcp_conn_write() from a thread other
 * than the loop thread.
 */

#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <stddef.h>

#include "tcp_connection.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque client/loop handle. */
typedef struct tcp_client tcp_client_t;

/** Loop tuning. Zero-initialize and override fields after
 *  tcp_client_config_default(), or pass NULL to tcp_client_create() for all
 *  defaults. */
typedef struct tcp_client_config {
    size_t read_chunk;       /**< Per-iteration socket read size (default 64 KiB). */
    size_t write_max;        /**< Max queued output per connection, 0 = unbounded
                                  (default 4 MiB). */
    int max_events;          /**< epoll batch size (default 1024). */
    int poll_timeout_ms;     /**< event_wait timeout while idle (default 1000). */
    int connect_timeout_ms;  /**< Non-blocking connect deadline, 0 = none (default 0). */
    int exit_when_idle;      /**< run() returns once the last connection closes
                                  (default 1). */
} tcp_client_config_t;

/** @return A fully defaulted configuration. */
tcp_client_config_t tcp_client_config_default(void);

/**
 * @brief Create a client loop.
 * @param cfg Configuration, or NULL for defaults.
 * @return Client handle, or NULL on failure (errno set).
 */
tcp_client_t* tcp_client_create(const tcp_client_config_t* cfg);

/** Destroy a client and close all of its connections. Must not be called from
 *  inside a callback belonging to the same client unless the loop has already
 *  returned. Does not invoke on_closed() for the discarded connections. */
void tcp_client_destroy(tcp_client_t* c);

/**
 * @brief Run the event loop until stopped or (when exit_when_idle) idle.
 * @return 0 on a clean stop, -1 on an unrecoverable loop error (errno set).
 */
int tcp_client_run(tcp_client_t* c);

/** Request loop termination. Safe to call from any thread and from callbacks. */
void tcp_client_stop(tcp_client_t* c);

/**
 * @brief Start an asynchronous connection.
 *
 * on_connected() fires from the loop once the handshake completes; on failure
 * on_closed() fires with the error instead. The returned handle is valid
 * immediately and may be used to set userdata-dependent state; writes queued
 * before on_connected() are buffered and flushed on connect.
 *
 * @return Connection handle, or NULL on immediate failure (errno set).
 */
tcp_conn_t* tcp_client_connect(tcp_client_t* c, const char* host, int port, void* userdata,
                               const tcp_conn_cbs_t* cbs);

/**
 * @brief Adopt an already-connected socket into the loop.
 *
 * The fd is made non-blocking if needed. on_connected() is invoked on the next
 * loop turn, so the returned handle is always valid and fully initialized.
 *
 * @return Connection handle, or NULL on failure (errno set). On failure the
 *         caller retains ownership of @p fd.
 */
tcp_conn_t* tcp_client_add(tcp_client_t* c, int fd, void* userdata, const tcp_conn_cbs_t* cbs);

/** @return Number of live connections. */
size_t tcp_client_connection_count(const tcp_client_t* c);

#ifdef __cplusplus
}
#endif

#endif /* TCP_CLIENT_H */
