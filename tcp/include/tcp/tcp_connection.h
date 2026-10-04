/**
 * @file tcp_connection.h
 * @brief Generic, protocol-agnostic non-blocking TCP connection.
 *
 * A tcp_conn_t is created and owned by a tcp_client_t event loop (see
 * tcp_client.h). It owns a socket, a small output queue for backpressure, and
 * a set of callbacks. Bytes are delivered to on_data() as they arrive; no
 * framing is imposed. Callbacks run on the loop thread and must not block.
 *
 * Ownership: a connection is destroyed by the loop after on_closed() returns
 * (or by tcp_conn_close(), which schedules destruction). The caller must not
 * free a connection directly, and must not use a connection pointer after it
 * has been closed.
 */

#ifndef TCP_CONNECTION_H
#define TCP_CONNECTION_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque connection handle. */
typedef struct tcp_conn tcp_conn_t;

typedef enum tcp_conn_state {
    TCP_CONN_CONNECTING = 0, /**< Non-blocking connect in flight. */
    TCP_CONN_ESTABLISHED,    /**< Handshake complete; data may flow. */
    TCP_CONN_CLOSED,         /**< Torn down; pointer is about to be freed. */
} tcp_conn_state_t;

/**
 * Callback set. Every callback is optional (NULL is ignored).
 *
 * on_connected  Handshake completed (or a socket was wrapped with
 *               tcp_client_add()). At this point writes always succeed.
 * on_data       A chunk of received bytes. @p data points into the loop's
 *               reusable read buffer and is valid only during the call; copy
 *               anything that must outlive it.
 * on_writable   The output queue drained after previous backpressure. Use it
 *               to resume producing.
 * on_closed     The connection ended. @p err is 0 for an orderly peer close
 *               (EOF), otherwise a positive errno (e.g. ECONNRESET). The
 *               connection is destroyed immediately after this returns.
 */
typedef struct tcp_conn_cbs {
    void (*on_connected)(tcp_conn_t* c);
    void (*on_data)(tcp_conn_t* c, const void* data, size_t len);
    void (*on_writable)(tcp_conn_t* c);
    void (*on_closed)(tcp_conn_t* c, int err);
} tcp_conn_cbs_t;

/** @return The underlying file descriptor (never -1 for a live conn). */
int tcp_conn_fd(const tcp_conn_t* c);

/** @return The userdata pointer supplied at creation. */
void* tcp_conn_userdata(const tcp_conn_t* c);

/** @return Current connection state. */
tcp_conn_state_t tcp_conn_state(const tcp_conn_t* c);

/** @return Non-zero once tcp_conn_close() has been requested. */
int tcp_conn_is_closing(const tcp_conn_t* c);

/** @return Number of bytes still queued for transmission. */
size_t tcp_conn_pending(const tcp_conn_t* c);

/**
 * @brief Set the per-read chunk size for this connection.
 *
 * Clamped to [256 bytes, loop read chunk]. Must be called before the loop
 * observes readable data. Returns the effective size.
 */
size_t tcp_conn_set_read_chunk(tcp_conn_t* c, size_t bytes);

/**
 * @brief Queue @p len bytes for transmission.
 *
 * Fast path: when the output queue is empty the bytes are written straight to
 * the socket in a single syscall. A short write or EAGAIN queues the
 * remainder and arms write-readiness, after which on_writable() fires once the
 * queue drains.
 *
 * @return @p len when the whole payload was accepted (written and/or queued),
 *         or -1 on a fatal error (errno set; ENOBUFS when the configured
 *         write_max would be exceeded and nothing was sent).
 */
ssize_t tcp_conn_write(tcp_conn_t* c, const void* data, size_t len);

/**
 * @brief Gather-write variant of tcp_conn_write().
 * @return Total bytes accepted, or -1 on a fatal error (errno set).
 */
ssize_t tcp_conn_writev(tcp_conn_t* c, const struct iovec* iov, int iovcnt);

/**
 * @brief Try to flush queued output.
 * @return 0 when the queue is empty, 1 when bytes remain queued, -1 on error.
 */
int tcp_conn_flush(tcp_conn_t* c);

/**
 * @brief Half-close (shutdown write) and schedule destruction.
 *
 * After this call the connection no longer accepts writes. Any data already
 * received before the peer closes is still delivered, then on_closed() runs.
 * The call is idempotent and safe from any callback.
 */
void tcp_conn_close(tcp_conn_t* c);

#ifdef __cplusplus
}
#endif

#endif /* TCP_CONNECTION_H */
