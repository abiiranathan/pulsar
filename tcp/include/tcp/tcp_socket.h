/**
 * @file tcp_socket.h
 * @brief Blocking/non-blocking TCP socket helpers (listen, accept, connect).
 *
 * Part of the standalone `tcp` package. This header has no dependency on the
 * HTTP layer and can be used to build servers or clients speaking any
 * protocol. It is Linux/x86-64 only and uses the raw syscall layer
 * (tcp_syscall.h) for the operations that matter on the hot path
 * (accept4, connect, bind); cold setup calls (getaddrinfo, setsockopt,
 * getsockname) use the C library.
 *
 * Return-value convention: functions returning an `int` fd return a
 * non-negative descriptor on success and `-1` with `errno` set on failure,
 * unless stated otherwise.
 */

#ifndef TCP_SOCKET_H
#define TCP_SOCKET_H

#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

#include "tcp_syscall.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Options for tcp_listen(). Zero-initialize and fill only what differs from
 *  tcp_listen_opts_default(); the default constructor is the recommended way
 *  to obtain a valid baseline. */
typedef struct tcp_listen_opts {
    int backlog;       /**< listen(2) backlog; <= 0 selects 65535. */
    int reuse_addr;    /**< SO_REUSEADDR (default 1). */
    int reuse_port;    /**< SO_REUSEPORT (default 0; set for one listener per worker). */
    int keepalive;     /**< SO_KEEPALIVE on the listener (default 0). */
    int defer_accept;  /**< TCP_DEFER_ACCEPT seconds; 0 disables. */
    int fastopen_qlen; /**< TCP_FASTOPEN SYN queue length; 0 disables. */
    int incoming_cpu;  /**< SO_INCOMING_CPU hint for the listener; < 0 disables. */
    int ipv6_only;     /**< IPv6 IPV6_V6ONLY: -1 default, 0 dual-stack, 1 v6-only. */
} tcp_listen_opts_t;

/** Options for tcp_connect_start()/tcp_connect(). */
typedef struct tcp_connect_opts {
    const char* bind_host; /**< Optional local address to bind before connecting. */
    int bind_port;         /**< Optional local port (0 = ephemeral) when bind_host is set. */
    int tcp_nodelay;       /**< TCP_NODELAY on the connected socket (default 1). */
    int keepalive;         /**< SO_KEEPALIVE on the connected socket (default 0). */
} tcp_connect_opts_t;

/** @return A baseline listen-options struct with every field defaulted. */
tcp_listen_opts_t tcp_listen_opts_default(void);

/** @return A baseline connect-options struct with every field defaulted. */
tcp_connect_opts_t tcp_connect_opts_default(void);

/**
 * @brief Resolve @p host/@p port into a NULL-terminated addrinfo list.
 *
 * @param host     Host name or numeric address; NULL means passive (any).
 * @param port     TCP port in [1, 65535].
 * @param socktype SOCK_STREAM or SOCK_DGRAM.
 * @param out      Receives a list the caller must release with freeaddrinfo().
 * @return 0 on success, otherwise a non-zero getaddrinfo()/EAI_* error code
 *         suitable for gai_strerror().
 */
int tcp_resolve(const char* host, int port, int socktype, struct addrinfo** out);

/**
 * @brief Create, configure, bind and listen on a TCP socket.
 *
 * The returned descriptor is non-blocking and close-on-exec. The socket is
 * bound to the first address getaddrinfo() yields that accepts a bind, so
 * passing "localhost" may produce either an IPv4 or an IPv6 listener.
 *
 * @param host Host name or literal address; NULL binds all interfaces.
 * @param port TCP port in [1, 65535].
 * @param opts Options, or NULL for tcp_listen_opts_default().
 * @return Listening fd on success, -1 on failure (errno set).
 */
int tcp_listen(const char* host, int port, const tcp_listen_opts_t* opts);

/**
 * @brief Accept one pending connection from a listening socket.
 *
 * The accepted fd is non-blocking and close-on-exec, with TCP_NODELAY always
 * enabled so small interactive payloads flush immediately. When @p peer is
 * non-NULL the peer address is rendered into it with inet_ntop() and
 * @p peer_cap bytes; pass NULL to skip the address copy (cheaper, and the
 * kernel copy is avoided).
 *
 * @return Client fd on success, -1 on failure (errno EAGAIN/EWOULDBLOCK when
 *         no connection is pending).
 */
int tcp_accept(int listen_fd, char* peer, size_t peer_cap);

/**
 * @brief Render the peer address of a connected socket.
 * @return 0 on success, -1 on failure (errno set).
 */
int tcp_peer_name(int fd, char* buf, size_t buf_cap);

/**
 * @brief Render the local address of a socket.
 * @return 0 on success, -1 on failure (errno set).
 */
int tcp_local_name(int fd, char* buf, size_t buf_cap);

/**
 * @brief Return the local TCP port of a socket (useful with port 0 listeners).
 * @return Port in [0, 65535], or -1 on failure (errno set).
 */
int tcp_local_port(int fd);

/** Enable O_NONBLOCK on @p fd. @return 0 on success, -1 on failure. */
int tcp_set_nonblock(int fd);

/** Enable FD_CLOEXEC on @p fd. @return 0 on success, -1 on failure. */
int tcp_set_cloexec(int fd);

/**
 * @brief Begin a non-blocking connect to @p host:@p port.
 *
 * The returned fd is non-blocking and close-on-exec. The connection may not
 * yet be established: poll it for writability (or drive it through
 * tcp_client) and call tcp_connect_check() to learn the outcome.
 *
 * @return Connected/connecting fd on success, -1 on failure (errno set).
 *         EINPROGRESS never leaks to the caller; it is reported as success.
 */
int tcp_connect_start(const char* host, int port, const tcp_connect_opts_t* opts);

/**
 * @brief Query the state of a connect started with tcp_connect_start().
 * @return 0 when connected, 1 when still in progress, -1 on failure (errno set).
 */
int tcp_connect_check(int fd);

/**
 * @brief Blocking connect convenience wrapper.
 *
 * Starts a non-blocking connect and waits for it to finish (no timeout).
 *
 * @return Connected fd on success, -1 on failure (errno set).
 */
int tcp_connect(const char* host, int port, const tcp_connect_opts_t* opts);

#ifdef __cplusplus
}
#endif

#endif /* TCP_SOCKET_H */
