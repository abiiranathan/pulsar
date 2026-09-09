/**
 * @file socket.h
 * @brief Cross-platform socket programming utilities.
 */

#ifndef SOCKET_H
#define SOCKET_H

// for SO_REUSEPORT
#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "platform.h"

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef _WIN32
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <unistd.h>
#endif
// On Windows, platform.h already includes winsock2 \u2192 mswsock \u2192
// windows \u2192 ws2tcpip in the correct order.

// Socket abstraction that works on both Windows and Unix
// On windows, you need to call initialize_winsock() before using any socket
// functions and cleanup_winsock() after you are done using the socket
// functions.
typedef struct {
#ifdef _WIN32
    SOCKET handle;
#else
    int handle;
#endif
} Socket;

// Initialize winsock on Windows. Does nothing on Unix.
void socket_initialize(void);

// Cleanup winsock on Windows. Does nothing on Unix.
void socket_cleanup(void);

// Create a socket, returns NULL on error.
Socket* socket_create(int domain, int type, int protocol);

// Close a socket and free the memory.
int socket_close(Socket* sock);

// Bind a socket to an address.
// Returns 0 on success, -1 on error (including invalid arguments).
// NOTE: failures are always reported; a failed bind never returns 0.
int socket_bind(Socket* sock, const struct sockaddr* addr, socklen_t addrlen);

// Listen for incoming connections. The backlog parameter is the maximum length
// of the queue of pending connections. If the queue is full, the client will
// receive an ECONNREFUSED error. Returns 0 on success, -1 on error (negative
// backlog is rejected).
int socket_listen(Socket* sock, int backlog);

// Accept an incoming connection
Socket* socket_accept(Socket* sock, struct sockaddr* addr, socklen_t* addrlen);

// Connect to a remote socket
int socket_connect(Socket* sock, const struct sockaddr* addr, socklen_t addrlen);

// Read from a socket
ssize_t socket_recv(Socket* sock, void* buffer, size_t size, int flags);

// Write to a socket
ssize_t socket_send(Socket* sock, const void* buffer, size_t size, int flags);

// Get the socket file descriptor
int socket_fd(Socket* sock);

// Get the socket error. Returns the last error code.
// On Windows, it returns the code from WSAGetLastError().
// On Unix, it returns the value of errno.
int socket_error(void);

// Get the socket error message for the given error code
// as returned by socket_error().
void socket_strerror(int err, char* buffer, size_t size);

// Get the socket option
int socket_get_option(Socket* sock, int level, int optname, void* optval, socklen_t* optlen);

// Set the socket option (SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
int socket_reuse_port(Socket* sock, int enable);

// Set the socket option
int socket_set_option(Socket* sock, int level, int optname, const void* optval, socklen_t optlen);

// Get the socket address
int socket_get_address(Socket* sock, struct sockaddr* addr, socklen_t* addrlen);

// Get the socket peer address
int socket_get_peer_address(Socket* sock, struct sockaddr* addr, socklen_t* addrlen);

// Get the socket family
int socket_family(Socket* sock);

// Get the socket type
int socket_type(Socket* sock);

// Set non-blocking mode on a socket.
// @param enable 1 to enable non-blocking, 0 to restore blocking mode.
// @return 0 on success, -1 on error (or if sock is NULL).
int socket_set_non_blocking(Socket* sock, int enable);

/**
 * Allocates and fills an IPv4 sockaddr from a dotted-quad string.
 * @param ip   Dotted-quad IPv4 address ("127.0.0.1"). Must be valid.
 * @param port Port in host byte order.
 * @return Newly allocated address on success (caller frees with free()),
 *         NULL if ip is NULL/invalid or on allocation failure.
 */
struct sockaddr_in* socket_ipv4_address(const char* ip, uint16_t port);

/**
 * Allocates and fills an IPv6 sockaddr from an IPv6 text representation.
 * @param ip   IPv6 address string ("::1"). Must be valid.
 * @param port Port in host byte order.
 * @return Newly allocated address on success (caller frees with free()),
 *         NULL if ip is NULL/invalid or on allocation failure.
 */
struct sockaddr_in6* socket_ipv6_address(const char* ip, uint16_t port);

#if defined(__cplusplus)
}
#endif

#endif  // SOCKET_H
