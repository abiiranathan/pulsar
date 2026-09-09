#include "../include/socket.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
static void printLastErrorMessage(const char* prefix) {
    LPSTR errorText = NULL;
    // create format flags
    DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

    FormatMessageA(flags, NULL, (DWORD)WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&errorText,
                   0, NULL);

    if (errorText != NULL) {
        fprintf(stderr, "%s failed with error %d: %s\n", prefix, WSAGetLastError(), errorText);
        LocalFree(errorText);
    } else {
        fprintf(stderr, "%s failed with unknown error %d\n", prefix, WSAGetLastError());
    }
}
#endif

#ifdef _WIN32
void socket_initialize() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

void socket_cleanup() { WSACleanup(); }
#else
void socket_initialize(void) {
    // do nothing
}
void socket_cleanup(void) {
    // do nothing
}
#endif

// Create a socket
Socket* socket_create(int domain, int type, int protocol) {
    Socket* sock = (Socket*)malloc(sizeof(Socket));
    if (!sock) {
        perror("malloc");
        return NULL;
    }
#ifdef _WIN32
    sock->handle = socket(domain, type, protocol);
    if (sock->handle == INVALID_SOCKET) {
        free(sock);
        // print the error message
        printLastErrorMessage("socket");
        return NULL;
    }
#else
    sock->handle = socket(domain, type, protocol);
    if (sock->handle == -1) {
        free(sock);
        return NULL;
    }
#endif
    return sock;
}

// Close a socket and free the memory
int socket_close(Socket* sock) {
    int ret = -1;
    if (sock) {
#ifdef _WIN32
        ret = closesocket(sock->handle);
#else
        ret = close(sock->handle);
#endif
        free(sock);
    }
    return ret;
}

// Bind a socket to an address
int socket_bind(Socket* sock, const struct sockaddr* addr, socklen_t addrlen) {
    if (!sock || !addr || addrlen == 0) {
        return -1;
    }

    /*
     * FIX (security): the POSIX path previously converted bind() failures
     * into success ("ret = 0" after perror), letting callers believe a
     * server was listening when it was not.  Failures are now propagated.
     */
#ifdef _WIN32
    int ret = bind(sock->handle, addr, addrlen);
    if (ret != 0) {
        printLastErrorMessage("bind");
    }
    return ret;
#else
    return bind(sock->handle, addr, addrlen);
#endif
}

int socket_listen(Socket* sock, int backlog) {
    if (!sock) {
        return -1;
    }
    /* Negative backlogs are platform-defined; reject them explicitly. */
    if (backlog < 0) {
        return -1;
    }
    return listen(sock->handle, backlog);
}

// Accept an incoming connection
Socket* socket_accept(Socket* sock, struct sockaddr* addr, socklen_t* addrlen) {
    if (!sock) {
        return NULL;
    }
    Socket* client = (Socket*)malloc(sizeof(Socket));
    if (!client) {
        perror("malloc");
        return NULL;
    }
#ifdef _WIN32
    client->handle = accept(sock->handle, addr, addrlen);
    if (client->handle == INVALID_SOCKET) {
        free(client);
        printLastErrorMessage("accept");
        return NULL;
    }
#else
    client->handle = accept(sock->handle, addr, addrlen);
    if (client->handle == -1) {
        perror("accept");
        free(client);
        return NULL;
    }
#endif
    return client;
}

// Connect to a remote socket
int socket_connect(Socket* sock, const struct sockaddr* addr, socklen_t addrlen) {
    if (!sock || !addr || addrlen == 0) {
        return -1;
    }
    return connect(sock->handle, addr, addrlen);
}

/**
 * @brief Reads from a socket.
 *
 * @param[in] sock Socket to read from. Must not be NULL.
 * @param[out] buffer Destination buffer. Must not be NULL when size > 0.
 * @param[in] size Capacity of buffer in bytes.
 * @param[in] flags recv(2) flags (see man 2 recv).
 * @return Number of bytes read (0 = peer closed), or -1 on error.
 * @note EINTR is NOT retried internally; callers running under signals must
 * check socket_error() for EINTR and retry themselves.
 */
ssize_t socket_recv(Socket* sock, void* buffer, size_t size, int flags) {
    if (!sock || !buffer || size == 0) {
        return -1;
    }
    return recv(sock->handle, buffer, size, flags);
}

/**
 * @brief Writes to a socket.
 *
 * @param[in] sock Socket to write to. Must not be NULL.
 * @param[in] buffer Message to send. Must not be NULL when size > 0.
 * @param[in] size Length of the message in bytes.
 * @param[in] flags send(2) flags (see man 2 send).
 * @return Number of bytes written, or -1 on error.
 * @note Partial sends are possible on stream sockets; callers must loop.
 * @note EINTR is NOT retried internally; see socket_recv().
 */
ssize_t socket_send(Socket* sock, const void* buffer, size_t size, int flags) {
    if (!sock || !buffer || size == 0) {
        return -1;
    }
    return send(sock->handle, buffer, size, flags);
}

// Get the socket file descriptor
int socket_fd(Socket* sock) { return sock != NULL ? sock->handle : -1; }

int socket_error(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

void socket_strerror(int err, char* buffer, size_t size) {
    if (!buffer || size == 0) return;

#ifdef _WIN32
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, (DWORD)err, 0, buffer, (DWORD)size, NULL);
    /* Ensure NUL-termination (FormatMessageA does not guarantee it on short buffers). */
    buffer[size - 1] = '\0';
#else
    #if defined(__GLIBC__)
    /*
     * GNU strerror_r: returns char* which may point to a static string
     * rather than `buffer`.  Copy it into the caller's buffer if needed.
     */
    char* msg = strerror_r(err, buffer, size);
    if (msg != buffer && msg != NULL) {
        const size_t msg_len = strlen(msg);
        const size_t copy = msg_len < size - 1 ? msg_len : size - 1;
        memcpy(buffer, msg, copy);
        buffer[copy] = '\0';
    }
    #else
    /* POSIX strerror_r (macOS, BSD): always writes into buffer, returns int. */
    strerror_r(err, buffer, size);
    buffer[size - 1] = '\0'; /* ensure NUL-termination */
    #endif
#endif
}

// Get the socket option
int socket_get_option(Socket* sock, int level, int optname, void* optval, socklen_t* optlen) {
    if (!sock || !optval || !optlen) {
        return -1;
    }
#ifdef _WIN32
    return getsockopt(sock->handle, level, optname, (char*)optval, optlen);
#else
    return getsockopt(sock->handle, level, optname, optval, optlen);
#endif
}

// Set the socket option
int socket_set_option(Socket* sock, int level, int optname, const void* optval, socklen_t optlen) {
    if (!sock || !optval || optlen == 0) {
        return -1;
    }
#ifdef _WIN32
    return setsockopt(sock->handle, level, optname, (const char*)optval, optlen);
#else
    return setsockopt(sock->handle, level, optname, optval, optlen);
#endif
}

int socket_reuse_port(Socket* sock, int enable) {
    if (!sock) {
        return -1;
    }
#ifdef _WIN32
    // Enable SO_REUSEADDR
    if (setsockopt(sock->handle, SOL_SOCKET, SO_REUSEADDR, (char*)&enable, sizeof(int)) == SOCKET_ERROR) {
        perror("setsockopt");
        fprintf(stderr, "setsockopt SO_REUSEADDR failed\n");
        return -1; /* FIX: was 1, inconsistent with the POSIX -1 convention */
    }

    // Enable SO_EXCLUSIVEADDRUSE
    if (setsockopt(sock->handle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&enable, sizeof(int)) == SOCKET_ERROR) {
        perror("setsockopt");
        fprintf(stderr, "setsockopt SO_EXCLUSIVEADDRUSE failed\n");
        return -1;
    }
    return 0;
#else
    int ret = 0;
    // Always set SO_REUSEADDR
    if (setsockopt(sock->handle, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) != 0) {
        ret = -1;
    }

    // SO_REUSEPORT is available on Linux and modern BSD/macOS
    #ifdef SO_REUSEPORT
    if (setsockopt(sock->handle, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) != 0) {
        ret = -1;
    }
    #endif

    return ret;
#endif
}

// Get the socket address
int socket_get_address(Socket* sock, struct sockaddr* addr, socklen_t* addrlen) {
    if (!sock || !addr || !addrlen) {
        return -1;
    }
    return getsockname(sock->handle, addr, addrlen);
}

// Get the socket peer address
int socket_get_peer_address(Socket* sock, struct sockaddr* addr, socklen_t* addrlen) {
    if (!sock || !addr || !addrlen) {
        return -1;
    }
    return getpeername(sock->handle, addr, addrlen);
}

int socket_type(Socket* sock) {
    if (!sock) {
        return -1;
    }
    int type = 0;
    socklen_t len = sizeof(type);
    if (socket_get_option(sock, SOL_SOCKET, SO_TYPE, &type, &len) == 0) {
        return type;
    }
    return -1;
}

int socket_family(Socket* sock) {
    if (!sock) {
        return -1;
    }
    int domain = -1;
#ifdef _WIN32
    /*
     * FIX: the previous Windows path passed &domain as optval while also
     * assigning getsockopt()'s return value into domain, so it reported
     * 0 or -1 instead of an address family.  Windows has no SO_DOMAIN;
     * use getsockname() like the macOS path.
     */
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(sock->handle, (struct sockaddr*)&addr, &addr_len) == 0) {
        domain = addr.ss_family;
    }
#elif defined(__APPLE__)
    // macOS doesn't support SO_DOMAIN, use getsockname instead
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(sock->handle, (struct sockaddr*)&addr, &addr_len) == 0) {
        domain = addr.ss_family;
    }
#else
    socklen_t len = sizeof(domain);
    socket_get_option(sock, SOL_SOCKET, SO_DOMAIN, &domain, &len);
#endif
    return domain;
}

// set non-blocking mode
int socket_set_non_blocking(Socket* sock, int enable) {
    if (!sock) {
        return -1;
    }
#ifdef _WIN32
    u_long mode = enable ? 1 : 0;
    return ioctlsocket(sock->handle, FIONBIO, &mode);
#else
    int flags = fcntl(sock->handle, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }
    if (enable) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    return fcntl(sock->handle, F_SETFL, flags);
#endif
}

// Create an IPv4 address
// Allocates a new sockaddr_in and sets the address and port.
// Returns NULL if ip is NULL or not a valid dotted-quad IPv4 string.
struct sockaddr_in* socket_ipv4_address(const char* ip, uint16_t port) {
    /*
     * FIX (security): inet_addr() signals failure with INADDR_NONE, which
     * the old code stored verbatim — broadcast address 255.255.255.255 is
     * also indistinguishable from that error.  inet_pton() is used instead
     * and parse failures now return NULL.
     */
    struct in_addr parsed;
    if (!ip || inet_pton(AF_INET, ip, &parsed) != 1) {
        return NULL;
    }

    struct sockaddr_in* addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
    if (!addr) {
        perror("malloc");
        return NULL;
    }
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr = parsed;
    return addr;
}

// Create an IPv6 address
// Allocates a new sockaddr_in6 and sets the address and port.
// Returns NULL if ip is NULL or not a valid IPv6 string.
struct sockaddr_in6* socket_ipv6_address(const char* ip, uint16_t port) {
    struct sockaddr_in6* addr = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
    if (!addr) {
        perror("malloc");
        return NULL;
    }
    memset(addr, 0, sizeof(struct sockaddr_in6));
    /* FIX: inet_pton()'s result was previously ignored; invalid input
     * silently produced an all-zero (::) address. */
    if (!ip || inet_pton(AF_INET6, ip, &addr->sin6_addr) != 1) {
        free(addr);
        return NULL;
    }
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(port);
    return addr;
}
