#include "tcp/tcp_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ----------------------------------------------------------------
 * Option constructors
 * ---------------------------------------------------------------- */

tcp_listen_opts_t tcp_listen_opts_default(void) {
    tcp_listen_opts_t o;
    o.backlog = 65535;
    o.reuse_addr = 1;
    o.reuse_port = 0;
    o.keepalive = 0;
    o.defer_accept = 0;
    o.fastopen_qlen = 0;
    o.incoming_cpu = -1;
    o.ipv6_only = -1;
    return o;
}

tcp_connect_opts_t tcp_connect_opts_default(void) {
    tcp_connect_opts_t o;
    o.bind_host = NULL;
    o.bind_port = 0;
    o.tcp_nodelay = 1;
    o.keepalive = 0;
    return o;
}

/* ----------------------------------------------------------------
 * Resolution
 * ---------------------------------------------------------------- */

int tcp_resolve(const char* host, int port, int socktype, struct addrinfo** out) {
    if (!out || port < 0 || port > 65535) return EAI_SERVICE;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_flags = (host == NULL) ? AI_PASSIVE : 0;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);
    return getaddrinfo(host, port_str, &hints, out);
}

/* ----------------------------------------------------------------
 * Small socket-option helpers
 * ---------------------------------------------------------------- */

static void set_int_opt(int fd, int level, int name, int value) {
    if (value >= 0) {
        (void)setsockopt(fd, level, name, &value, sizeof(value));
    }
}

static int create_stream_socket(int family, int protocol) {
    return socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
}

/* ----------------------------------------------------------------
 * Listener
 * ---------------------------------------------------------------- */

int tcp_listen(const char* host, int port, const tcp_listen_opts_t* opts) {
    if (port < 0 || port > 65535) {
        errno = EINVAL;
        return -1;
    }

    tcp_listen_opts_t o = opts ? *opts : tcp_listen_opts_default();

    struct addrinfo* res = NULL;
    int g = tcp_resolve(host, port, SOCK_STREAM, &res);
    if (g != 0) {
        errno = EADDRNOTAVAIL;
        return -1;
    }

    int fd = -1;
    for (struct addrinfo* rp = res; rp; rp = rp->ai_next) {
        fd = create_stream_socket(rp->ai_family, rp->ai_protocol);
        if (fd < 0) continue;

        if (o.reuse_addr) set_int_opt(fd, SOL_SOCKET, SO_REUSEADDR, 1);
        if (o.reuse_port) set_int_opt(fd, SOL_SOCKET, SO_REUSEPORT, 1);
        if (o.keepalive) set_int_opt(fd, SOL_SOCKET, SO_KEEPALIVE, 1);

#ifdef IPV6_V6ONLY
        if (rp->ai_family == AF_INET6 && o.ipv6_only >= 0) {
            set_int_opt(fd, IPPROTO_IPV6, IPV6_V6ONLY, o.ipv6_only);
        }
#else
        (void)o.ipv6_only;
#endif

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;

        sys_close_direct(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) return -1;

    if (o.defer_accept > 0) set_int_opt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, o.defer_accept);
#ifdef TCP_FASTOPEN
    if (o.fastopen_qlen > 0) set_int_opt(fd, IPPROTO_TCP, TCP_FASTOPEN, o.fastopen_qlen);
#endif
#ifdef SO_INCOMING_CPU
    if (o.incoming_cpu >= 0) set_int_opt(fd, SOL_SOCKET, SO_INCOMING_CPU, o.incoming_cpu);
#endif

    int backlog = o.backlog > 0 ? o.backlog : 65535;
    if (listen(fd, backlog) < 0) {
        sys_close_direct(fd);
        return -1;
    }

    return fd;
}

/* ----------------------------------------------------------------
 * Accept / address rendering
 * ---------------------------------------------------------------- */

static int format_addr(const struct sockaddr* sa, socklen_t salen, char* buf, size_t cap) {
    if (!sa || !buf || cap == 0) {
        errno = EINVAL;
        return -1;
    }

    char ip[INET6_ADDRSTRLEN];
    unsigned port = 0;
    bool v6 = false;

    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in* v4 = (const struct sockaddr_in*)sa;
        if (!inet_ntop(AF_INET, &v4->sin_addr, ip, sizeof(ip))) return -1;
        port = ntohs(v4->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6* v6a = (const struct sockaddr_in6*)sa;
        if (!inet_ntop(AF_INET6, &v6a->sin6_addr, ip, sizeof(ip))) return -1;
        port = ntohs(v6a->sin6_port);
        v6 = true;
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
    (void)salen;

    int n = v6 ? snprintf(buf, cap, "[%s]:%u", ip, port) : snprintf(buf, cap, "%s:%u", ip, port);
    if (n < 0 || (size_t)n >= cap) {
        errno = ENOSPC;
        return -1;
    }
    return 0;
}

int tcp_accept(int listen_fd, char* peer, size_t peer_cap) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    struct sockaddr* ap = NULL;
    socklen_t* alp = NULL;

    if (peer && peer_cap > 0) {
        ap = (struct sockaddr*)&ss;
        alp = &slen;
    }

    int fd = raw_accept4(listen_fd, ap, alp, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return -1;

    /* Disable Nagle: small interactive payloads must flush immediately. */
    set_int_opt(fd, IPPROTO_TCP, TCP_NODELAY, 1);

    if (ap && format_addr(ap, slen, peer, peer_cap) < 0) {
        /* Peer rendering is cosmetic; keep the connection. */
    }
    return fd;
}

int tcp_peer_name(int fd, char* buf, size_t buf_cap) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getpeername(fd, (struct sockaddr*)&ss, &slen) < 0) return -1;
    return format_addr((struct sockaddr*)&ss, slen, buf, buf_cap);
}

int tcp_local_name(int fd, char* buf, size_t buf_cap) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getsockname(fd, (struct sockaddr*)&ss, &slen) < 0) return -1;
    return format_addr((struct sockaddr*)&ss, slen, buf, buf_cap);
}

int tcp_local_port(int fd) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getsockname(fd, (struct sockaddr*)&ss, &slen) < 0) return -1;

    if (ss.ss_family == AF_INET) return ntohs(((struct sockaddr_in*)&ss)->sin_port);
    if (ss.ss_family == AF_INET6) return ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
    errno = EAFNOSUPPORT;
    return -1;
}

/* ----------------------------------------------------------------
 * Flags
 * ---------------------------------------------------------------- */

int tcp_set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    if (flags & O_NONBLOCK) return 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int tcp_set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1) return -1;
    if (flags & FD_CLOEXEC) return 0;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

/* ----------------------------------------------------------------
 * Connect
 * ---------------------------------------------------------------- */

static int bind_local(int fd, const char* host, int port, int family) {
    struct addrinfo* res = NULL;
    int g = tcp_resolve(host, port, SOCK_STREAM, &res);
    if (g != 0) {
        errno = EADDRNOTAVAIL;
        return -1;
    }

    int rc = -1;
    for (struct addrinfo* rp = res; rp; rp = rp->ai_next) {
        if (family != AF_UNSPEC && rp->ai_family != family) continue;
        if (raw_bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            rc = 0;
            break;
        }
    }
    freeaddrinfo(res);
    return rc;
}

int tcp_connect_start(const char* host, int port, const tcp_connect_opts_t* opts) {
    if (port <= 0 || port > 65535) {
        errno = EINVAL;
        return -1;
    }

    tcp_connect_opts_t o = opts ? *opts : tcp_connect_opts_default();

    struct addrinfo* res = NULL;
    int g = tcp_resolve(host, port, SOCK_STREAM, &res);
    if (g != 0) {
        errno = EADDRNOTAVAIL;
        return -1;
    }

    int fd = -1;
    int last_err = ECONNREFUSED;

    for (struct addrinfo* rp = res; rp; rp = rp->ai_next) {
        fd = create_stream_socket(rp->ai_family, rp->ai_protocol);
        if (fd < 0) {
            last_err = errno;
            continue;
        }

        if (o.bind_host) {
            if (bind_local(fd, o.bind_host, o.bind_port, rp->ai_family) < 0) {
                last_err = errno;
                sys_close_direct(fd);
                fd = -1;
                continue;
            }
        }

        if (o.tcp_nodelay) set_int_opt(fd, IPPROTO_TCP, TCP_NODELAY, 1);
        if (o.keepalive) set_int_opt(fd, SOL_SOCKET, SO_KEEPALIVE, 1);

        int r = sys_connect_direct(fd, rp->ai_addr, rp->ai_addrlen);
        if (r == 0 || r == -EINPROGRESS || r == -EINTR) break;

        last_err = -r;
        sys_close_direct(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) errno = last_err;
    return fd;
}

int tcp_connect_check(int fd) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);

    if (getpeername(fd, (struct sockaddr*)&ss, &slen) == 0) {
        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0) return -1;
        if (err != 0) {
            errno = err;
            return -1;
        }
        return 0;
    }

    if (errno != ENOTCONN) return -1;

    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0) return -1;
    if (err != 0) {
        errno = err;
        return -1;
    }
    return 1;
}

int tcp_connect(const char* host, int port, const tcp_connect_opts_t* opts) {
    int fd = tcp_connect_start(host, port, opts);
    if (fd < 0) return -1;

    for (;;) {
        int st = tcp_connect_check(fd);
        if (st == 0) return fd;
        if (st < 0) {
            int saved = errno;
            sys_close_direct(fd);
            errno = saved;
            return -1;
        }

        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int pr = poll(&pfd, 1, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            int saved = errno;
            sys_close_direct(fd);
            errno = saved;
            return -1;
        }
    }
}
