/*****************************************************************************
 * npe_lib_net.c — TCP/UDP/RAW socket operations for NPE Lua scripts
 *
 * Implements the "npe.net" Lua namespace: tcp_connect, udp_connect, send,
 * recv, recv_line, recv_until, recv_bytes, close, resolve, is_port_open,
 * set_timeout, get_peer_info.
 *
 * All sockets are represented as Lua full-userdata carrying an
 * npe_net_socket_t with the NPE_NET_SOCKET_METATABLE metatable.
 *****************************************************************************/

#include "npe_lib_net.h"
#include "npe_error.h"
#include "npe_ssl.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <stdatomic.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

/* ─────────────────────────────────────────────────────────
 *  Low-level helpers
 * ───────────────────────────────────────────────────────── */

static int
set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int
set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Socket ID Generator (thread-safe, atomic)
 * ═══════════════════════════════════════════════════════════════════════════ */

static _Atomic uint64_t g_socket_id_counter = 1;

uint64_t
npe_net_next_socket_id(void)
{
    return atomic_fetch_add(&g_socket_id_counter, 1);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Get current monotonic time in milliseconds.
 */
static double
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/**
 * Wait for a file descriptor to become ready for the given events.
 *
 * @param fd          File descriptor.
 * @param events      POLLIN, POLLOUT, etc.
 * @param timeout_ms  Timeout in milliseconds.
 * @return            1 if ready, 0 on timeout, -1 on error.
 */
static int
wait_for_fd(int fd, short events, uint32_t timeout_ms)
{
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = events;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, (int)timeout_ms);
    if (ret < 0)
        return -1;
    if (ret == 0)
        return 0; /* timeout */

    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
        return -1;

    return 1;
}

/**
 * Resolve host:port into a struct sockaddr_storage.
 * Tries IPv4 first, then IPv6.
 *
 * @return 0 on success, -1 on failure.
 */
static int
resolve_address(const char *host, uint16_t port, int socktype,
                struct sockaddr_storage *out_addr, socklen_t *out_len)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0 || !res)
        return -1;

    memcpy(out_addr, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}

/**
 * Initialize the internal receive buffer on a socket.
 */
static int
init_recv_buf(npe_net_socket_t *sock)
{
    if (sock->recv_buf)
        return 0;

    sock->recv_buf = malloc(NPE_NET_DEFAULT_RECV_SIZE);
    if (!sock->recv_buf)
        return -1;
    sock->recv_buf_size = NPE_NET_DEFAULT_RECV_SIZE;
    sock->recv_buf_len = 0;
    return 0;
}

/**
 * Grow the internal receive buffer if needed.
 */
static int
grow_recv_buf(npe_net_socket_t *sock, size_t needed)
{
    if (sock->recv_buf_size >= needed)
        return 0;

    size_t new_size = sock->recv_buf_size;
    while (new_size < needed && new_size < NPE_NET_MAX_RECV_SIZE)
        new_size *= 2;

    if (new_size < needed)
        return -1; /* would exceed max */

    char *new_buf = realloc(sock->recv_buf, new_size);
    if (!new_buf)
        return -1;

    sock->recv_buf = new_buf;
    sock->recv_buf_size = new_size;
    return 0;
}

/**
 * Extract the IP address string from a sockaddr_storage.
 */
static void
sockaddr_to_string(const struct sockaddr_storage *addr, char *buf, size_t bufsz,
                   uint16_t *out_port)
{
    if (addr->ss_family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &sin->sin_addr, buf, (socklen_t)bufsz);
        if (out_port)
            *out_port = ntohs(sin->sin_port);
    }
    else if (addr->ss_family == AF_INET6)
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, buf, (socklen_t)bufsz);
        if (out_port)
            *out_port = ntohs(sin6->sin6_port);
    }
    else
    {
        snprintf(buf, bufsz, "unknown");
        if (out_port)
            *out_port = 0;
    }
}

/**
 * Get the effective timeout for an operation.
 */
static uint32_t
effective_timeout(const npe_net_socket_t *sock, uint32_t override_ms)
{
    if (override_ms > 0)
        return override_ms;
    if (sock->timeout_ms > 0)
        return sock->timeout_ms;
    return NPE_NET_DEFAULT_TIMEOUT_MS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: TCP Connect
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ─────────────────────────────────────────────────────────
 *  npe_net_tcp_connect  —  raw TCP with full error handling
 * ───────────────────────────────────────────────────────── */
int npe_net_tcp_connect(const char *host, uint16_t port,
                        uint32_t timeout_ms, npe_net_socket_t *out_sock)
{
    if (!host || !host[0] || !out_sock)
    {
        errno = EINVAL;
        return -1;
    }

    /* ── Initialise output structure ── */
    memset(out_sock, 0, sizeof(*out_sock));
    out_sock->fd = -1;
    out_sock->type = NPE_NET_SOCK_TCP;
    out_sock->state = NPE_NET_STATE_CLOSED;
    out_sock->is_http2 = false;
    out_sock->ssl_handle = NULL;
    out_sock->socket_id = npe_net_next_socket_id();

    if (timeout_ms == 0)
        timeout_ms = NPE_NET_DEFAULT_TIMEOUT_MS;
    out_sock->timeout_ms = timeout_ms;

    /* ── DNS resolution ── */
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    if (resolve_address(host, port, SOCK_STREAM, &addr, &addr_len) < 0)
    {
        out_sock->state = NPE_NET_STATE_ERROR;
        return -1;
    }

    /* ── Create socket ── */
    int fd = socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
    {
        out_sock->state = NPE_NET_STATE_ERROR;
        return -1;
    }

    /* ── Socket options ── */
    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    /* Keep-alive for long-lived connections */
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

#ifdef TCP_KEEPIDLE
    int keepidle = 60;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
#endif
#ifdef TCP_KEEPINTVL
    int keepintvl = 10;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
#endif
#ifdef TCP_KEEPCNT
    int keepcnt = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
#endif

    /* ── Non-blocking connect ── */
    if (set_nonblocking(fd) < 0)
    {
        close(fd);
        out_sock->state = NPE_NET_STATE_ERROR;
        return -1;
    }

    out_sock->state = NPE_NET_STATE_CONNECTING;

    int rc = connect(fd, (struct sockaddr *)&addr, addr_len);
    if (rc < 0)
    {
        if (errno != EINPROGRESS)
        {
            close(fd);
            out_sock->state = NPE_NET_STATE_ERROR;
            return -1;
        }

        /* Wait for connection to complete */
        int ready = wait_for_fd(fd, POLLOUT, timeout_ms);
        if (ready <= 0)
        {
            int saved_errno = (ready == 0) ? ETIMEDOUT : errno;
            close(fd);
            out_sock->state = NPE_NET_STATE_ERROR;
            errno = saved_errno;
            return -1;
        }

        /* Verify no socket-level error */
        int sock_err = 0;
        socklen_t err_len = sizeof(sock_err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len) < 0 || sock_err != 0)
        {
            int saved_errno = sock_err ? sock_err : errno;
            close(fd);
            out_sock->state = NPE_NET_STATE_ERROR;
            errno = saved_errno;
            return -1;
        }
    }

    /* ── Restore blocking mode ── */
    if (set_blocking(fd) < 0)
    {
        close(fd);
        out_sock->state = NPE_NET_STATE_ERROR;
        return -1;
    }

    /* ── Populate output ── */
    out_sock->fd = fd;
    out_sock->state = NPE_NET_STATE_CONNECTED;
    out_sock->peer_port = port;
    out_sock->peer_addr_len = addr_len;
    memcpy(&out_sock->peer_addr, &addr, addr_len);

    strncpy(out_sock->peer_host, host, sizeof(out_sock->peer_host) - 1);
    out_sock->peer_host[sizeof(out_sock->peer_host) - 1] = '\0';

    return 0;
}

/* ─────────────────────────────────────────────────────────
 *  npe_net_tcp_connect_ssl  —  TCP + TLS + ALPN in one call
 *
 *  This is what npe_http_request() should use for HTTPS.
 *  After this returns, sock->is_http2 is authoritative.
 * ───────────────────────────────────────────────────────── */
int npe_net_tcp_connect_ssl(const char *host, uint16_t port,
                            uint32_t timeout_ms, bool verify_ssl,
                            npe_net_socket_t *out_sock)
{
    /* Step 1: Establish TCP connection */
    int rc = npe_net_tcp_connect(host, port, timeout_ms, out_sock);
    if (rc < 0)
        return rc;

    /* Step 2: TLS handshake with ALPN negotiation */
    npe_error_t err = npe_ssl_wrap(out_sock, host, verify_ssl);
    if (err != NPE_OK)
    {
        /* Clean up the TCP socket on SSL failure */
        close(out_sock->fd);
        out_sock->fd = -1;
        out_sock->state = NPE_NET_STATE_ERROR;
        return -1;
    }

    /* sock->is_http2 is now set by npe_ssl_wrap() */
    return 0;
}

/* ─────────────────────────────────────────────────────────
 *  npe_net_tcp_disconnect  —  clean teardown
 * ───────────────────────────────────────────────────────── */
int npe_net_tcp_disconnect(npe_net_socket_t *sock)
{
    if (!sock)
        return -1;

    /* Unwrap SSL first if present */
    if (sock->ssl_handle)
    {
        npe_ssl_unwrap(sock); /* resets is_http2 = false */
    }

    if (sock->fd >= 0)
    {
        shutdown(sock->fd, SHUT_RDWR);
        close(sock->fd);
        sock->fd = -1;
    }

    sock->state = NPE_NET_STATE_CLOSED;
    sock->is_http2 = false;

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: UDP Create
 * ═══════════════════════════════════════════════════════════════════════════ */

int npe_net_udp_create(const char *host, uint16_t port,
                       npe_net_socket_t *out_sock)
{
    if (!host || !out_sock)
        return -1;

    memset(out_sock, 0, sizeof(*out_sock));
    out_sock->fd = -1;
    out_sock->type = NPE_NET_SOCK_UDP;
    out_sock->state = NPE_NET_STATE_CLOSED;
    out_sock->timeout_ms = NPE_NET_DEFAULT_TIMEOUT_MS;
    out_sock->socket_id = npe_net_next_socket_id();

    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    if (resolve_address(host, port, SOCK_DGRAM, &addr, &addr_len) < 0)
        return -1;

    int fd = socket(addr.ss_family, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    /*
     * "Connect" the UDP socket to set a default destination.  This allows
     * us to use send()/recv() instead of sendto()/recvfrom() and also
     * receive ICMP unreachable errors.
     */
    if (connect(fd, (struct sockaddr *)&addr, addr_len) < 0)
    {
        close(fd);
        return -1;
    }

    out_sock->fd = fd;
    out_sock->state = NPE_NET_STATE_CONNECTED;
    out_sock->peer_port = port;
    memcpy(&out_sock->peer_addr, &addr, addr_len);
    out_sock->peer_addr_len = addr_len;

    sockaddr_to_string(&addr, out_sock->peer_host,
                       sizeof(out_sock->peer_host), NULL);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: Send
 * ═══════════════════════════════════════════════════════════════════════════ */

ssize_t npe_net_send(npe_net_socket_t *sock, const void *buf, size_t buf_size)
{
    SSL *ssl = (SSL *)sock->ssl_handle;
    if (ssl)
    {
        int n = SSL_write(ssl, buf, buf_size);
        if (n <= 0)
        {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
            {
                errno = EAGAIN;
                return -1;
            }
            unsigned long ssl_err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
            LOGE("SSL_write failed: %s", err_buf);
            return -1;
        }
        return n;
    }
    else
    {
        ssize_t n = send(sock->fd, buf, buf_size, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN))
            return -1;
        if (n < 0)
            LOGE("send failed: %s", strerror(errno));
        return n;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: Recv
 * ═══════════════════════════════════════════════════════════════════════════ */

ssize_t npe_net_recv(npe_net_socket_t *sock, void *buf, size_t buf_size,uint32_t timeout_ms)
{
    if (!sock || !buf || buf_size == 0)
        return -1;

    if (sock->ssl_handle)
    {
        SSL *ssl = (SSL *)sock->ssl_handle;
        int ret = SSL_read(ssl, buf, (int)buf_size);
        
        if (ret > 0)
            return ret;
            
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            errno = EAGAIN;
            return -1;
        }
        
        if (err == SSL_ERROR_ZERO_RETURN)return 0;
            LOGE("SSL_read failed: %lu", ERR_get_error());
        return -1;
    }

    return recv(sock->fd, buf, buf_size, 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: Recv Line
 * ═══════════════════════════════════════════════════════════════════════════ */

ssize_t
npe_net_recv_line(npe_net_socket_t *sock, char *buf, size_t buf_size,
                  uint32_t timeout_ms)
{
    if (!sock || !buf || buf_size == 0 || sock->fd < 0)
        return -1;

    uint32_t tmo = effective_timeout(sock, timeout_ms);
    double deadline = now_ms() + (double)tmo;

    if (init_recv_buf(sock) < 0)
        return -1;

    /*
     * Scan internal buffer for newline; if not found, read more data.
     */
    for (;;)
    {
        /* Scan for \n in current buffer. */
        for (size_t i = 0; i < sock->recv_buf_len; i++)
        {
            if (sock->recv_buf[i] == '\n')
            {
                /* Found newline — copy up to and including it. */
                size_t line_len = i + 1;
                if (line_len > buf_size - 1)
                    line_len = buf_size - 1;

                memcpy(buf, sock->recv_buf, line_len);
                buf[line_len] = '\0';

                /* Remove consumed data from internal buffer. */
                size_t consumed = i + 1;
                size_t remaining = sock->recv_buf_len - consumed;
                if (remaining > 0)
                    memmove(sock->recv_buf, sock->recv_buf + consumed, remaining);
                sock->recv_buf_len = remaining;

                return (ssize_t)line_len;
            }
        }

        /* No newline yet — check if we've exceeded the max line length. */
        if (sock->recv_buf_len >= NPE_NET_MAX_LINE_LENGTH)
        {
            size_t to_copy = (sock->recv_buf_len < buf_size - 1)
                                 ? sock->recv_buf_len
                                 : buf_size - 1;
            memcpy(buf, sock->recv_buf, to_copy);
            buf[to_copy] = '\0';
            sock->recv_buf_len = 0;
            return (ssize_t)to_copy;
        }

        /* Check timeout. */
        double remaining_ms = deadline - now_ms();
        if (remaining_ms <= 0)
        {
            errno = ETIMEDOUT;
            return -1;
        }

        int ready = wait_for_fd(sock->fd, POLLIN, (uint32_t)remaining_ms);
        if (ready <= 0)
        {
            errno = (ready == 0) ? ETIMEDOUT : errno;
            return -1;
        }

        /* Grow buffer if needed. */
        if (grow_recv_buf(sock, sock->recv_buf_len + NPE_NET_DEFAULT_RECV_SIZE) < 0)
            return -1;

        ssize_t n = recv(sock->fd,
                         sock->recv_buf + sock->recv_buf_len,
                         sock->recv_buf_size - sock->recv_buf_len, 0);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
        {
            /* EOF — return whatever we have. */
            if (sock->recv_buf_len > 0)
            {
                size_t to_copy = (sock->recv_buf_len < buf_size - 1)
                                     ? sock->recv_buf_len
                                     : buf_size - 1;
                memcpy(buf, sock->recv_buf, to_copy);
                buf[to_copy] = '\0';
                sock->recv_buf_len = 0;
                return (ssize_t)to_copy;
            }
            return 0;
        }

        sock->recv_buf_len += (size_t)n;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: Recv Until (pattern match)
 * ═══════════════════════════════════════════════════════════════════════════ */

ssize_t
npe_net_recv_until(npe_net_socket_t *sock, char *buf, size_t buf_size,
                   const char *pattern, size_t pattern_len,
                   uint32_t timeout_ms)
{
    if (!sock || !buf || !pattern || pattern_len == 0 || sock->fd < 0)
        return -1;

    uint32_t tmo = effective_timeout(sock, timeout_ms);
    double deadline = now_ms() + (double)tmo;

    if (init_recv_buf(sock) < 0)
        return -1;

    for (;;)
    {
        /* Search for pattern in current buffer. */
        if (sock->recv_buf_len >= pattern_len)
        {
            for (size_t i = 0; i <= sock->recv_buf_len - pattern_len; i++)
            {
                if (memcmp(sock->recv_buf + i, pattern, pattern_len) == 0)
                {
                    /* Found — return data up to and including the pattern. */
                    size_t total = i + pattern_len;
                    size_t to_copy = (total < buf_size - 1) ? total : buf_size - 1;
                    memcpy(buf, sock->recv_buf, to_copy);
                    buf[to_copy] = '\0';

                    size_t consumed = total;
                    size_t remaining = sock->recv_buf_len - consumed;
                    if (remaining > 0)
                        memmove(sock->recv_buf,
                                sock->recv_buf + consumed, remaining);
                    sock->recv_buf_len = remaining;

                    return (ssize_t)to_copy;
                }
            }
        }

        /* Check buffer limits. */
        if (sock->recv_buf_len >= NPE_NET_MAX_RECV_SIZE)
        {
            errno = EOVERFLOW;
            return -1;
        }

        double remaining_ms = deadline - now_ms();
        if (remaining_ms <= 0)
        {
            errno = ETIMEDOUT;
            return -1;
        }

        int ready = wait_for_fd(sock->fd, POLLIN, (uint32_t)remaining_ms);
        if (ready <= 0)
        {
            errno = (ready == 0) ? ETIMEDOUT : errno;
            return -1;
        }

        if (grow_recv_buf(sock, sock->recv_buf_len + NPE_NET_DEFAULT_RECV_SIZE) < 0)
            return -1;

        ssize_t n = recv(sock->fd,
                         sock->recv_buf + sock->recv_buf_len,
                         sock->recv_buf_size - sock->recv_buf_len, 0);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
        {
            /* EOF without finding pattern. */
            if (sock->recv_buf_len > 0)
            {
                size_t to_copy = (sock->recv_buf_len < buf_size - 1)
                                     ? sock->recv_buf_len
                                     : buf_size - 1;
                memcpy(buf, sock->recv_buf, to_copy);
                buf[to_copy] = '\0';
                sock->recv_buf_len = 0;
                return (ssize_t)to_copy;
            }
            return 0;
        }
        sock->recv_buf_len += (size_t)n;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: Recv Bytes (exact count)
 * ═══════════════════════════════════════════════════════════════════════════ */

ssize_t
npe_net_recv_bytes(npe_net_socket_t *sock, void *buf, size_t count,
                   uint32_t timeout_ms)
{
    if (!sock || !buf || count == 0 || sock->fd < 0)
        return -1;

    uint32_t tmo = effective_timeout(sock, timeout_ms);
    double deadline = now_ms() + (double)tmo;

    uint8_t *dst = (uint8_t *)buf;
    size_t total = 0;

    /* Drain internal buffer first. */
    if (sock->recv_buf && sock->recv_buf_len > 0)
    {
        size_t avail = (sock->recv_buf_len < count) ? sock->recv_buf_len : count;
        memcpy(dst, sock->recv_buf, avail);
        total += avail;
        size_t remaining = sock->recv_buf_len - avail;
        if (remaining > 0)
            memmove(sock->recv_buf, sock->recv_buf + avail, remaining);
        sock->recv_buf_len = remaining;
    }

    while (total < count)
    {
        double remaining_ms = deadline - now_ms();
        if (remaining_ms <= 0)
        {
            errno = ETIMEDOUT;
            return (total > 0) ? (ssize_t)total : -1;
        }

        int ready = wait_for_fd(sock->fd, POLLIN, (uint32_t)remaining_ms);
        if (ready <= 0)
        {
            errno = (ready == 0) ? ETIMEDOUT : errno;
            return (total > 0) ? (ssize_t)total : -1;
        }

        ssize_t n = recv(sock->fd, dst + total, count - total, 0);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return (total > 0) ? (ssize_t)total : -1;
        }
        if (n == 0)
            return (ssize_t)total; /* EOF */

        total += (size_t)n;
    }

    return (ssize_t)total;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: Close
 * ═══════════════════════════════════════════════════════════════════════════ */

void npe_net_close(npe_net_socket_t *sock)
{
    if (!sock)
        return;

    if (sock->fd >= 0)
    {
        shutdown(sock->fd, SHUT_RDWR);
        close(sock->fd);
        sock->fd = -1;
    }

    if (sock->recv_buf)
    {
        free(sock->recv_buf);
        sock->recv_buf = NULL;
        sock->recv_buf_size = 0;
        sock->recv_buf_len = 0;
    }

    /* Note: SSL handle cleanup is handled by npe_lib_ssl if set. */
    sock->ssl_handle = NULL;
    sock->state = NPE_NET_STATE_CLOSED;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: Set Timeout
 * ═══════════════════════════════════════════════════════════════════════════ */

int npe_net_set_timeout(npe_net_socket_t *sock, uint32_t timeout_ms)
{
    if (!sock)
        return -1;
    sock->timeout_ms = timeout_ms;

    if (sock->fd >= 0)
    {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: Is Port Open
 * ═══════════════════════════════════════════════════════════════════════════ */

bool npe_net_is_port_open(const char *host, uint16_t port, uint32_t timeout_ms)
{
    npe_net_socket_t sock;
    if (npe_net_tcp_connect(host, port, timeout_ms, &sock) == 0)
    {
        npe_net_close(&sock);
        return true;
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * C-Level API: Resolve
 * ═══════════════════════════════════════════════════════════════════════════ */

int npe_net_resolve(const char *hostname, char *out_ip, size_t out_ip_size)
{
    if (!hostname || !out_ip || out_ip_size == 0)
        return -1;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(hostname, NULL, &hints, &res);
    if (rc != 0 || !res)
        return -1;

    void *addr_ptr = NULL;
    if (res->ai_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        addr_ptr = &sin->sin_addr;
    }
    else if (res->ai_family == AF_INET6)
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)res->ai_addr;
        addr_ptr = &sin6->sin6_addr;
    }

    if (!addr_ptr)
    {
        freeaddrinfo(res);
        return -1;
    }

    if (!inet_ntop(res->ai_family, addr_ptr, out_ip, (socklen_t)out_ip_size))
    {
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Lua Userdata Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_net_socket_t *
npe_net_push_socket(lua_State *L, const npe_net_socket_t *sock)
{
    npe_net_socket_t *ud = (npe_net_socket_t *)lua_newuserdata(L, sizeof(*ud));
    memcpy(ud, sock, sizeof(*ud));

    /* The userdata now owns the fd and buffers; mark Lua ownership. */
    ud->owned_by_lua = true;

    /*
     * Deep-copy the recv buffer so the original and the userdata
     * don't share the same heap pointer.
     */
    if (sock->recv_buf && sock->recv_buf_len > 0)
    {
        ud->recv_buf = malloc(sock->recv_buf_size);
        if (ud->recv_buf)
        {
            memcpy(ud->recv_buf, sock->recv_buf, sock->recv_buf_len);
            ud->recv_buf_size = sock->recv_buf_size;
            ud->recv_buf_len = sock->recv_buf_len;
        }
        else
        {
            ud->recv_buf_size = 0;
            ud->recv_buf_len = 0;
        }
    }
    else
    {
        ud->recv_buf = NULL;
        ud->recv_buf_size = 0;
        ud->recv_buf_len = 0;
    }

    luaL_getmetatable(L, NPE_NET_SOCKET_METATABLE);
    lua_setmetatable(L, -2);

    return ud;
}

npe_net_socket_t *
npe_net_check_socket(lua_State *L, int idx)
{
    return (npe_net_socket_t *)luaL_checkudata(L, idx, NPE_NET_SOCKET_METATABLE);
}

int npe_net_socket_gc(lua_State *L)
{
    npe_net_socket_t *sock = npe_net_check_socket(L, 1);
    if (sock && sock->state != NPE_NET_STATE_CLOSED)
    {
        npe_net_close(sock);
    }
    return 0;
}

int npe_net_socket_tostring(lua_State *L)
{
    npe_net_socket_t *sock = npe_net_check_socket(L, 1);
    const char *type_str = "UNKNOWN";
    switch (sock->type)
    {
    case NPE_NET_SOCK_TCP:
        type_str = "TCP";
        break;
    case NPE_NET_SOCK_UDP:
        type_str = "UDP";
        break;
    case NPE_NET_SOCK_RAW:
        type_str = "RAW";
        break;
    }

    if (sock->state == NPE_NET_STATE_CONNECTED)
    {
        lua_pushfstring(L, "npe.net.socket<%s:%s:%d>",
                        type_str, sock->peer_host, (int)sock->peer_port);
    }
    else
    {
        lua_pushfstring(L, "npe.net.socket<%s:closed>", type_str);
    }
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Lua-C Bindings
 * ═══════════════════════════════════════════════════════════════════════════ */

/* -- npe.net.tcp_connect(host, port [, timeout_ms]) → socket userdata -- */
int npe_net_l_tcp_connect(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);
    uint32_t tmo = (uint32_t)luaL_optinteger(L, 3, 0);

    if (port < 1 || port > 65535)
        return luaL_error(L, "npe.net.tcp_connect: port out of range");

    npe_net_socket_t sock;
    if (npe_net_tcp_connect(host, (uint16_t)port, tmo, &sock) < 0)
    {
        lua_pushnil(L);
        lua_pushfstring(L, "tcp_connect failed: %s", strerror(errno));
        return 2;
    }

    npe_net_push_socket(L, &sock);

    /*
     * After push_socket deep-copies, the stack-local 'sock' still holds
     * the original fd.  Zero it so we don't double-close.
     */
    sock.fd = -1;
    sock.recv_buf = NULL;

    return 1;
}

/* -- npe.net.udp_connect(host, port) → socket userdata -- */
int npe_net_l_udp_connect(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);

    if (port < 1 || port > 65535)
        return luaL_error(L, "npe.net.udp_connect: port out of range");

    npe_net_socket_t sock;
    if (npe_net_udp_create(host, (uint16_t)port, &sock) < 0)
    {
        lua_pushnil(L);
        lua_pushfstring(L, "udp_connect failed: %s", strerror(errno));
        return 2;
    }

    npe_net_push_socket(L, &sock);
    sock.fd = -1;
    sock.recv_buf = NULL;
    return 1;
}

/* -- npe.net.send(sock, data) → bytes_sent -- */
int npe_net_l_send(lua_State *L)
{
    npe_net_socket_t *sock = npe_net_check_socket(L, 1);
    size_t len = 0;
    const char *data = luaL_checklstring(L, 2, &len);

    if (sock->state != NPE_NET_STATE_CONNECTED)
        return luaL_error(L, "npe.net.send: socket not connected");

    ssize_t sent = npe_net_send(sock, data, len);
    if (sent < 0)
    {
        lua_pushnil(L);
        lua_pushfstring(L, "send failed: %s", strerror(errno));
        return 2;
    }

    lua_pushinteger(L, (lua_Integer)sent);
    return 1;
}

/* -- npe.net.recv(sock [, max_bytes [, timeout_ms]]) → data -- */
int npe_net_l_recv(lua_State *L)
{
    npe_net_socket_t *sock = npe_net_check_socket(L, 1);
    size_t max_bytes = (size_t)luaL_optinteger(L, 2, NPE_NET_DEFAULT_RECV_SIZE);
    uint32_t tmo = (uint32_t)luaL_optinteger(L, 3, 0);

    if (max_bytes > NPE_NET_MAX_RECV_SIZE)
        max_bytes = NPE_NET_MAX_RECV_SIZE;

    char *buf = malloc(max_bytes);
    if (!buf)
        return luaL_error(L, "npe.net.recv: out of memory");

    ssize_t n = npe_net_recv(sock, buf, max_bytes, tmo);
    if (n < 0)
    {
        free(buf);
        lua_pushnil(L);
        lua_pushfstring(L, "recv failed: %s", strerror(errno));
        return 2;
    }
    if (n == 0)
    {
        free(buf);
        lua_pushnil(L);
        lua_pushliteral(L, "connection closed");
        return 2;
    }

    lua_pushlstring(L, buf, (size_t)n);
    free(buf);
    return 1;
}

/* -- npe.net.recv_line(sock [, timeout_ms]) → line -- */
int npe_net_l_recv_line(lua_State *L)
{
    npe_net_socket_t *sock = npe_net_check_socket(L, 1);
    uint32_t tmo = (uint32_t)luaL_optinteger(L, 2, 0);

    char buf[NPE_NET_MAX_LINE_LENGTH + 1];
    ssize_t n = npe_net_recv_line(sock, buf, sizeof(buf), tmo);
    if (n < 0)
    {
        lua_pushnil(L);
        lua_pushfstring(L, "recv_line failed: %s", strerror(errno));
        return 2;
    }
    if (n == 0)
    {
        lua_pushnil(L);
        lua_pushliteral(L, "connection closed");
        return 2;
    }

    lua_pushlstring(L, buf, (size_t)n);
    return 1;
}

/* -- npe.net.recv_until(sock, pattern [, timeout_ms]) → data -- */
int npe_net_l_recv_until(lua_State *L)
{
    npe_net_socket_t *sock = npe_net_check_socket(L, 1);
    size_t pat_len = 0;
    const char *pattern = luaL_checklstring(L, 2, &pat_len);
    uint32_t tmo = (uint32_t)luaL_optinteger(L, 3, 0);

    size_t buf_size = NPE_NET_MAX_RECV_SIZE;
    char *buf = malloc(buf_size);
    if (!buf)
        return luaL_error(L, "npe.net.recv_until: out of memory");

    ssize_t n = npe_net_recv_until(sock, buf, buf_size, pattern, pat_len, tmo);
    if (n < 0)
    {
        free(buf);
        lua_pushnil(L);
        lua_pushfstring(L, "recv_until failed: %s", strerror(errno));
        return 2;
    }
    if (n == 0)
    {
        free(buf);
        lua_pushnil(L);
        lua_pushliteral(L, "connection closed without finding pattern");
        return 2;
    }

    lua_pushlstring(L, buf, (size_t)n);
    free(buf);
    return 1;
}

/* -- npe.net.recv_bytes(sock, count [, timeout_ms]) → data -- */
int npe_net_l_recv_bytes(lua_State *L)
{
    npe_net_socket_t *sock = npe_net_check_socket(L, 1);
    size_t count = (size_t)luaL_checkinteger(L, 2);
    uint32_t tmo = (uint32_t)luaL_optinteger(L, 3, 0);

    if (count > NPE_NET_MAX_RECV_SIZE)
        return luaL_error(L, "npe.net.recv_bytes: requested size too large");

    char *buf = malloc(count);
    if (!buf)
        return luaL_error(L, "npe.net.recv_bytes: out of memory");

    ssize_t n = npe_net_recv_bytes(sock, buf, count, tmo);
    if (n < 0)
    {
        free(buf);
        lua_pushnil(L);
        lua_pushfstring(L, "recv_bytes failed: %s", strerror(errno));
        return 2;
    }

    lua_pushlstring(L, buf, (size_t)n);
    free(buf);
    return 1;
}

/* -- npe.net.close(sock) -- */
int npe_net_l_close(lua_State *L)
{
    npe_net_socket_t *sock = npe_net_check_socket(L, 1);
    npe_net_close(sock);
    return 0;
}

/* -- npe.net.resolve(hostname) → ip_string -- */
int npe_net_l_resolve(lua_State *L)
{
    const char *hostname = luaL_checkstring(L, 1);
    char ip_buf[INET6_ADDRSTRLEN];

    if (npe_net_resolve(hostname, ip_buf, sizeof(ip_buf)) < 0)
    {
        lua_pushnil(L);
        lua_pushfstring(L, "resolve failed for '%s'", hostname);
        return 2;
    }

    lua_pushstring(L, ip_buf);
    return 1;
}

/* -- npe.net.is_port_open(host, port [, timeout_ms]) → boolean -- */
int npe_net_l_is_port_open(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);
    uint32_t tmo = (uint32_t)luaL_optinteger(L, 3, NPE_NET_DEFAULT_TIMEOUT_MS);

    if (port < 1 || port > 65535)
        return luaL_error(L, "npe.net.is_port_open: port out of range");

    lua_pushboolean(L, npe_net_is_port_open(host, (uint16_t)port, tmo));
    return 1;
}

/* -- npe.net.set_timeout(sock, timeout_ms) -- */
int npe_net_l_set_timeout(lua_State *L)
{
    npe_net_socket_t *sock = npe_net_check_socket(L, 1);
    uint32_t tmo = (uint32_t)luaL_checkinteger(L, 2);
    npe_net_set_timeout(sock, tmo);
    return 0;
}

/* -- npe.net.get_peer_info(sock) → { host, port, type, state } -- */
int npe_net_l_get_peer_info(lua_State *L)
{
    npe_net_socket_t *sock = npe_net_check_socket(L, 1);

    lua_newtable(L);

    lua_pushstring(L, sock->peer_host);
    lua_setfield(L, -2, "host");

    lua_pushinteger(L, (lua_Integer)sock->peer_port);
    lua_setfield(L, -2, "port");

    const char *type_str = "unknown";
    switch (sock->type)
    {
    case NPE_NET_SOCK_TCP:
        type_str = "tcp";
        break;
    case NPE_NET_SOCK_UDP:
        type_str = "udp";
        break;
    case NPE_NET_SOCK_RAW:
        type_str = "raw";
        break;
    }
    lua_pushstring(L, type_str);
    lua_setfield(L, -2, "type");

    const char *state_str = "unknown";
    switch (sock->state)
    {
    case NPE_NET_STATE_CLOSED:
        state_str = "closed";
        break;
    case NPE_NET_STATE_CONNECTING:
        state_str = "connecting";
        break;
    case NPE_NET_STATE_CONNECTED:
        state_str = "connected";
        break;
    case NPE_NET_STATE_ERROR:
        state_str = "error";
        break;
    }
    lua_pushstring(L, state_str);
    lua_setfield(L, -2, "state");

    lua_pushinteger(L, (lua_Integer)sock->socket_id);
    lua_setfield(L, -2, "id");

    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Module Registration
 * ═══════════════════════════════════════════════════════════════════════════ */

static const luaL_Reg net_methods[] = {
    {"tcp_connect", npe_net_l_tcp_connect},
    {"udp_connect", npe_net_l_udp_connect},
    {"send", npe_net_l_send},
    {"recv", npe_net_l_recv},
    {"recv_line", npe_net_l_recv_line},
    {"recv_until", npe_net_l_recv_until},
    {"recv_bytes", npe_net_l_recv_bytes},
    {"close", npe_net_l_close},
    {"resolve", npe_net_l_resolve},
    {"is_port_open", npe_net_l_is_port_open},
    {"set_timeout", npe_net_l_set_timeout},
    {"get_peer_info", npe_net_l_get_peer_info},
    {NULL, NULL}};

static const luaL_Reg socket_meta_methods[] = {
    {"__gc", npe_net_socket_gc},
    {"__tostring", npe_net_socket_tostring},
    {"send", npe_net_l_send},
    {"recv", npe_net_l_recv},
    {"recv_line", npe_net_l_recv_line},
    {"recv_until", npe_net_l_recv_until},
    {"recv_bytes", npe_net_l_recv_bytes},
    {"close", npe_net_l_close},
    {"set_timeout", npe_net_l_set_timeout},
    {"get_peer_info", npe_net_l_get_peer_info},
    {NULL, NULL}};

int luaopen_npe_net(lua_State *L)
{
    /* Create the socket metatable. */
    luaL_newmetatable(L, NPE_NET_SOCKET_METATABLE);

    /* Set __index to itself so socket:method() works. */
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");

    luaL_setfuncs(L, socket_meta_methods, 0);
    lua_pop(L, 1);

    /* Create and return the module table. */
    luaL_newlib(L, net_methods);
    return 1;
}
