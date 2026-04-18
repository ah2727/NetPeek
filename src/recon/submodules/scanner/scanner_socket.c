#include "scanner_internal.h"
#include "proxy.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

int np_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int np_get_socket_error(int fd)
{
    int err = 0;
    socklen_t len = sizeof(err);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
        return errno;

    return err;
}

np_connect_rc_t np_start_connect(const np_target_t *target,
                                 uint16_t port,
                                 int timeout_ms,
                                 int *out_fd)
{
    (void)timeout_ms;

    *out_fd = -1;

    int af = target->is_ipv6 ? AF_INET6 : AF_INET;

    int fd = socket(af, SOCK_STREAM, 0);
    if (fd < 0)
        return NP_CONNECT_FAILED;

    /* --------------------------------------------- */
    /* macOS: prevent SIGPIPE on connect/write       */
    /* --------------------------------------------- */
#ifdef __APPLE__
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    /* --------------------------------------------- */
    /* Non-blocking                                  */
    /* --------------------------------------------- */
    if (np_set_nonblocking(fd) < 0)
    {
        close(fd);
        return NP_CONNECT_FAILED;
    }

    /* --------------------------------------------- */
    /* Address setup                                 */
    /* --------------------------------------------- */
    struct sockaddr_storage ss;
    socklen_t slen;

    memset(&ss, 0, sizeof(ss));

    if (target->is_ipv6)
    {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
        a6->sin6_family = AF_INET6;
        a6->sin6_port   = htons(port);
        a6->sin6_addr   = target->addr6.sin6_addr;
        slen = sizeof(*a6);
    }
    else
    {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&ss;
        a4->sin_family = AF_INET;
        a4->sin_port   = htons(port);
        a4->sin_addr   = target->addr4.sin_addr;
        slen = sizeof(*a4);
    }

    /* --------------------------------------------- */
    /* Connect                                       */
    /* --------------------------------------------- */
    errno = 0;
    int rc = connect(fd, (struct sockaddr *)&ss, slen);

    /* ✅ Immediate success (e.g. localhost or ultra-low latency) */
    if (rc == 0)
    {
        *out_fd = fd;
        return NP_CONNECT_IMMEDIATE;
    }

    /* ✅ Expected non-blocking path (safeguard with EWOULDBLOCK) */
    if (rc < 0 && (errno == EINPROGRESS || errno == EWOULDBLOCK))
    {
        *out_fd = fd;
        return NP_CONNECT_IN_PROGRESS;
    }

    close(fd);
    return NP_CONNECT_FAILED;
}

np_connect_rc_t np_start_connect_proxy(const np_proxy_t *proxy,
                                       const np_target_t *target,
                                       uint16_t port,
                                       uint32_t timeout_ms,
                                       int *out_fd)
{
    int fd = np_proxy_connect(proxy, target->hostname, port, timeout_ms);
    if (fd < 0)
        return NP_CONNECT_FAILED;

    if (np_set_nonblocking(fd) < 0)
    {
        close(fd);
        return NP_CONNECT_FAILED;
    }

    *out_fd = fd;
    return NP_CONNECT_IMMEDIATE; /* ✅ tunnel established */
}

int np_start_udp(const np_target_t *target, uint16_t port)
{
    int af = target->is_ipv6 ? AF_INET6 : AF_INET;

    int fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return -1;

    struct sockaddr_storage addr;
    socklen_t addrlen;
    memset(&addr, 0, sizeof(addr));

    if (af == AF_INET)
    {
        struct sockaddr_in *sa = (struct sockaddr_in *)&addr;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr = target->addr4.sin_addr;
        addrlen = sizeof(*sa);
    }
    else
    {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&addr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(port);
        sa6->sin6_addr = target->addr6.sin6_addr;
        addrlen = sizeof(*sa6);
    }

    /* UDP connect is a local socket operation; do it in blocking mode for
     * deterministic behavior, then switch to non-blocking for the event loop. */
    if (connect(fd, (struct sockaddr *)&addr, addrlen) < 0)
    {
        close(fd);
        return -1;
    }

    if (np_set_nonblocking(fd) < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}
