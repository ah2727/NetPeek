#include "os_port_discovery.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/select.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "os_port_discovery.h"

/*
 * Common ports likely to be open.
 * Order matters: faster discovery if common services exist.
 */

static const uint16_t common_ports[] =
{
    22,     /* SSH   */
    80,     /* HTTP  */
    443,    /* HTTPS */
    8080,   /* HTTP alt */
    21,     /* FTP   */
    25,     /* SMTP  */
    110,    /* POP3  */
    143,    /* IMAP  */
    3306,   /* MySQL */
    3389    /* RDP   */
};

static const uint32_t common_port_count =
        sizeof(common_ports) / sizeof(common_ports[0]);




int np_find_closed_port(const char *ip, uint16_t *out)
{
    if (!ip || !out)
        return -1;

    /* High ephemeral range – very unlikely to be open */
    for (uint16_t port = 65000; port < 65535; port++)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
            continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));

        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);

        if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
        {
            close(sock);
            continue;
        }

        /* short timeout */
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 300000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        int r = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        int err = errno;

        close(sock);

        if (r < 0 && err == ECONNREFUSED)
        {
            *out = port;
            return 0;
        }
    }

    return -1;
}

/* ---------------------------------------------------- */
/* Non‑blocking connect helper                         */
/* ---------------------------------------------------- */

static int try_connect(const char *ip, uint16_t port, int timeout_ms)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
    {
        close(sock);
        return -1;
    }

    /* make socket non‑blocking */

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    if (res < 0 && errno != EINPROGRESS)
    {
        close(sock);
        return -1;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    res = select(sock + 1, NULL, &wfds, NULL, &tv);

    if (res <= 0)
    {
        close(sock);
        return -1;
    }

    int err = 0;
    socklen_t len = sizeof(err);

    getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);

    close(sock);

    if (err == 0)
        return 0;

    return -1;
}


/* ---------------------------------------------------- */
/* Public API                                           */
/* ---------------------------------------------------- */
/* Common ports to probe for OS detection */
static const uint16_t discovery_ports[] = {
        /* High-priority: ports nmap found open on your machine */
        5000, 5432, 3306, 7000, 7070, 9000, 9050,
        /* Common services */
        22, 80, 443, 8080, 8443,
        /* Databases & dev tools */
        6379, 27017, 11211, 15672,
        /* Web frameworks */
        3000, 4200, 4567, 8000, 8888,
        /* Docker / k8s */
        2375, 2376, 6443, 10250,
        /* Mail / misc */
        25, 110, 143, 993, 995, 587,
        21, 23, 53, 111, 135, 139, 445,
        389, 636, 1433, 1521, 3389,
        5900, 5901, 6000, 6001,
        8081, 8082, 8443, 9090, 9200, 9300,
        /* Fallback high ports */
        49152, 49153, 49154, 49155,
    };;

#define DISCOVERY_PORT_COUNT \
    (sizeof(discovery_ports) / sizeof(discovery_ports[0]))

/* Try a quick TCP connect to classify port as open or closed */
static int quick_connect(const char *ip, uint16_t port, uint32_t timeout_ms)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc == 0) {
        close(fd);
        return 1;  /* open */
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return 0;  /* closed / unreachable */
    }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    rc = poll(&pfd, 1, (int)timeout_ms);

    if (rc > 0 && (pfd.revents & POLLOUT)) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        close(fd);
        return (err == 0) ? 1 : 0;
    }

    close(fd);
    return -1;  /* filtered / timeout */
}

/* ── Public API ──────────────────────────────────────── */

int np_find_open_port(const char *ip, uint16_t *out)
{
    for (unsigned i = 0; i < DISCOVERY_PORT_COUNT; i++) {
        if (quick_connect(ip, discovery_ports[i], 1500) == 1) {
            *out = discovery_ports[i];
            return 0;
        }
    }
    return -1;
}

int np_os_discover_ports(const char *target_ip,
                         uint32_t    timeout_ms,
                         np_os_discovery_result_t *result)
{
    if (!target_ip || !result) return -1;

    memset(result, 0, sizeof(*result));

    for (unsigned i = 0; i < DISCOVERY_PORT_COUNT; i++) {
        int rc = quick_connect(target_ip, discovery_ports[i], timeout_ms);

        if (rc == 1) {
            /* Open */
            if (result->open_count < NP_DISCOVERY_MAX_OPEN) {
                result->open_ports[result->open_count++] = discovery_ports[i];
            }
        } else if (rc == 0) {
            /* Closed — record it */
            if (result->closed_count < NP_DISCOVERY_MAX_CLOSED) {
                result->closed_ports[result->closed_count++] = discovery_ports[i];
            }
            if (!result->has_closed) {
                result->closed_port = discovery_ports[i];
                result->has_closed  = true;
            }
        }
        /* rc == -1 → filtered, skip */
    }

    return 0;
}
