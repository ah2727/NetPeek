/* os_ttl_fallback.c — extract TTL from a normal TCP connection */

#include <stdio.h>
#include "core/error.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <poll.h>

#include "os_ttl_fallback.h"

/* ------------------------------------------------------------------ */
/*  Minimal fallback logging if the project-wide np_log is not        */
/*  available via os_ttl_fallback.h or another included header.       */
/* ------------------------------------------------------------------ */
#ifndef NP_LOG_DEBUG
#define NP_LOG_DEBUG 0
#endif
#ifndef NP_LOG_INFO
#define NP_LOG_INFO  1
#endif

#ifndef HAVE_NP_LOG
/* Replace this with your real logging include/path when available.
   For now, a simple stderr fallback keeps the build green.          */
#include <stdarg.h>
static void np_log(int level, const char *fmt, ...)
{
    (void)level;
    va_list ap;
    va_start(ap, fmt);
    np_verror(NP_ERR_RUNTIME, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
#endif
/* ------------------------------------------------------------------ */

/*
 * Attempt to determine the remote host's initial TTL by connecting
 * via a normal TCP socket and reading the TTL from the received packets
 * using IP_RECVTTL (Linux) or IP_TTL inspection.
 *
 * Returns the observed TTL, or -1 on failure.
 */
int np_get_ttl_via_tcp(const char *target_ip, uint16_t port, int timeout_ms)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Enable TTL reception on this socket */
    int on = 1;
#ifdef IP_RECVTTL
    setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
#endif

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };

    /* BUG FIX: was `ip` — the parameter is called `target_ip` */
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    /* Blocking connect with timeout via poll */
    struct timeval tv = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        np_log(NP_LOG_DEBUG, "ttl_fallback: connect failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /*
     * On macOS/BSD we can read the TTL of the last received packet
     * via getsockopt IP_TTL on the connected socket.
     */
    int ttl = -1;
    socklen_t ttl_len = sizeof(ttl);

#if defined(__APPLE__) || defined(__FreeBSD__)
    /* macOS: IP_TTL on a connected TCP socket returns the TTL of received pkts */
    if (getsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, &ttl_len) == 0) {
        np_log(NP_LOG_INFO, "ttl_fallback: got TTL=%d via getsockopt", ttl);
    }
#else
    /*
     * Linux: use recvmsg with IP_RECVTTL ancillary data.
     * We need to receive at least one byte, so send a tiny probe first.
     */
    const char *probe = "\r\n";
    send(fd, probe, 2, 0);

    char buf[256];
    char cmsgbuf[256];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (poll(&pfd, 1, timeout_ms) > 0) {
        ssize_t n = recvmsg(fd, &msg, 0);
        if (n > 0) {
            struct cmsghdr *cmsg;
            for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
                 cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == IPPROTO_IP &&
                    cmsg->cmsg_type  == IP_TTL) {
                    ttl = *(int *)CMSG_DATA(cmsg);
                    np_log(NP_LOG_INFO,
                           "ttl_fallback: got TTL=%d via recvmsg", ttl);
                    break;
                }
            }
        }
    }
#endif

    close(fd);
    return ttl;
}

/*
 * Infer the initial TTL and OS family from an observed TTL value.
 * Common initial TTLs:
 *   64  → Linux, macOS, iOS, Android, FreeBSD
 *   128 → Windows
 *   255 → Solaris, some network equipment
 */
const char *np_os_family_from_ttl(int observed_ttl)
{
    if (observed_ttl <= 0)   return "unknown";
    if (observed_ttl <= 64)  return "unix-like";   /* Linux, macOS, BSD */
    if (observed_ttl <= 128) return "windows";
    if (observed_ttl <= 255) return "solaris/network-device";
    return "unknown";
}

int np_initial_ttl_from_observed(int observed_ttl)
{
    if (observed_ttl <= 0)   return 0;
    if (observed_ttl <= 64)  return 64;
    if (observed_ttl <= 128) return 128;
    if (observed_ttl <= 255) return 255;
    return 0;
}
