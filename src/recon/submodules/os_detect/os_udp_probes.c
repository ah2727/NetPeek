#include "os_udp_probes.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

/* ------------------------------------------------ */
/* ICMP Receive Helper                              */
/* ------------------------------------------------ */

static void np_recv_icmp(
    np_pipeline_ctx_t *ctx,
    np_udp_probe_result_t *out)
{
    uint8_t buf[1024];
    struct sockaddr_in src;
    socklen_t slen = sizeof(src);

    struct timeval tv;
    tv.tv_sec = ctx->timeout_ms / 1000;
    tv.tv_usec = (ctx->timeout_ms % 1000) * 1000;
    setsockopt(ctx->icmp_sock, SOL_SOCKET, SO_RCVTIMEO,
               &tv, sizeof(tv));

    ssize_t n = recvfrom(
        ctx->icmp_sock,
        buf,
        sizeof(buf),
        0,
        (struct sockaddr *)&src,
        &slen);

    if (n <= 0)
        return;

    struct ip *ip = (struct ip *)buf;
    uint8_t ip_hl = ip->ip_hl * 4;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)

    if (n < ip_hl + sizeof(struct icmp))
        return;

    struct icmp *icmp =
        (struct icmp *)(buf + ip_hl);

    out->responded = true;
    out->icmp_type = icmp->icmp_type;
    out->icmp_code = icmp->icmp_code;

#else /* Linux */

    if (n < ip_hl + sizeof(struct icmphdr))
        return;

    struct icmphdr *icmp =
        (struct icmphdr *)(buf + ip_hl);

    out->responded = true;
    out->icmp_type = icmp->type;
    out->icmp_code = icmp->code;

#endif

    out->ttl = ip->ip_ttl;
}


/* ------------------------------------------------ */
/* ✅ UDP U1 Probe                                  */
/* ------------------------------------------------ */

void np_send_udp_u1(
    np_pipeline_ctx_t *ctx,
    const np_target_t *tgt,
    np_udp_probe_result_t *out)
{
    memset(out, 0, sizeof(*out));

    uint8_t payload[300];
    memset(payload, 0, sizeof(payload));

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
        return;

    struct sockaddr_in dst = tgt->addr;
    dst.sin_port = htons(tgt->closed_port);

    sendto(
        sock,
        payload,
        sizeof(payload),
        0,
        (struct sockaddr *)&dst,
        sizeof(dst));

    /* ✅ Wait for ICMP unreachable */
    np_recv_icmp(ctx, out);

    close(sock);
}
