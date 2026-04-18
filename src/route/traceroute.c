#define _POSIX_C_SOURCE 200809L

#include "route/route.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "logger.h"

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static bool ipv4_match_probe(const uint8_t *buf,
                             ssize_t len,
                             const struct in_addr *dst_addr,
                             uint16_t dst_port,
                             bool *reached)
{
    if (len < (ssize_t)(sizeof(struct ip) + sizeof(struct icmp)))
        return false;

    const struct ip *ip = (const struct ip *)buf;
    size_t ip_hlen = (size_t)ip->ip_hl * 4u;
    if (ip_hlen < sizeof(struct ip) || len < (ssize_t)(ip_hlen + sizeof(struct icmp)))
        return false;

    const struct icmp *icmp = (const struct icmp *)(buf + ip_hlen);
    if (icmp->icmp_type != ICMP_TIMXCEED && icmp->icmp_type != ICMP_UNREACH)
        return false;

    if (len < (ssize_t)(ip_hlen + 8 + sizeof(struct ip)))
        return false;

    const uint8_t *inner = buf + ip_hlen + 8;
    const struct ip *inner_ip = (const struct ip *)inner;
    size_t inner_hlen = (size_t)inner_ip->ip_hl * 4u;
    if (inner_hlen < sizeof(struct ip))
        return false;

    if (inner_ip->ip_p != IPPROTO_UDP)
        return false;

    if (memcmp(&inner_ip->ip_dst, dst_addr, sizeof(*dst_addr)) != 0)
        return false;

    if ((size_t)len < ip_hlen + 8 + inner_hlen + sizeof(struct udphdr))
        return false;

    const struct udphdr *uh = (const struct udphdr *)(inner + inner_hlen);
    if (ntohs(uh->uh_dport) != dst_port)
        return false;

    *reached = (icmp->icmp_type == ICMP_UNREACH && icmp->icmp_code == ICMP_UNREACH_PORT);
    return true;
}

static np_status_t probe_ipv4_hop(const np_target_t *target,
                                  uint8_t ttl,
                                  uint32_t timeout_ms,
                                  char *hop_ip,
                                  size_t hop_ip_len,
                                  double *out_rtt,
                                  bool *out_timeout,
                                  bool *out_reached)
{
    int send_fd = -1;
    int recv_fd = -1;
    np_status_t rc = NP_OK;

    *out_timeout = true;
    *out_reached = false;

    send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (send_fd < 0 || recv_fd < 0)
    {
        LOGD("[route] ttl=%u socket setup failed: %s\n", (unsigned)ttl, strerror(errno));
        goto done;
    }

    int ttl_opt = (int)ttl;
    if (setsockopt(send_fd, IPPROTO_IP, IP_TTL, &ttl_opt, sizeof(ttl_opt)) != 0)
    {
        LOGD("[route] ttl=%u setsockopt(IP_TTL) failed: %s\n", (unsigned)ttl, strerror(errno));
        goto done;
    }

    struct sockaddr_in dst = target->addr4;
    uint16_t dport = (uint16_t)(33434u + ttl);
    dst.sin_port = htons(dport);

    uint8_t payload[8] = {0};
    payload[0] = ttl;

    double started = now_ms();
    if (sendto(send_fd, payload, sizeof(payload), 0, (const struct sockaddr *)&dst, sizeof(dst)) < 0)
    {
        LOGD("[route] ttl=%u sendto failed: %s\n", (unsigned)ttl, strerror(errno));
        goto done;
    }

    struct pollfd pfd = {.fd = recv_fd, .events = POLLIN};
    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr <= 0)
    {
        *out_timeout = true;
        rc = NP_OK;
        goto done;
    }

    uint8_t rbuf[2048];
    struct sockaddr_in src;
    socklen_t slen = sizeof(src);
    ssize_t n = recvfrom(recv_fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&src, &slen);
    if (n <= 0)
    {
        LOGD("[route] ttl=%u recvfrom failed: %s\n", (unsigned)ttl, strerror(errno));
        goto done;
    }

    bool reached = false;
    if (!ipv4_match_probe(rbuf, n, &target->addr4.sin_addr, dport, &reached))
    {
        *out_timeout = true;
        rc = NP_OK;
        goto done;
    }

    inet_ntop(AF_INET, &src.sin_addr, hop_ip, (socklen_t)hop_ip_len);
    *out_rtt = now_ms() - started;
    *out_timeout = false;
    *out_reached = reached;
    rc = NP_OK;

done:
    if (send_fd >= 0)
        close(send_fd);
    if (recv_fd >= 0)
        close(recv_fd);
    return rc;
}

static bool ipv6_match_probe(const uint8_t *buf,
                             ssize_t len,
                             const struct in6_addr *dst_addr,
                             uint16_t dst_port,
                             bool *reached)
{
    if (len < (ssize_t)sizeof(struct icmp6_hdr))
        return false;

    const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)buf;
    if (icmp6->icmp6_type != ICMP6_TIME_EXCEEDED && icmp6->icmp6_type != ICMP6_DST_UNREACH)
        return false;

    const uint8_t *inner = buf + sizeof(struct icmp6_hdr);
    ssize_t inner_len = len - (ssize_t)sizeof(struct icmp6_hdr);
    if (inner_len < 48)
        return false;

    const struct ip6_hdr *inner_ip6 = (const struct ip6_hdr *)inner;
    if (inner_ip6->ip6_nxt != IPPROTO_UDP)
        return false;

    if (memcmp(&inner_ip6->ip6_dst, dst_addr, sizeof(*dst_addr)) != 0)
        return false;

    const struct udphdr *uh = (const struct udphdr *)(inner + sizeof(struct ip6_hdr));
    if (ntohs(uh->uh_dport) != dst_port)
        return false;

    *reached = (icmp6->icmp6_type == ICMP6_DST_UNREACH);
    return true;
}

static np_status_t probe_ipv6_hop(const np_target_t *target,
                                  uint8_t ttl,
                                  uint32_t timeout_ms,
                                  char *hop_ip,
                                  size_t hop_ip_len,
                                  double *out_rtt,
                                  bool *out_timeout,
                                  bool *out_reached)
{
    int send_fd = -1;
    int recv_fd = -1;
    np_status_t rc = NP_OK;

    *out_timeout = true;
    *out_reached = false;

    send_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    recv_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (send_fd < 0 || recv_fd < 0)
    {
        LOGD("[route] ttl=%u socket6 setup failed: %s\n", (unsigned)ttl, strerror(errno));
        goto done;
    }

    int hops = ttl;
    if (setsockopt(send_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) != 0)
    {
        LOGD("[route] ttl=%u setsockopt(IPV6_UNICAST_HOPS) failed: %s\n", (unsigned)ttl, strerror(errno));
        goto done;
    }

    struct sockaddr_in6 dst = target->addr6;
    uint16_t dport = (uint16_t)(33434u + ttl);
    dst.sin6_port = htons(dport);

    uint8_t payload[8] = {0};
    payload[0] = ttl;

    double started = now_ms();
    if (sendto(send_fd, payload, sizeof(payload), 0, (const struct sockaddr *)&dst, sizeof(dst)) < 0)
    {
        LOGD("[route] ttl=%u sendto6 failed: %s\n", (unsigned)ttl, strerror(errno));
        goto done;
    }

    struct pollfd pfd = {.fd = recv_fd, .events = POLLIN};
    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr <= 0)
    {
        *out_timeout = true;
        rc = NP_OK;
        goto done;
    }

    uint8_t rbuf[2048];
    struct sockaddr_in6 src;
    socklen_t slen = sizeof(src);
    ssize_t n = recvfrom(recv_fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&src, &slen);
    if (n <= 0)
    {
        LOGD("[route] ttl=%u recvfrom6 failed: %s\n", (unsigned)ttl, strerror(errno));
        goto done;
    }

    bool reached = false;
    if (!ipv6_match_probe(rbuf, n, &target->addr6.sin6_addr, dport, &reached))
    {
        *out_timeout = true;
        rc = NP_OK;
        goto done;
    }

    inet_ntop(AF_INET6, &src.sin6_addr, hop_ip, (socklen_t)hop_ip_len);
    *out_rtt = now_ms() - started;
    *out_timeout = false;
    *out_reached = reached;
    rc = NP_OK;

done:
    if (send_fd >= 0)
        close(send_fd);
    if (recv_fd >= 0)
        close(recv_fd);
    return rc;
}

np_status_t np_route_traceroute(const np_target_t *target,
                                const np_route_options_t *opts,
                                np_route_result_t *out)
{
    if (!target || !opts || !out)
        return NP_ERR_ARGS;

    memset(out, 0, sizeof(*out));
    strncpy(out->target_input, target->hostname, sizeof(out->target_input) - 1);
    strncpy(out->target_ip, target->ip, sizeof(out->target_ip) - 1);
    out->target_is_ipv6 = target->is_ipv6;

    out->hops = calloc(opts->max_hops, sizeof(*out->hops));
    if (!out->hops)
        return NP_ERR_MEMORY;

    LOGI("[route] traceroute start target=%s (%s) max_hops=%u timeout=%ums\n",
         out->target_input,
         out->target_ip,
         opts->max_hops,
         opts->timeout_ms);

    for (uint32_t i = 0; i < opts->max_hops; i++)
    {
        np_route_hop_t *hop = &out->hops[out->hop_count++];
        hop->ttl = (uint8_t)(i + 1);
        hop->is_ipv6 = target->is_ipv6;

        bool timeout = true;
        bool reached = false;
        double rtt_ms = 0.0;
        np_status_t rc;

        if (target->is_ipv6)
            rc = probe_ipv6_hop(target, hop->ttl, opts->timeout_ms, hop->ip, sizeof(hop->ip), &rtt_ms, &timeout, &reached);
        else
            rc = probe_ipv4_hop(target, hop->ttl, opts->timeout_ms, hop->ip, sizeof(hop->ip), &rtt_ms, &timeout, &reached);

        if (rc != NP_OK)
            return rc;

        hop->timeout = timeout;
        hop->rtt_ms = rtt_ms;
        hop->is_target = reached;

        if (timeout)
            LOGD("[route] ttl=%u timeout\n", (unsigned)hop->ttl);
        else
            LOGD("[route] ttl=%u hop=%s rtt=%.2fms%s\n",
                 (unsigned)hop->ttl,
                 hop->ip,
                 hop->rtt_ms,
                 reached ? " target" : "");

        if (reached)
        {
            LOGI("[route] destination reached at ttl=%u\n", (unsigned)hop->ttl);
            break;
        }
    }

    LOGI("[route] traceroute complete hops=%u\n", out->hop_count);

    return NP_OK;
}

void np_route_result_free(np_route_result_t *result)
{
    if (!result)
        return;

    if (result->hops)
    {
        for (uint32_t i = 0; i < result->hop_count; i++)
            free(result->hops[i].open_ports);
    }
    free(result->hops);
    memset(result, 0, sizeof(*result));
}
