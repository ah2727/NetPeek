#include "scanner_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef SOCK_SEQPACKET
#define SOCK_SEQPACKET 5
#endif

#define IDLE_TIMEOUT_FRACTION_DIV 2
#define IDLE_BASELINE_SAMPLES 4
#define IDLE_ROUNDS 3

static uint16_t checksum16(const void *data, size_t len)
{
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1)
    {
        uint16_t odd = 0;
        *(uint8_t *)&odd = *(const uint8_t *)ptr;
        sum += odd;
    }

    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);

    return (uint16_t)(~sum);
}

static uint32_t local_ipv4_for_target(const struct sockaddr_in *target)
{
    if (!target) return 0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;

    struct sockaddr_in tmp = *target;
    if (tmp.sin_port == 0)
        tmp.sin_port = htons(53);

    (void)connect(fd, (const struct sockaddr *)&tmp, sizeof(tmp));

    struct sockaddr_in local;
    socklen_t sl = sizeof(local);
    memset(&local, 0, sizeof(local));

    if (getsockname(fd, (struct sockaddr *)&local, &sl) != 0)
    {
        close(fd);
        return 0;
    }

    close(fd);
    return local.sin_addr.s_addr;
}

static np_connect_rc_t start_connect_proto(const np_target_t *target,
                                           uint16_t port,
                                           int socktype,
                                           int proto,
                                           int *out_fd)
{
    if (!target || !out_fd)
        return NP_CONNECT_FAILED;

    *out_fd = -1;

    int af = target->is_ipv6 ? AF_INET6 : AF_INET;
    int fd = socket(af, socktype, proto);
    if (fd < 0)
        return NP_CONNECT_FAILED;

#ifdef __APPLE__
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    if (np_set_nonblocking(fd) < 0)
    {
        close(fd);
        return NP_CONNECT_FAILED;
    }

    struct sockaddr_storage ss;
    socklen_t slen = 0;
    memset(&ss, 0, sizeof(ss));

    if (target->is_ipv6)
    {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);
        a6->sin6_addr = target->addr6.sin6_addr;
        slen = sizeof(*a6);
    }
    else
    {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&ss;
        a4->sin_family = AF_INET;
        a4->sin_port = htons(port);
        a4->sin_addr = target->addr4.sin_addr;
        slen = sizeof(*a4);
    }

    errno = 0;
    int rc = connect(fd, (struct sockaddr *)&ss, slen);
    if (rc == 0)
    {
        *out_fd = fd;
        return NP_CONNECT_IMMEDIATE;
    }

    if (rc < 0 && (errno == EINPROGRESS || errno == EWOULDBLOCK))
    {
        *out_fd = fd;
        return NP_CONNECT_IN_PROGRESS;
    }

    close(fd);
    return NP_CONNECT_FAILED;
}

void np_sctp_scan_task(void *arg)
{
    np_task_arg_t *targ = (np_task_arg_t *)arg;
    np_scan_ctx_t *ctx = &targ->ctx;
    const np_config_t *cfg = ctx->cfg;
    np_worker_ctx_t wctx = {
        .cfg = ctx->cfg,
        .queue = ctx->queue,
        .interrupted = ctx->interrupted,
        .metrics = ctx->metrics,
        .metrics_lock = ctx->metrics_lock,
        .total_work = ctx->total_work,
        .completed_work = ctx->completed_work,
        .completed_lock = ctx->completed_lock,
    };

    while (!(*ctx->interrupted))
    {
        np_work_item_t item;
        if (!np_wq_pop(ctx->queue, &item))
            break;

        const np_target_t *target = &cfg->targets[item.target_idx];
        np_port_state_t state = NP_PORT_FILTERED;
        double rtt = 0.0;

        np_timer_t tm;
        np_timer_start(&tm);

        int fd = -1;
        np_connect_rc_t rc = start_connect_proto(target,
                                                 item.port,
                                                 SOCK_SEQPACKET,
                                                 IPPROTO_SCTP,
                                                 &fd);

        if (rc == NP_CONNECT_IMMEDIATE)
        {
            state = NP_PORT_OPEN;
        }
        else if (rc == NP_CONNECT_IN_PROGRESS)
        {
            struct pollfd pfd = {.fd = fd, .events = POLLOUT};
            int pr = poll(&pfd, 1, (int)cfg->timeout_ms);
            if (pr > 0)
            {
                int err = np_get_socket_error(fd);
                if (err == 0)
                    state = NP_PORT_OPEN;
                else if (err == ECONNREFUSED)
                    state = NP_PORT_CLOSED;
                else
                    state = NP_PORT_FILTERED;
            }
            else if (pr == 0)
            {
                state = NP_PORT_FILTERED;
            }
            else
            {
                state = NP_PORT_FILTERED;
            }
        }
        else
        {
            if (errno == ECONNREFUSED)
                state = NP_PORT_CLOSED;
            else
                state = NP_PORT_FILTERED;
        }

        if (fd >= 0)
            close(fd);

        rtt = np_timer_elapsed_ms(&tm);
        np_record_result(&wctx,
                         item.target_idx,
                         item.port_idx,
                         item.port,
                         state,
                         rtt);
    }

    np_completion_signal(targ->completion);
}

static int ipproto_probe(const np_target_t *target,
                         uint8_t proto,
                         uint32_t timeout_ms,
                         np_port_state_t *out_state,
                         const char **out_reason)
{
    if (!target || target->is_ipv6 || !out_state || !out_reason)
        return -1;

    int send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_fd < 0)
    {
        *out_state = NP_PORT_FILTERED;
        *out_reason = "raw-send-failed";
        return 0;
    }

    int icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_fd < 0)
    {
        close(send_fd);
        *out_state = NP_PORT_FILTERED;
        *out_reason = "icmp-recv-failed";
        return 0;
    }

    int proto_fd = socket(AF_INET, SOCK_RAW, proto == 0 ? 255 : proto);
    if (proto_fd >= 0)
        np_set_nonblocking(proto_fd);

    int one = 1;
    setsockopt(send_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    np_set_nonblocking(icmp_fd);

    uint8_t packet[sizeof(struct ip) + 8];
    memset(packet, 0, sizeof(packet));

    struct ip *iph = (struct ip *)packet;
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(packet));
    iph->ip_id = htons((uint16_t)rand());
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = proto;

    uint32_t src_ip = local_ipv4_for_target(&target->addr4);
    if (src_ip == 0)
        src_ip = INADDR_ANY;

    iph->ip_src.s_addr = src_ip;
    iph->ip_dst = target->addr4.sin_addr;
    iph->ip_sum = checksum16(packet, sizeof(struct ip));

    struct sockaddr_in dst = target->addr4;
    (void)sendto(send_fd, packet, sizeof(packet), 0,
                 (struct sockaddr *)&dst, sizeof(dst));

    np_timer_t timer;
    np_timer_start(&timer);

    *out_state = NP_PORT_OPEN_FILTERED;
    *out_reason = "no-response";

    while (np_timer_elapsed_ms(&timer) < timeout_ms)
    {
        int wait_ms = 10;
        struct pollfd pfds[2];
        nfds_t nfds = 0;

        pfds[nfds].fd = icmp_fd;
        pfds[nfds].events = POLLIN;
        nfds++;

        if (proto_fd >= 0)
        {
            pfds[nfds].fd = proto_fd;
            pfds[nfds].events = POLLIN;
            nfds++;
        }

        int pr = poll(pfds, nfds, wait_ms);
        if (pr <= 0)
            continue;

        if (pfds[0].revents & POLLIN)
        {
            uint8_t buf[1500];
            struct sockaddr_in src;
            socklen_t sl = sizeof(src);
            ssize_t n = recvfrom(icmp_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&src, &sl);
            if (n > (ssize_t)(sizeof(struct ip) + sizeof(struct icmp)) &&
                src.sin_addr.s_addr == target->addr4.sin_addr.s_addr)
            {
                struct ip *outer = (struct ip *)buf;
                size_t off = (size_t)(outer->ip_hl * 4);
                if (n > (ssize_t)(off + sizeof(struct icmp) + sizeof(struct ip)))
                {
                    struct icmp *icmp = (struct icmp *)(buf + off);
                    struct ip *inner = (struct ip *)(buf + off + sizeof(struct icmp));
                    if ((uint8_t)inner->ip_p == proto)
                    {
                        if (icmp->icmp_type == 3 && icmp->icmp_code == 2)
                        {
                            *out_state = NP_PORT_CLOSED;
                            *out_reason = "proto-unreachable";
                            break;
                        }
                        if (icmp->icmp_type == 3 && (icmp->icmp_code == 1 || icmp->icmp_code == 3 ||
                                                     icmp->icmp_code == 9 || icmp->icmp_code == 10 || icmp->icmp_code == 13))
                        {
                            *out_state = NP_PORT_FILTERED;
                            *out_reason = "admin-filter";
                            break;
                        }
                    }
                }
            }
        }

        if (proto_fd >= 0 && nfds > 1 && (pfds[1].revents & POLLIN))
        {
            uint8_t buf[1500];
            struct sockaddr_in src;
            socklen_t sl = sizeof(src);
            ssize_t n = recvfrom(proto_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&src, &sl);
            if (n > 0 && src.sin_addr.s_addr == target->addr4.sin_addr.s_addr)
            {
                *out_state = NP_PORT_OPEN;
                *out_reason = "proto-response";
                break;
            }
        }
    }

    close(send_fd);
    close(icmp_fd);
    if (proto_fd >= 0)
        close(proto_fd);
    return 0;
}

void np_ipproto_scan_task(void *arg)
{
    np_task_arg_t *targ = (np_task_arg_t *)arg;
    np_scan_ctx_t *ctx = &targ->ctx;
    const np_config_t *cfg = ctx->cfg;
    np_worker_ctx_t wctx = {
        .cfg = ctx->cfg,
        .queue = ctx->queue,
        .interrupted = ctx->interrupted,
        .metrics = ctx->metrics,
        .metrics_lock = ctx->metrics_lock,
        .total_work = ctx->total_work,
        .completed_work = ctx->completed_work,
        .completed_lock = ctx->completed_lock,
    };

    while (!(*ctx->interrupted))
    {
        np_work_item_t item;
        if (!np_wq_pop(ctx->queue, &item))
            break;

        const np_target_t *target = &cfg->targets[item.target_idx];
        np_port_state_t state = NP_PORT_OPEN_FILTERED;
        const char *reason = "no-response";

        np_timer_t tm;
        np_timer_start(&tm);

        uint8_t proto = (uint8_t)(item.port & 0xffu);
        (void)ipproto_probe(target, proto, cfg->timeout_ms, &state, &reason);
        double rtt = np_timer_elapsed_ms(&tm);

        np_record_result(&wctx,
                         item.target_idx,
                         item.port_idx,
                         item.port,
                         state,
                         rtt);

        np_target_t *t = &ctx->cfg->targets[item.target_idx];
        if (item.port_idx < t->port_count)
            strncpy(t->results[item.port_idx].reason, reason,
                    sizeof(t->results[item.port_idx].reason) - 1);
    }

    np_completion_signal(targ->completion);
}

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

static int send_spoofed_syn(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
        return -1;

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        close(sock);
        return -1;
    }

    uint8_t packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct ip *ip = (struct ip *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ip));

    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_len = htons(sizeof(packet));
    ip->ip_src.s_addr = src_ip;
    ip->ip_dst.s_addr = dst_ip;
    ip->ip_id = htons((uint16_t)rand());

    tcp->th_sport = htons((uint16_t)(40000 + (rand() % 20000)));
    tcp->th_dport = htons(dst_port);
    tcp->th_seq = htonl((uint32_t)rand());
    tcp->th_off = 5;
    tcp->th_flags = TH_SYN;
    tcp->th_win = htons(8192);

    struct pseudo_header psh;
    psh.source_address = src_ip;
    psh.dest_address = dst_ip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    uint8_t pseudo[sizeof(psh) + sizeof(struct tcphdr)];
    memcpy(pseudo, &psh, sizeof(psh));
    memcpy(pseudo + sizeof(psh), tcp, sizeof(struct tcphdr));
    tcp->th_sum = checksum16(pseudo, sizeof(pseudo));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = dst_ip;
    dst.sin_port = htons(dst_port);

    int rc = (int)sendto(sock, packet, sizeof(packet), 0,
                         (struct sockaddr *)&dst, sizeof(dst));
    close(sock);
    return rc;
}

static int idle_probe_ipid(uint32_t zombie_ip, uint16_t zombie_port, uint16_t *out_ipid)
{
    if (!out_ipid) return -1;

    int recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_fd < 0)
        return -1;
    np_set_nonblocking(recv_fd);

    int send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_fd < 0)
    {
        close(recv_fd);
        return -1;
    }

    int one = 1;
    if (setsockopt(send_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        close(send_fd);
        close(recv_fd);
        return -1;
    }

    struct sockaddr_in tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.sin_family = AF_INET;
    tmp.sin_addr.s_addr = zombie_ip;
    tmp.sin_port = htons(zombie_port);

    uint32_t local_ip = local_ipv4_for_target(&tmp);
    if (local_ip == 0)
    {
        close(send_fd);
        close(recv_fd);
        return -1;
    }

    uint16_t src_port = (uint16_t)(45000 + (rand() % 10000));

    uint8_t packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct ip *ip = (struct ip *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ip));

    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_len = htons(sizeof(packet));
    ip->ip_src.s_addr = local_ip;
    ip->ip_dst.s_addr = zombie_ip;
    ip->ip_id = htons((uint16_t)rand());

    tcp->th_sport = htons(src_port);
    tcp->th_dport = htons(zombie_port);
    tcp->th_seq = htonl((uint32_t)rand());
    tcp->th_off = 5;
    tcp->th_flags = TH_SYN;
    tcp->th_win = htons(8192);

    struct pseudo_header psh;
    psh.source_address = local_ip;
    psh.dest_address = zombie_ip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    uint8_t pseudo[sizeof(psh) + sizeof(struct tcphdr)];
    memcpy(pseudo, &psh, sizeof(psh));
    memcpy(pseudo + sizeof(psh), tcp, sizeof(struct tcphdr));
    tcp->th_sum = checksum16(pseudo, sizeof(pseudo));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = zombie_ip;
    dst.sin_port = htons(zombie_port);

    (void)sendto(send_fd, packet, sizeof(packet), 0,
                 (struct sockaddr *)&dst, sizeof(dst));

    np_timer_t timer;
    np_timer_start(&timer);

    while (np_timer_elapsed_ms(&timer) < 1000.0)
    {
        struct pollfd pfd = {.fd = recv_fd, .events = POLLIN};
        if (poll(&pfd, 1, 20) <= 0)
            continue;

        uint8_t buf[1500];
        ssize_t n = recv(recv_fd, buf, sizeof(buf), 0);
        if (n < (ssize_t)(sizeof(struct ip) + sizeof(struct tcphdr)))
            continue;

        struct ip *rip = (struct ip *)buf;
        if (rip->ip_v != 4 || rip->ip_p != IPPROTO_TCP)
            continue;
        if (rip->ip_src.s_addr != zombie_ip)
            continue;

        int ihl = rip->ip_hl * 4;
        if (n < ihl + (int)sizeof(struct tcphdr))
            continue;

        struct tcphdr *rtcp = (struct tcphdr *)(buf + ihl);
        if (ntohs(rtcp->th_sport) != zombie_port)
            continue;
        if (ntohs(rtcp->th_dport) != src_port)
            continue;
        if (!(rtcp->th_flags & TH_RST))
            continue;

        *out_ipid = ntohs(rip->ip_id);
        close(send_fd);
        close(recv_fd);
        return 0;
    }

    close(send_fd);
    close(recv_fd);
    return -1;
}

static bool idle_zombie_is_sequential(uint32_t zombie_ip, uint16_t zombie_port)
{
    uint16_t ids[IDLE_BASELINE_SAMPLES];
    memset(ids, 0, sizeof(ids));

    for (int i = 0; i < IDLE_BASELINE_SAMPLES; i++)
    {
        if (idle_probe_ipid(zombie_ip, zombie_port, &ids[i]) != 0)
            return false;
        usleep(20000);
    }

    for (int i = 1; i < IDLE_BASELINE_SAMPLES; i++)
    {
        uint16_t d = (uint16_t)(ids[i] - ids[i - 1]);
        if (d == 0 || d > 8)
            return false;
    }

    return true;
}

void np_idle_scan_task(void *arg)
{
    np_task_arg_t *targ = (np_task_arg_t *)arg;
    np_scan_ctx_t *ctx = &targ->ctx;
    const np_config_t *cfg = ctx->cfg;
    np_worker_ctx_t wctx = {
        .cfg = ctx->cfg,
        .queue = ctx->queue,
        .interrupted = ctx->interrupted,
        .metrics = ctx->metrics,
        .metrics_lock = ctx->metrics_lock,
        .total_work = ctx->total_work,
        .completed_work = ctx->completed_work,
        .completed_lock = ctx->completed_lock,
    };

    if (cfg->zombie_host[0] == '\0')
    {
        while (true)
        {
            np_work_item_t item;
            if (!np_wq_pop(ctx->queue, &item)) break;
            np_record_result(&wctx,
                             item.target_idx,
                             item.port_idx,
                             item.port,
                             NP_PORT_FILTERED,
                             0.0);
            np_target_t *t = &ctx->cfg->targets[item.target_idx];
            if (item.port_idx < t->port_count)
                strncpy(t->results[item.port_idx].reason, "idle-no-zombie",
                        sizeof(t->results[item.port_idx].reason) - 1);
        }
        np_completion_signal(targ->completion);
        return;
    }

    struct sockaddr_in zombie_addr;
    memset(&zombie_addr, 0, sizeof(zombie_addr));
    zombie_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, cfg->zombie_host, &zombie_addr.sin_addr) != 1)
    {
        np_completion_signal(targ->completion);
        return;
    }

    if (!idle_zombie_is_sequential(zombie_addr.sin_addr.s_addr, cfg->zombie_probe_port))
    {
        while (true)
        {
            np_work_item_t item;
            if (!np_wq_pop(ctx->queue, &item)) break;
            np_record_result(&wctx,
                             item.target_idx,
                             item.port_idx,
                             item.port,
                             NP_PORT_FILTERED,
                             0.0);
            np_target_t *t = &ctx->cfg->targets[item.target_idx];
            if (item.port_idx < t->port_count)
                strncpy(t->results[item.port_idx].reason,
                        "idle-zombie-ipid-randomized",
                        sizeof(t->results[item.port_idx].reason) - 1);
        }
        np_completion_signal(targ->completion);
        return;
    }

    while (!(*ctx->interrupted))
    {
        np_work_item_t item;
        if (!np_wq_pop(ctx->queue, &item))
            break;

        const np_target_t *target = &cfg->targets[item.target_idx];
        np_port_state_t state = NP_PORT_FILTERED;
        const char *reason = "idle-failed";

        np_timer_t tm;
        np_timer_start(&tm);

        int open_votes = 0;
        int closed_votes = 0;
        int filtered_votes = 0;

        for (int round = 0; round < IDLE_ROUNDS; round++)
        {
            uint16_t id1 = 0, id2 = 0;
            int rc1 = idle_probe_ipid(zombie_addr.sin_addr.s_addr,
                                      cfg->zombie_probe_port,
                                      &id1);
            if (rc1 != 0)
            {
                filtered_votes++;
                continue;
            }

            (void)send_spoofed_syn(zombie_addr.sin_addr.s_addr,
                                   target->addr4.sin_addr.s_addr,
                                   item.port);
            usleep((useconds_t)((cfg->timeout_ms / IDLE_TIMEOUT_FRACTION_DIV) * 1000u));

            int rc2 = idle_probe_ipid(zombie_addr.sin_addr.s_addr,
                                      cfg->zombie_probe_port,
                                      &id2);
            if (rc2 != 0)
            {
                filtered_votes++;
                continue;
            }

            uint16_t delta = (uint16_t)(id2 - id1);
            if (delta == 2)
                open_votes++;
            else if (delta == 1)
                closed_votes++;
            else
                filtered_votes++;
        }

        if (open_votes > closed_votes && open_votes >= filtered_votes)
        {
            state = NP_PORT_OPEN;
            reason = "idle-ipid-open";
        }
        else if (closed_votes > open_votes && closed_votes >= filtered_votes)
        {
            state = NP_PORT_CLOSED;
            reason = "idle-ipid-closed";
        }
        else
        {
            state = NP_PORT_FILTERED;
            reason = "idle-ambiguous";
        }

        double rtt = np_timer_elapsed_ms(&tm);

        np_record_result(&wctx,
                         item.target_idx,
                         item.port_idx,
                         item.port,
                         state,
                         rtt);

        np_target_t *t = &ctx->cfg->targets[item.target_idx];
        if (item.port_idx < t->port_count)
            strncpy(t->results[item.port_idx].reason, reason,
                    sizeof(t->results[item.port_idx].reason) - 1);
    }

    np_completion_signal(targ->completion);
}
