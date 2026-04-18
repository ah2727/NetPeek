#define _POSIX_C_SOURCE 200809L

#include "host_discovery.h"
#include "core/error.h"
#include "traceroute.h"
#include "target.h"
#include "ports.h"

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static bool has_explicit_discovery_probe(const np_config_t *cfg)
{
    if (!cfg)
        return false;

    return cfg->probe_icmp_echo ||
           cfg->probe_icmp_timestamp ||
           cfg->probe_icmp_netmask ||
           cfg->probe_tcp_syn ||
           cfg->probe_tcp_ack ||
           cfg->probe_udp ||
           cfg->probe_sctp_init ||
           cfg->probe_ip_proto;
}

static bool set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool probe_tcp_connect(const np_target_t *target,
                              uint16_t port,
                              uint32_t timeout_ms,
                              double *out_rtt_ms,
                              const char **out_reason)
{
    if (!target)
        return false;

    int fd = socket(target->is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return false;

    if (!set_nonblocking(fd))
    {
        close(fd);
        return false;
    }

    struct sockaddr_storage ss;
    socklen_t slen = 0;
    memset(&ss, 0, sizeof(ss));

    if (target->is_ipv6)
    {
        struct sockaddr_in6 sin6 = target->addr6;
        sin6.sin6_port = htons(port);
        memcpy(&ss, &sin6, sizeof(sin6));
        slen = sizeof(sin6);
    }
    else
    {
        struct sockaddr_in sin = target->addr4;
        sin.sin_port = htons(port);
        memcpy(&ss, &sin, sizeof(sin));
        slen = sizeof(sin);
    }

    int rc = connect(fd, (struct sockaddr *)&ss, slen);
    if (rc == 0)
    {
        if (out_rtt_ms)
            *out_rtt_ms = 1.0;
        if (out_reason)
            *out_reason = "tcp-connect";
        close(fd);
        return true;
    }

    if (errno != EINPROGRESS)
    {
        if (errno == ECONNREFUSED)
        {
            if (out_rtt_ms)
                *out_rtt_ms = 1.0;
            if (out_reason)
                *out_reason = "tcp-refused";
            close(fd);
            return true;
        }
        close(fd);
        return false;
    }

    struct pollfd pfd = {0};
    pfd.fd = fd;
    pfd.events = POLLOUT;

    rc = poll(&pfd, 1, (int)timeout_ms);
    if (rc <= 0)
    {
        close(fd);
        return false;
    }

    int so_error = 0;
    socklen_t optlen = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &optlen) != 0)
    {
        close(fd);
        return false;
    }

    close(fd);

    if (so_error == 0)
    {
        if (out_rtt_ms)
            *out_rtt_ms = 1.0;
        if (out_reason)
            *out_reason = "tcp-connect";
        return true;
    }

    if (so_error == ECONNREFUSED)
    {
        if (out_rtt_ms)
            *out_rtt_ms = 1.0;
        if (out_reason)
            *out_reason = "tcp-refused";
        return true;
    }

    return false;
}

static bool probe_udp_send(const np_target_t *target,
                           uint16_t port,
                           double *out_rtt_ms,
                           const char **out_reason)
{
    if (!target)
        return false;

    int fd = socket(target->is_ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    struct sockaddr_storage ss;
    socklen_t slen = 0;
    memset(&ss, 0, sizeof(ss));

    if (target->is_ipv6)
    {
        struct sockaddr_in6 sin6 = target->addr6;
        sin6.sin6_port = htons(port);
        memcpy(&ss, &sin6, sizeof(sin6));
        slen = sizeof(sin6);
    }
    else
    {
        struct sockaddr_in sin = target->addr4;
        sin.sin_port = htons(port);
        memcpy(&ss, &sin, sizeof(sin));
        slen = sizeof(sin);
    }

    const char payload = '\0';
    ssize_t wr = sendto(fd, &payload, sizeof(payload), 0, (struct sockaddr *)&ss, slen);
    close(fd);

    if (wr > 0)
    {
        if (out_rtt_ms)
            *out_rtt_ms = 1.0;
        if (out_reason)
            *out_reason = "udp-probe-sent";
        return true;
    }

    return false;
}

static bool probe_icmpv6_echo(const np_target_t *target,
                              uint32_t timeout_ms,
                              double *out_rtt_ms,
                              const char **out_reason)
{
    if (!target || !target->is_ipv6)
        return false;

    int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0)
        return false;

    struct sockaddr_in6 dst = target->addr6;
    dst.sin6_port = 0;

    struct
    {
        struct icmp6_hdr hdr;
        uint64_t nonce;
    } pkt;

    memset(&pkt, 0, sizeof(pkt));
    pkt.hdr.icmp6_type = ICMP6_ECHO_REQUEST;
    pkt.hdr.icmp6_code = 0;
    pkt.hdr.icmp6_id = htons((uint16_t)getpid());
    pkt.hdr.icmp6_seq = htons((uint16_t)(rand() & 0xffff));
    pkt.nonce = (uint64_t)rand();

    if (sendto(fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
    {
        close(fd);
        return false;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr <= 0)
    {
        close(fd);
        return false;
    }

    uint8_t buf[1500];
    struct sockaddr_in6 src;
    socklen_t slen = sizeof(src);
    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &slen);
    close(fd);

    if (n < (ssize_t)sizeof(struct icmp6_hdr))
        return false;

    struct icmp6_hdr *icmp = (struct icmp6_hdr *)buf;
    if (icmp->icmp6_type != ICMP6_ECHO_REPLY)
        return false;
    if (icmp->icmp6_id != pkt.hdr.icmp6_id || icmp->icmp6_seq != pkt.hdr.icmp6_seq)
        return false;

    if (out_rtt_ms)
        *out_rtt_ms = 1.0;
    if (out_reason)
        *out_reason = "icmpv6-echo";
    return true;
}

static bool parse_numeric_target(np_target_t *target)
{
    if (!target || !target->hostname[0])
        return false;

    struct in_addr addr4;
    if (inet_pton(AF_INET, target->hostname, &addr4) == 1)
    {
        target->is_ipv6 = false;
        target->addr4.sin_family = AF_INET;
        target->addr4.sin_addr = addr4;
        strncpy(target->ip, target->hostname, sizeof(target->ip) - 1);
        target->ip[sizeof(target->ip) - 1] = '\0';
        return true;
    }

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, target->hostname, &addr6) == 1)
    {
        target->is_ipv6 = true;
        target->addr6.sin6_family = AF_INET6;
        target->addr6.sin6_addr = addr6;
        strncpy(target->ip, target->hostname, sizeof(target->ip) - 1);
        target->ip[sizeof(target->ip) - 1] = '\0';
        return true;
    }

    return false;
}

np_status_t np_discovery_resolve_targets(np_config_t *cfg)
{
    if (!cfg)
        return NP_ERR_ARGS;

    if (cfg->dns_mode == NP_DNS_NEVER)
    {
        for (uint32_t i = 0; i < cfg->target_count; i++)
        {
            if (!parse_numeric_target(&cfg->targets[i]))
            {
                np_error(NP_ERR_RUNTIME, "[!] -n requires numeric targets, cannot resolve: %s\n",
                        cfg->targets[i].hostname);
                return NP_ERR_RESOLVE;
            }
        }
        return NP_OK;
    }

    if (cfg->dns_server_count > 0 && cfg->dns_mode == NP_DNS_SYSTEM)
    {
        np_error(NP_ERR_RUNTIME, "[!] --dns-servers ignored with --system-dns\n");
    }

    if (cfg->dns_server_count > 0 && cfg->dns_mode != NP_DNS_SYSTEM)
    {
        np_error(NP_ERR_RUNTIME, "[!] custom DNS servers are accepted but not yet fully implemented; using system resolver\n");
    }

    return np_target_resolve_all(cfg);
}

static void set_host_result(np_target_t *target,
                            bool up,
                            const char *reason,
                            double rtt_ms)
{
    if (!target)
        return;

    target->host_discovered = true;
    target->host_up = up;
    target->host_rtt_ms = rtt_ms;

    if (!reason)
        reason = up ? "up" : "no-response";

    strncpy(target->host_reason, reason, sizeof(target->host_reason) - 1);
    target->host_reason[sizeof(target->host_reason) - 1] = '\0';
}

static bool run_ports_probe(const np_target_t *target,
                            const np_port_spec_t *ports,
                            uint32_t timeout_ms,
                            bool udp,
                            double *out_rtt,
                            const char **out_reason)
{
    np_port_iter_t it;
    np_port_iter_init(&it);

    uint16_t port = 0;
    while (np_port_iter_next(ports, &it, &port))
    {
        bool up = udp
                      ? probe_udp_send(target, port, out_rtt, out_reason)
                      : probe_tcp_connect(target, port, timeout_ms, out_rtt, out_reason);
        if (up)
            return true;
    }

    return false;
}

static np_status_t ensure_raw_probe_supported(const np_config_t *cfg)
{
    if (!cfg)
        return NP_ERR_ARGS;

    bool raw_probe = cfg->probe_icmp_echo || cfg->probe_icmp_timestamp ||
                     cfg->probe_icmp_netmask || cfg->probe_sctp_init ||
                     cfg->probe_ip_proto;

    if (!raw_probe)
        return NP_OK;

    if (geteuid() != 0)
    {
        np_error(NP_ERR_RUNTIME, "[!] selected host discovery probe requires root privileges\n");
        return NP_ERR_PRIVILEGE_REQUIRED;
    }

    return NP_OK;
}

np_status_t np_host_discovery_run(np_config_t *cfg,
                                  volatile sig_atomic_t *interrupted)
{
    if (!cfg)
        return NP_ERR_ARGS;

    cfg->host_discovery_done = true;

    if (cfg->host_discovery_mode == NP_HOST_DISCOVERY_LIST_ONLY)
    {
        for (uint32_t i = 0; i < cfg->target_count; i++)
            set_host_result(&cfg->targets[i], false, "listed", 0.0);
        return NP_OK;
    }

    if (cfg->host_discovery_mode == NP_HOST_DISCOVERY_SKIP)
    {
        for (uint32_t i = 0; i < cfg->target_count; i++)
            set_host_result(&cfg->targets[i], true, "user-set-Pn", 0.0);

        if (cfg->traceroute_enabled)
        {
            for (uint32_t i = 0; i < cfg->target_count; i++)
                np_traceroute_target(cfg, &cfg->targets[i]);
        }

        return NP_OK;
    }

    np_status_t rc = ensure_raw_probe_supported(cfg);
    if (rc != NP_OK)
        return rc;

    bool explicit_probe = has_explicit_discovery_probe(cfg);

    np_port_spec_t default_ports = {0};
    default_ports.ranges[0].start = 80;
    default_ports.ranges[0].end = 80;
    default_ports.ranges[1].start = 443;
    default_ports.ranges[1].end = 443;
    default_ports.count = 2;

    for (uint32_t i = 0; i < cfg->target_count; i++)
    {
        if (interrupted && *interrupted)
            break;

        np_target_t *target = &cfg->targets[i];
        target->trace_hop_count = 0;

        bool up = false;
        double rtt = 0.0;
        const char *reason = NULL;

        bool do_tcp_syn = explicit_probe ? cfg->probe_tcp_syn : true;
        bool do_tcp_ack = explicit_probe ? cfg->probe_tcp_ack : true;
        bool do_udp = explicit_probe ? cfg->probe_udp : false;

        if (do_tcp_syn)
        {
            const np_port_spec_t *ports = cfg->discovery_tcp_syn_ports.count
                                              ? &cfg->discovery_tcp_syn_ports
                                              : &default_ports;
            up = run_ports_probe(target, ports, cfg->timeout_ms, false, &rtt, &reason);
        }

        if (!up && do_tcp_ack)
        {
            const np_port_spec_t *ports = cfg->discovery_tcp_ack_ports.count
                                              ? &cfg->discovery_tcp_ack_ports
                                              : &default_ports;
            up = run_ports_probe(target, ports, cfg->timeout_ms, false, &rtt, &reason);
        }

        if (!up && do_udp)
        {
            const np_port_spec_t *ports = cfg->discovery_udp_ports.count
                                              ? &cfg->discovery_udp_ports
                                              : &default_ports;
            up = run_ports_probe(target, ports, cfg->timeout_ms, true, &rtt, &reason);
        }

        if (!up && target->is_ipv6 && (cfg->probe_icmp_echo || !explicit_probe))
        {
            up = probe_icmpv6_echo(target, cfg->timeout_ms, &rtt, &reason);
        }

        if (!up && (cfg->probe_icmp_echo || cfg->probe_icmp_timestamp || cfg->probe_icmp_netmask))
            reason = "icmp-probe-unavailable";

        if (!up && (cfg->probe_sctp_init || cfg->probe_ip_proto))
            reason = "probe-unavailable";

        set_host_result(target, up, reason, rtt);

        if (cfg->traceroute_enabled && target->host_up)
            np_traceroute_target(cfg, target);
    }

    return NP_OK;
}
