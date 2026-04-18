#include "subenum/axfr.h"
#include "subenum/dns_packet.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int fqdn_has_domain_suffix(const char *fqdn, const char *domain)
{
    if (!fqdn || !domain)
        return 0;

    size_t f_len = strlen(fqdn);
    size_t d_len = strlen(domain);
    if (f_len < d_len || d_len == 0)
        return 0;

    const char *tail = fqdn + (f_len - d_len);
    if (strcasecmp(tail, domain) != 0)
        return 0;

    return (f_len == d_len) || (tail[-1] == '.');
}

static int connect_tcp_53(const char *host, int timeout_ms)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, "53", &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *it = res; it; it = it->ai_next)
    {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0)
            (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, it->ai_addr, it->ai_addrlen);
        if (rc == 0)
            break;

        if (errno == EINPROGRESS)
        {
            struct pollfd pfd = {.fd = fd, .events = POLLOUT};
            int pr = poll(&pfd, 1, timeout_ms);
            if (pr > 0)
            {
                int soerr = 0;
                socklen_t slen = sizeof(soerr);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr == 0)
                    break;
            }
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int dns_udp_query(const char *resolver,
                         const char *domain,
                         np_dns_record_type_t qtype,
                         int timeout_ms,
                         np_dns_answer_t *answers,
                         size_t cap)
{
    if (!resolver || !domain)
        return -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(resolver, "53", &hints, &res) != 0)
        return -1;

    int fd = -1;
    int count = -1;
    for (struct addrinfo *it = res; it; it = it->ai_next)
    {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;

        uint8_t query[1024];
        int qlen = np_dns_build_query(query,
                                      sizeof(query),
                                      (uint16_t)rand(),
                                      domain,
                                      qtype);
        if (qlen <= 0)
        {
            close(fd);
            fd = -1;
            continue;
        }

        if (connect(fd, it->ai_addr, it->ai_addrlen) != 0)
        {
            close(fd);
            fd = -1;
            continue;
        }

        if (send(fd, query, (size_t)qlen, 0) != qlen)
        {
            close(fd);
            fd = -1;
            continue;
        }

        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0)
        {
            close(fd);
            fd = -1;
            continue;
        }

        uint8_t resp[65535];
        ssize_t rlen = recv(fd, resp, sizeof(resp), 0);
        if (rlen > 0)
        {
            count = np_dns_parse_response(resp, (size_t)rlen, answers, cap, NULL);
            close(fd);
            fd = -1;
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return count;
}

static size_t collect_authoritative_ns(const char *domain,
                                       const np_subenum_config_t *cfg,
                                       char out[][512],
                                       size_t out_cap)
{
    if (!domain || !out || out_cap == 0)
        return 0;

    const char *fallback[] = {"1.1.1.1", "8.8.8.8"};
    np_dns_answer_t answers[64];
    size_t count = 0;

    size_t resolver_count = (cfg && cfg->resolver_count > 0) ? cfg->resolver_count : 2;
    for (size_t i = 0; i < resolver_count; i++)
    {
        const char *resolver = (cfg && cfg->resolver_count > 0) ? cfg->resolvers[i] : fallback[i];
        int n = dns_udp_query(resolver, domain, NP_DNS_REC_NS, (cfg && cfg->timeout_ms > 0) ? cfg->timeout_ms : 3000, answers, 64);
        if (n <= 0)
            continue;

        for (int j = 0; j < n && count < out_cap; j++)
        {
            if (answers[j].type != NP_DNS_REC_NS || answers[j].value[0] == '\0')
                continue;

            bool dup = false;
            for (size_t k = 0; k < count; k++)
            {
                if (strcasecmp(out[k], answers[j].value) == 0)
                {
                    dup = true;
                    break;
                }
            }

            if (!dup)
            {
                snprintf(out[count], 512, "%s", answers[j].value);
                count++;
            }
        }

        if (count > 0)
            break;
    }

    return count;
}

static int send_all(int fd, const uint8_t *buf, size_t len, int timeout_ms)
{
    size_t sent = 0;
    while (sent < len)
    {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0)
            return -1;

        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0)
            return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
    size_t got = 0;
    while (got < len)
    {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0)
            return -1;

        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    return 0;
}

static int recv_dns_tcp_message(int fd, uint8_t *buf, size_t cap, int timeout_ms)
{
    uint8_t lenbuf[2];
    if (recv_all(fd, lenbuf, sizeof(lenbuf), timeout_ms) != 0)
        return -1;

    uint16_t msg_len = (uint16_t)(((uint16_t)lenbuf[0] << 8) | lenbuf[1]);
    if (msg_len == 0 || msg_len > cap)
        return -1;

    if (recv_all(fd, buf, msg_len, timeout_ms) != 0)
        return -1;

    return (int)msg_len;
}

static void axfr_ingest_answer(np_result_store_t *store,
                               const np_dns_answer_t *ans,
                               const char *domain,
                               uint16_t depth)
{
    if (!store || !ans || !domain)
        return;

    if (!fqdn_has_domain_suffix(ans->name, domain))
        return;

    np_resolved_addr_t addr;
    memset(&addr, 0, sizeof(addr));
    size_t addr_count = 0;

    if (ans->type == NP_DNS_REC_A)
    {
        addr.family = AF_INET;
        if (inet_pton(AF_INET, ans->value, &addr.addr.v4) == 1)
        {
            snprintf(addr.addr_str, sizeof(addr.addr_str), "%s", ans->value);
            addr_count = 1;
        }
    }
    else if (ans->type == NP_DNS_REC_AAAA)
    {
        addr.family = AF_INET6;
        if (inet_pton(AF_INET6, ans->value, &addr.addr.v6) == 1)
        {
            snprintf(addr.addr_str, sizeof(addr.addr_str), "%s", ans->value);
            addr_count = 1;
        }
    }

    (void)np_result_store_insert(store,
                                 ans->name,
                                 addr_count ? &addr : NULL,
                                 addr_count,
                                 NP_SUBSRC_AXFR,
                                 depth,
                                 0.0,
                                 NULL);
}

static int attempt_axfr_server(const char *server,
                               const char *domain,
                               const np_subenum_config_t *cfg,
                               np_result_store_t *store,
                               uint16_t depth)
{
    if (!server || !server[0] || !domain || !store)
        return 0;

    int timeout_ms = (cfg && cfg->timeout_ms > 0) ? cfg->timeout_ms : 3000;
    int fd = connect_tcp_53(server, timeout_ms);
    if (fd < 0)
        return 0;

    uint8_t query[1024];
    int qlen = np_dns_build_query(query, sizeof(query), (uint16_t)rand(), domain, NP_DNS_REC_AXFR);
    if (qlen <= 0)
    {
        close(fd);
        return 0;
    }

    uint8_t frame[2 + 1024];
    frame[0] = (uint8_t)(((uint16_t)qlen) >> 8);
    frame[1] = (uint8_t)(((uint16_t)qlen) & 0xFF);
    memcpy(frame + 2, query, (size_t)qlen);

    if (send_all(fd, frame, (size_t)qlen + 2, timeout_ms) != 0)
    {
        close(fd);
        return 0;
    }

    int soa_seen = 0;
    int added = 0;
    for (int i = 0; i < 256; i++)
    {
        uint8_t resp[65535];
        int rlen = recv_dns_tcp_message(fd, resp, sizeof(resp), timeout_ms);
        if (rlen <= 0)
            break;

        np_dns_answer_t answers[256];
        int count = np_dns_parse_response(resp, (size_t)rlen, answers, 256, NULL);
        if (count <= 0)
            continue;

        for (int a = 0; a < count; a++)
        {
            if (answers[a].type == NP_DNS_REC_SOA)
                soa_seen++;

            size_t before = np_result_store_count(store);
            axfr_ingest_answer(store, &answers[a], domain, depth);
            if (np_result_store_count(store) > before)
                added++;
        }

        if (soa_seen >= 2)
            break;
    }

    close(fd);
    return added;
}

int np_axfr_attempt(const char *domain,
                    const np_subenum_config_t *cfg,
                    np_result_store_t *store,
                    uint16_t depth)
{
    if (!domain || !store)
        return -1;

    int total_added = 0;
    char ns_hosts[32][512];
    size_t ns_count = collect_authoritative_ns(domain, cfg, ns_hosts, 32);

    if (ns_count == 0)
    {
        total_added += attempt_axfr_server(domain, domain, cfg, store, depth);
        return total_added;
    }

    for (size_t i = 0; i < ns_count; i++)
        total_added += attempt_axfr_server(ns_hosts[i], domain, cfg, store, depth);

    return total_added;
}
