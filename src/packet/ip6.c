#include "packet/ip6.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

static uint16_t checksum16(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;

    while (len > 1)
    {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }

    if (len == 1)
        sum += (uint16_t)(p[0] << 8);

    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);

    return (uint16_t)(~sum);
}

static uint16_t l4_checksum6(const struct in6_addr *src,
                             const struct in6_addr *dst,
                             uint8_t next_header,
                             const void *seg,
                             size_t seg_len)
{
    struct
    {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zeros[3];
        uint8_t nh;
    } ph;

    memset(&ph, 0, sizeof(ph));
    ph.src = *src;
    ph.dst = *dst;
    ph.len = htonl((uint32_t)seg_len);
    ph.nh = next_header;

    uint8_t buf[2048];
    if (sizeof(ph) + seg_len > sizeof(buf))
        return 0;

    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), seg, seg_len);
    return checksum16(buf, sizeof(ph) + seg_len);
}

uint16_t np_tcp6_checksum(const struct in6_addr *src,
                         const struct in6_addr *dst,
                         const void *tcp_seg,
                         size_t tcp_len)
{
    return l4_checksum6(src, dst, IPPROTO_TCP, tcp_seg, tcp_len);
}

uint16_t np_udp6_checksum(const struct in6_addr *src,
                         const struct in6_addr *dst,
                         const void *udp_seg,
                         size_t udp_len)
{
    return l4_checksum6(src, dst, IPPROTO_UDP, udp_seg, udp_len);
}

bool np_build_ipv6_tcp_packet(uint8_t *buf,
                              size_t buf_len,
                              const struct in6_addr *src,
                              const struct in6_addr *dst,
                              uint16_t src_port,
                              uint16_t dst_port,
                              uint8_t flags,
                              uint32_t seq,
                              uint16_t win,
                              uint8_t hop_limit,
                              uint32_t flow_label,
                              size_t *out_len)
{
    size_t total = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
    if (!buf || !src || !dst || buf_len < total)
        return false;

    memset(buf, 0, total);

    struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct ip6_hdr));

    uint32_t vtf = (6u << 28) | (flow_label & 0x000fffffu);
    ip6->ip6_flow = htonl(vtf);
    ip6->ip6_plen = htons((uint16_t)sizeof(struct tcphdr));
    ip6->ip6_nxt = IPPROTO_TCP;
    ip6->ip6_hlim = hop_limit;
    ip6->ip6_src = *src;
    ip6->ip6_dst = *dst;

    tcp->th_sport = htons(src_port);
    tcp->th_dport = htons(dst_port);
    tcp->th_seq = htonl(seq);
    tcp->th_off = 5;
    tcp->th_flags = flags;
    tcp->th_win = htons(win);
    tcp->th_sum = 0;
    tcp->th_sum = np_tcp6_checksum(src, dst, tcp, sizeof(struct tcphdr));

    if (out_len)
        *out_len = total;

    return true;
}
