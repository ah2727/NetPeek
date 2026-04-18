/*****************************************************************************
 * npe_lib_packet.c
 *
 * Portable packet crafting (Linux + macOS/BSD)
 *****************************************************************************/

#include "npe_lib_packet.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifdef __APPLE__
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#else
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#endif

#include <pcap.h>

/* =======================
 * Internal packet object
 * ======================= */

struct npe_packet {

#ifdef __APPLE__
    struct ip ip;
    struct tcphdr tcp;
    struct udphdr udp;
    struct icmp icmp;
#else
    struct iphdr ip;
    struct tcphdr tcp;
    struct udphdr udp;
    struct icmphdr icmp;
#endif

    uint8_t protocol;

    uint8_t *payload;
    size_t payload_len;
};

/* capture object */
struct npe_packet_capture {
    pcap_t *handle;
};

/* =======================
 * checksum
 * ======================= */

static uint16_t npe_checksum(uint16_t *buf, int len)
{
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len)
        sum += *(uint8_t*)buf;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

/* =======================
 * lifecycle
 * ======================= */

npe_error_t npe_packet_create(npe_packet_t **pkt)
{
    *pkt = calloc(1, sizeof(npe_packet_t));
    return *pkt ? 0 : -1;
}

void npe_packet_destroy(npe_packet_t *pkt)
{
    if (!pkt) return;
    free(pkt->payload);
    free(pkt);
}

/* =======================
 * IPv4
 * ======================= */

npe_error_t npe_packet_set_ipv4(
    npe_packet_t *pkt,
    const char *src_ip,
    const char *dst_ip,
    uint8_t ttl)
{
#ifdef __APPLE__
    memset(&pkt->ip, 0, sizeof(struct ip));
    pkt->ip.ip_v   = 4;
    pkt->ip.ip_hl  = 5;
    pkt->ip.ip_ttl = ttl;
    pkt->ip.ip_p   = pkt->protocol;
    inet_pton(AF_INET, src_ip, &pkt->ip.ip_src);
    inet_pton(AF_INET, dst_ip, &pkt->ip.ip_dst);
#else
    memset(&pkt->ip, 0, sizeof(struct iphdr));
    pkt->ip.version = 4;
    pkt->ip.ihl = 5;
    pkt->ip.ttl = ttl;
    pkt->ip.protocol = pkt->protocol;
    inet_pton(AF_INET, src_ip, &pkt->ip.saddr);
    inet_pton(AF_INET, dst_ip, &pkt->ip.daddr);
#endif
    return 0;
}

/* =======================
 * TCP
 * ======================= */

npe_error_t npe_packet_set_tcp(
    npe_packet_t *pkt,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t flags,
    uint32_t seq,
    uint32_t ack)
{
    memset(&pkt->tcp, 0, sizeof(pkt->tcp));
    pkt->protocol = IPPROTO_TCP;

#ifdef __APPLE__
    pkt->tcp.th_sport = htons(src_port);
    pkt->tcp.th_dport = htons(dst_port);
    pkt->tcp.th_seq   = htonl(seq);
    pkt->tcp.th_ack   = htonl(ack);
    pkt->tcp.th_off   = 5;
    pkt->tcp.th_flags = 0;

    if (flags & NPE_TCP_FIN) pkt->tcp.th_flags |= TH_FIN;
    if (flags & NPE_TCP_SYN) pkt->tcp.th_flags |= TH_SYN;
    if (flags & NPE_TCP_RST) pkt->tcp.th_flags |= TH_RST;
    if (flags & NPE_TCP_PSH) pkt->tcp.th_flags |= TH_PUSH;
    if (flags & NPE_TCP_ACK) pkt->tcp.th_flags |= TH_ACK;
    if (flags & NPE_TCP_URG) pkt->tcp.th_flags |= TH_URG;
#else
    pkt->tcp.source = htons(src_port);
    pkt->tcp.dest   = htons(dst_port);
    pkt->tcp.seq    = htonl(seq);
    pkt->tcp.ack_seq= htonl(ack);
    pkt->tcp.doff   = 5;

    pkt->tcp.fin = flags & NPE_TCP_FIN;
    pkt->tcp.syn = flags & NPE_TCP_SYN;
    pkt->tcp.rst = flags & NPE_TCP_RST;
    pkt->tcp.psh = flags & NPE_TCP_PSH;
    pkt->tcp.ack = flags & NPE_TCP_ACK;
    pkt->tcp.urg = flags & NPE_TCP_URG;
#endif
    return 0;
}

/* =======================
 * UDP
 * ======================= */

npe_error_t npe_packet_set_udp(
    npe_packet_t *pkt,
    uint16_t src_port,
    uint16_t dst_port)
{
    memset(&pkt->udp, 0, sizeof(pkt->udp));
    pkt->protocol = IPPROTO_UDP;

#ifdef __APPLE__
    pkt->udp.uh_sport = htons(src_port);
    pkt->udp.uh_dport = htons(dst_port);
#else
    pkt->udp.source = htons(src_port);
    pkt->udp.dest   = htons(dst_port);
#endif
    return 0;
}

/* =======================
 * ICMP echo
 * ======================= */

npe_error_t npe_packet_set_icmp_echo(
    npe_packet_t *pkt,
    uint16_t id,
    uint16_t seq)
{
    memset(&pkt->icmp, 0, sizeof(pkt->icmp));
    pkt->protocol = IPPROTO_ICMP;

#ifdef __APPLE__
    pkt->icmp.icmp_type = ICMP_ECHO;
    pkt->icmp.icmp_id   = htons(id);
    pkt->icmp.icmp_seq  = htons(seq);
#else
    pkt->icmp.type = ICMP_ECHO;
    pkt->icmp.un.echo.id = htons(id);
    pkt->icmp.un.echo.sequence = htons(seq);
#endif
    return 0;
}

/* =======================
 * payload
 * ======================= */

npe_error_t npe_packet_set_payload(
    npe_packet_t *pkt,
    const void *data,
    size_t length)
{
    pkt->payload = malloc(length);
    if (!pkt->payload) return -1;

    memcpy(pkt->payload, data, length);
    pkt->payload_len = length;
    return 0;
}

/* =======================
 * build
 * ======================= */

npe_error_t npe_packet_build(
    npe_packet_t *pkt,
    uint8_t **buffer,
    size_t *length)
{
    size_t hdr =
#ifdef __APPLE__
        sizeof(struct ip);
#else
        sizeof(struct iphdr);
#endif

    if (pkt->protocol == IPPROTO_TCP) hdr += sizeof(struct tcphdr);
    if (pkt->protocol == IPPROTO_UDP) hdr += sizeof(struct udphdr);
    if (pkt->protocol == IPPROTO_ICMP)
#ifdef __APPLE__
        hdr += sizeof(struct icmp);
#else
        hdr += sizeof(struct icmphdr);
#endif

    *length = hdr + pkt->payload_len;
    *buffer = malloc(*length);
    if (!*buffer) return -1;

    uint8_t *p = *buffer;

#ifdef __APPLE__
    memcpy(p, &pkt->ip, sizeof(struct ip));
    p += sizeof(struct ip);
#else
    memcpy(p, &pkt->ip, sizeof(struct iphdr));
    p += sizeof(struct iphdr);
#endif

    if (pkt->protocol == IPPROTO_TCP) { memcpy(p, &pkt->tcp, sizeof(pkt->tcp)); }
    if (pkt->protocol == IPPROTO_UDP) { memcpy(p, &pkt->udp, sizeof(pkt->udp)); }
    if (pkt->protocol == IPPROTO_ICMP){ memcpy(p, &pkt->icmp,sizeof(pkt->icmp)); }

    p += (pkt->protocol == IPPROTO_TCP) ? sizeof(pkt->tcp) :
         (pkt->protocol == IPPROTO_UDP) ? sizeof(pkt->udp) :
         (pkt->protocol == IPPROTO_ICMP)? sizeof(pkt->icmp) : 0;

    memcpy(p, pkt->payload, pkt->payload_len);

    return 0;
}

/* =======================
 * send
 * ======================= */

npe_error_t npe_packet_send(
    npe_context_t *ctx,
    const uint8_t *packet,
    size_t length)
{
    (void)ctx;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) return -1;

#ifdef __APPLE__
    struct ip *ip = (struct ip*)packet;
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr = ip->ip_dst };
#else
    struct iphdr *ip = (struct iphdr*)packet;
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = ip->daddr };
#endif

    sendto(sock, packet, length, 0, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    return 0;
}