#include "syn_scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include "netpeek.h"

static uint16_t checksum(uint16_t *buf, int nwords) {
    uint32_t sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}


void np_syn_send(np_config_t *cfg,
                 const char *dst_ip,
                 uint16_t dst_port,
                 uint16_t src_port)
{
    (void)cfg;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
        return;

    char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));

    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_len = htons(sizeof(packet));
    iph->ip_dst.s_addr = inet_addr(dst_ip);

    tcph->th_sport = htons(src_port);
    tcph->th_dport = htons(dst_port);
    tcph->th_seq = htonl(arc4random());
    tcph->th_off = 5;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(65535);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(dst_port),
        .sin_addr.s_addr = iph->ip_dst.s_addr
    };

    sendto(sock, packet, sizeof(packet), 0,
           (struct sockaddr *)&addr, sizeof(addr));

    close(sock);
}