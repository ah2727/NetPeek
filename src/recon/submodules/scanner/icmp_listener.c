#include "scanner_internal.h"
#include "core/error.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>

#if defined(ICMP_UNREACH_ADMIN_PROHIB)
#define NP_ICMP_UNREACH_ADMIN ICMP_UNREACH_ADMIN_PROHIB
#elif defined(ICMP_UNREACH_FILTER_PROHIB)
#define NP_ICMP_UNREACH_ADMIN ICMP_UNREACH_FILTER_PROHIB
#elif defined(ICMP_UNREACH_ADMIN_PROHIBITED)
#define NP_ICMP_UNREACH_ADMIN ICMP_UNREACH_ADMIN_PROHIBITED
#endif

static int icmp_sock = -1;

np_status_t np_icmp_init(void)
{
    icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0)
    {
        np_perror("socket(ICMP)");
        return NP_ERR_SYSTEM;
    }
    return NP_OK;
}

void np_icmp_close(void)
{
    if (icmp_sock >= 0)
    {
        close(icmp_sock);
        icmp_sock = -1;
    }
}

bool np_icmp_unreachable_seen(void)
{
    uint8_t buf[1500];

    ssize_t n = recv(
        icmp_sock,
        buf,
        sizeof(buf),
        MSG_DONTWAIT);

    if (n <= 0)
        return false;

    struct ip *ip = (struct ip *)buf;
    size_t ip_hlen = ip->ip_hl << 2;

    if (n < (ssize_t)(ip_hlen + sizeof(struct icmp)))
        return false;

    struct icmp *icmp =
        (struct icmp *)(buf + ip_hlen);

    if (icmp->icmp_type != ICMP_UNREACH)
        return false;

    switch (icmp->icmp_code)
    {
    case ICMP_UNREACH_NET:
    case ICMP_UNREACH_HOST:
    case ICMP_UNREACH_PROTOCOL:
    case ICMP_UNREACH_PORT:
    case NP_ICMP_UNREACH_ADMIN:
        return true;
    default:
        return false;
    }
}
