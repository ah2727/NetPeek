#ifndef NP_DNS_ENUM_H
#define NP_DNS_ENUM_H

#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    bool subdomains;
    const char *wordlist;
    bool json;
    int threads;
    const char *types;
    bool zone_transfer;
    const char *reverse_cidr;
    const char *dns_servers;
} np_dns_enum_opts_t;

int np_dns_enum_run(const char *domain, const np_dns_enum_opts_t *opts);

#endif
