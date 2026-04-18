#define _POSIX_C_SOURCE 200809L

#include "subenum/reverse_dns.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>

typedef struct
{
    const char *domain;
    np_result_store_t *store;
    uint16_t depth;
} reverse_ctx_t;

static int ends_with_domain(const char *fqdn, const char *domain)
{
    size_t f = strlen(fqdn);
    size_t d = strlen(domain);
    if (f < d)
        return 0;
    if (strcmp(fqdn + (f - d), domain) != 0)
        return 0;
    return 1;
}

static void reverse_cb(const np_subdomain_entry_t *entry, void *userdata)
{
    reverse_ctx_t *ctx = (reverse_ctx_t *)userdata;
    size_t i;

    if (!entry || !ctx)
        return;

    for (i = 0; i < entry->addr_count; i++)
    {
        char host[NI_MAXHOST] = {0};
        if (entry->addrs[i].family == AF_INET)
        {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr = entry->addrs[i].addr.v4;
            if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0)
            {
                if (ends_with_domain(host, ctx->domain))
                    np_result_store_insert(ctx->store, host, NULL, 0, NP_SUBSRC_REVERSE, ctx->depth, 0.0, NULL);
            }
        }
        else if (entry->addrs[i].family == AF_INET6)
        {
            struct sockaddr_in6 sa6;
            memset(&sa6, 0, sizeof(sa6));
            sa6.sin6_family = AF_INET6;
            sa6.sin6_addr = entry->addrs[i].addr.v6;
            if (getnameinfo((struct sockaddr *)&sa6, sizeof(sa6), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0)
            {
                if (ends_with_domain(host, ctx->domain))
                    np_result_store_insert(ctx->store, host, NULL, 0, NP_SUBSRC_REVERSE, ctx->depth, 0.0, NULL);
            }
        }
    }
}

int np_reverse_dns_sweep(const char *domain,
                         np_result_store_t *store,
                         uint16_t depth)
{
    reverse_ctx_t ctx;
    if (!domain || !store)
        return -1;

    ctx.domain = domain;
    ctx.store = store;
    ctx.depth = depth;
    np_result_store_foreach(store, reverse_cb, &ctx);
    return 0;
}
