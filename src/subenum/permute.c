#define _POSIX_C_SOURCE 200809L

#include "subenum/permute.h"

#include <stdio.h>
#include <string.h>

typedef struct
{
    const char *domain;
    np_dns_engine_t *engine;
    uint16_t depth;
} permute_ctx_t;

static int ends_with_domain(const char *fqdn, const char *domain)
{
    size_t f = strlen(fqdn);
    size_t d = strlen(domain);
    if (f <= d + 1)
        return 0;
    return strcmp(fqdn + (f - d), domain) == 0 && fqdn[f - d - 1] == '.';
}

static void submit_perm(const char *label, const char *domain,
                        np_dns_engine_t *engine, uint16_t depth)
{
    char fqdn[700];
    snprintf(fqdn, sizeof(fqdn), "%s.%s", label, domain);
    np_dns_engine_submit(engine, fqdn, NP_DNS_REC_A, NP_SUBSRC_PERMUTE, depth);
}

static void permute_cb(const np_subdomain_entry_t *entry, void *userdata)
{
    char label[512];
    char temp[512];
    const char *dot;
    permute_ctx_t *ctx = (permute_ctx_t *)userdata;

    if (!entry || !ctx)
        return;
    if (!ends_with_domain(entry->fqdn, ctx->domain))
        return;

    dot = strchr(entry->fqdn, '.');
    if (!dot)
        return;

    snprintf(label, sizeof(label), "%.*s", (int)(dot - entry->fqdn), entry->fqdn);
    if (label[0] == 0)
        return;

    snprintf(temp, sizeof(temp), "%s-dev", label);
    submit_perm(temp, ctx->domain, ctx->engine, ctx->depth);

    snprintf(temp, sizeof(temp), "dev-%s", label);
    submit_perm(temp, ctx->domain, ctx->engine, ctx->depth);

    snprintf(temp, sizeof(temp), "%s1", label);
    submit_perm(temp, ctx->domain, ctx->engine, ctx->depth);
}

int np_permute_run(np_dns_engine_t *engine,
                   const char *domain,
                   np_result_store_t *store,
                   uint16_t depth)
{
    permute_ctx_t ctx;
    if (!engine || !domain || !store)
        return -1;

    ctx.domain = domain;
    ctx.engine = engine;
    ctx.depth = depth;

    np_result_store_foreach(store, permute_cb, &ctx);
    return 0;
}
