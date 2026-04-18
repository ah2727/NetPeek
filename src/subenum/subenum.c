#define _POSIX_C_SOURCE 200809L

#include "subenum/subenum.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "subenum/axfr.h"
#include "subenum/brute.h"
#include "subenum/ct_lookup.h"
#include "subenum/dns_resolver.h"
#include "subenum/permute.h"
#include "subenum/result_store.h"
#include "subenum/reverse_dns.h"
#include "subenum/wildcard.h"
#include "recon/graph.h"
#include "recon/graph_types.h"
#include "recon/evidence.h"
#include "recon/output.h"

static const char *source_bits(uint32_t sources, char *buf, size_t cap)
{
    size_t used = 0;
    buf[0] = 0;

    if (sources & NP_SUBSRC_BRUTE)
        used += (size_t)snprintf(buf + used, cap - used, "%sbrute", used ? "," : "");
    if (sources & NP_SUBSRC_AXFR)
        used += (size_t)snprintf(buf + used, cap - used, "%saxfr", used ? "," : "");
    if (sources & NP_SUBSRC_CT)
        used += (size_t)snprintf(buf + used, cap - used, "%sct", used ? "," : "");
    if (sources & NP_SUBSRC_REVERSE)
        used += (size_t)snprintf(buf + used, cap - used, "%sreverse", used ? "," : "");
    if (sources & NP_SUBSRC_PERMUTE)
        used += (size_t)snprintf(buf + used, cap - used, "%spermute", used ? "," : "");
    if (sources & NP_SUBSRC_RECURSIVE)
        used += (size_t)snprintf(buf + used, cap - used, "%srecursive", used ? "," : "");

    return buf;
}

typedef struct
{
    np_recon_context_t *ctx;
    size_t total;
    const np_wildcard_info_t *wild;
    bool filter_alive;
} ingest_ctx_t;

static void ingest_entry(const np_subdomain_entry_t *entry, void *userdata)
{
    ingest_ctx_t *ctx = (ingest_ctx_t *)userdata;

    if (ctx->filter_alive && entry->addr_count == 0)
        return;
    if (ctx->wild && np_wildcard_is_false_positive(ctx->wild, entry))
        return;

    ctx->total++;

    np_host_payload_t host;
    memset(&host, 0, sizeof(host));
    strncpy(host.hostname, entry->fqdn, sizeof(host.hostname) - 1);
    if (entry->addr_count > 0)
        strncpy(host.ip, entry->addrs[0].addr_str, sizeof(host.ip) - 1);

    uint64_t host_id = np_graph_add_host_payload(ctx->ctx, &host);
    if (host_id == 0)
        return;

    char src[128];
    np_evidence_t ev = {
        .source_module = "subenum",
        .description = source_bits(entry->sources, src, sizeof(src)),
        .timestamp = time(NULL),
        .confidence = entry->addr_count > 0 ? 0.9 : 0.6,
        .raw_data = NULL,
    };
    (void)np_evidence_add(ctx->ctx, host_id, &ev);
}

void np_subenum_config_init(np_subenum_config_t *cfg)
{
    if (!cfg)
        return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->thread_count = 32;
    cfg->timeout_ms = 3000;
    cfg->techniques = NP_SUBSRC_BRUTE;
    cfg->ct_providers = NP_CTPROV_CRTSH | NP_CTPROV_CERTSPOTTER;
    cfg->max_depth = 3;
    cfg->wildcard_detect = true;
}

void np_subenum_config_free(np_subenum_config_t *cfg)
{
    size_t i;
    if (!cfg)
        return;
    for (i = 0; i < cfg->domain_count; i++)
        free(cfg->domains[i]);
    free(cfg->domains);
    free(cfg->wordlist_path);
    free(cfg->output_file);
    free(cfg->http_proxy);
    free(cfg->ct_certspotter_token);
    memset(cfg, 0, sizeof(*cfg));
}

static const char *subenum_format(const np_subenum_config_t *cfg)
{
    if (cfg->output_json)
        return "json";
    if (cfg->output_csv)
        return "csv";
    return "text";
}

static int run_one_domain(const np_subenum_config_t *cfg, const char *domain)
{
    np_result_store_t *store;
    np_dns_engine_t *engine;
    np_wildcard_info_t wild;
    ingest_ctx_t ingest;

    store = np_result_store_create(2048);
    if (!store)
        return 1;
    engine = np_dns_engine_create(cfg, store);
    if (!engine)
    {
        np_result_store_destroy(store);
        return 1;
    }

    memset(&wild, 0, sizeof(wild));
    if (cfg->wildcard_detect)
        np_wildcard_detect(engine, domain, &wild);

    if (cfg->techniques & NP_SUBSRC_CT)
        np_ct_lookup_multi(domain, cfg, engine, 0);

    if (cfg->techniques & NP_SUBSRC_AXFR)
        np_axfr_attempt(domain, cfg, store, 0);

    if (cfg->techniques & NP_SUBSRC_BRUTE)
        np_brute_run(engine, domain, cfg, 0);

    np_dns_engine_run(engine);

    if (cfg->techniques & NP_SUBSRC_PERMUTE)
    {
        np_permute_run(engine, domain, store, 1);
        np_dns_engine_run(engine);
    }

    if (cfg->techniques & NP_SUBSRC_REVERSE)
        np_reverse_dns_sweep(domain, store, 1);

    np_config_t *ocfg = np_config_create();
    if (!ocfg)
    {
        np_dns_engine_destroy(engine);
        np_result_store_destroy(store);
        return 1;
    }

    ocfg->recon_cli_mode = true;
    ocfg->recon_subcommand = "subenum";
    ocfg->recon_output_format = subenum_format(cfg);
    ocfg->output_file = cfg->output_file;
    ocfg->show_evidence = true;

    np_recon_context_t *rctx = np_recon_create(ocfg);
    if (!rctx)
    {
        np_config_destroy(ocfg);
        np_dns_engine_destroy(engine);
        np_result_store_destroy(store);
        return 1;
    }

    memset(&ingest, 0, sizeof(ingest));
    ingest.ctx = rctx;
    ingest.wild = &wild;
    ingest.filter_alive = cfg->filter_alive;

    np_result_store_foreach(store, ingest_entry, &ingest);
    np_status_t out_rc = np_output_stage_run(rctx);

    np_recon_destroy(rctx);
    np_config_destroy(ocfg);
    np_dns_engine_destroy(engine);
    np_result_store_destroy(store);
    return out_rc == NP_OK ? 0 : 1;
}

int np_subenum_execute(const np_subenum_config_t *cfg)
{
    size_t i;
    if (!cfg || cfg->domain_count == 0)
        return 1;

    for (i = 0; i < cfg->domain_count; i++)
    {
        if (run_one_domain(cfg, cfg->domains[i]) != 0)
            return 1;
    }

    return 0;
}
