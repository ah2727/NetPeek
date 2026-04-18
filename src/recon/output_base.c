#include "recon/output_base.h"

#include <stdlib.h>
#include <string.h>

#include "recon/query.h"

void np_output_doc_init(np_output_doc_t *doc)
{
    if (!doc)
        return;

    memset(doc, 0, sizeof(*doc));
    doc->command = NP_OUTPUT_CMD_RECON;
}

void np_output_doc_free(np_output_doc_t *doc)
{
    if (!doc)
        return;

    for (uint32_t i = 0; i < doc->host_count; i++)
        free(doc->hosts[i].services);

    free(doc->hosts);
    np_output_doc_init(doc);
}

np_status_t np_output_doc_from_recon(np_recon_context_t *ctx, np_output_doc_t *doc)
{
    if (!ctx || !doc)
        return NP_ERR_ARGS;

    np_output_doc_free(doc);

    np_host_view_t *hosts = NULL;
    uint32_t host_count = np_query_hosts(ctx, &hosts);

    doc->run_id = ctx->run_id;
    doc->timestamp = (uint64_t)ctx->start_ts;
    doc->command = NP_OUTPUT_CMD_RECON;

    if (host_count == 0)
        return NP_OK;

    doc->hosts = calloc(host_count, sizeof(*doc->hosts));
    if (!doc->hosts)
    {
        np_query_free(hosts);
        return NP_ERR_MEMORY;
    }

    doc->host_count = host_count;

    for (uint32_t i = 0; i < host_count; i++)
    {
        np_output_doc_host_t *dst = &doc->hosts[i];
        dst->ip = hosts[i].ip;
        dst->hostname = hosts[i].hostname;
        dst->discovered = hosts[i].discovered;
        dst->up = hosts[i].up;
        dst->reason = hosts[i].reason;
        dst->rtt_ms = hosts[i].rtt_ms;

        np_service_view_t *services = NULL;
        uint32_t svc_count = np_query_services(ctx, hosts[i].id, &services);
        if (svc_count == 0)
            continue;

        dst->services = calloc(svc_count, sizeof(*dst->services));
        if (!dst->services)
        {
            np_query_free(services);
            np_query_free(hosts);
            np_output_doc_free(doc);
            return NP_ERR_MEMORY;
        }

        dst->service_count = svc_count;
        for (uint32_t j = 0; j < svc_count; j++)
        {
            dst->services[j].port = services[j].port;
            dst->services[j].proto = services[j].proto;
            dst->services[j].service = services[j].service;
            dst->services[j].state = services[j].state;
            dst->services[j].product = services[j].product;
            dst->services[j].version = services[j].version;
            dst->services[j].tls_detected = services[j].tls_detected;
        }

        np_query_free(services);
    }

    np_query_free(hosts);
    return NP_OK;
}
