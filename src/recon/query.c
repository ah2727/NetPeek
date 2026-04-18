#include "recon/query.h"

#include <stdlib.h>
#include <string.h>

#include "recon/graph_types.h"
#include "recon_internal.h"
#include "utils.h"

static const char *np_service_proto_fallback(np_scan_type_t scan_type)
{
    switch (scan_type)
    {
    case NP_SCAN_UDP:
        return "udp";
    case NP_SCAN_SCTP_INIT:
    case NP_SCAN_SCTP_COOKIE_ECHO:
        return "sctp";
    case NP_SCAN_IP_PROTOCOL:
        return "ip";
    default:
        return "tcp";
    }
}

uint32_t np_query_hosts(np_recon_context_t *ctx, np_host_view_t **out)
{
    if (!ctx || !ctx->graph || !out)
        return 0;

    *out = NULL;
    np_graph_store_t *graph = (np_graph_store_t *)ctx->graph;

    size_t count = 0;
    for (size_t i = 0; i < graph->node_count; i++)
        if (graph->nodes[i].type == NP_NODE_HOST)
            count++;

    if (count == 0)
        return 0;

    np_host_view_t *views = calloc(count, sizeof(*views));
    if (!views)
        return 0;

    size_t w = 0;
    for (size_t i = 0; i < graph->node_count; i++)
    {
        if (graph->nodes[i].type != NP_NODE_HOST || !graph->nodes[i].payload)
            continue;

        views[w].id = graph->nodes[i].id;

        if (graph->nodes[i].payload_size == sizeof(np_target_t))
        {
            const np_target_t *host = (const np_target_t *)graph->nodes[i].payload;
            views[w].ip = host->ip;
            views[w].hostname = host->hostname;
            views[w].discovered = host->host_discovered;
            views[w].up = host->host_up;
            views[w].reason = host->host_reason;
            views[w].rtt_ms = host->host_rtt_ms;
        }
        else if (graph->nodes[i].payload_size == sizeof(np_host_payload_t))
        {
            const np_host_payload_t *host = (const np_host_payload_t *)graph->nodes[i].payload;
            views[w].ip = host->ip;
            views[w].hostname = host->hostname;
            views[w].reason = "unknown";
        }

        w++;
    }

    *out = views;
    return (uint32_t)w;
}

uint32_t np_query_services(np_recon_context_t *ctx,
                           uint64_t host_id,
                           np_service_view_t **out)
{
    if (!ctx || !ctx->graph || !out || host_id == 0)
        return 0;

    *out = NULL;
    np_graph_store_t *graph = (np_graph_store_t *)ctx->graph;

    size_t count = 0;
    for (size_t i = 0; i < graph->edge_count; i++)
    {
        const np_graph_edge_store_t *edge = &graph->edges[i];
        if (edge->src == host_id && strcmp(edge->relation, NP_RECON_REL_EXPOSES) == 0)
            count++;
    }

    if (count == 0)
        return 0;

    np_service_view_t *views = calloc(count, sizeof(*views));
    if (!views)
        return 0;

    size_t w = 0;
    for (size_t i = 0; i < graph->edge_count; i++)
    {
        const np_graph_edge_store_t *edge = &graph->edges[i];
        if (edge->src != host_id || strcmp(edge->relation, NP_RECON_REL_EXPOSES) != 0)
            continue;

        for (size_t n = 0; n < graph->node_count; n++)
        {
            if (graph->nodes[n].id != edge->dst ||
                graph->nodes[n].type != NP_NODE_SERVICE ||
                !graph->nodes[n].payload)
                continue;

            views[w].node_id = graph->nodes[n].id;

            if (graph->nodes[n].payload_size == sizeof(np_port_result_t))
            {
                const np_port_result_t *svc = (const np_port_result_t *)graph->nodes[n].payload;
                const char *fallback = "tcp";
                if (ctx->cfg)
                    fallback = np_service_proto_fallback(ctx->cfg->scan_type);

                views[w].port = svc->port;
                views[w].proto = svc->proto[0] ? svc->proto : fallback;
                views[w].service = svc->service[0] ? svc->service : np_service_name(svc->port);
                views[w].state = np_port_state_str(svc->state);
                views[w].product = svc->product;
                views[w].version = svc->version;
                views[w].tls_detected = svc->tls_detected;
            }
            else if (graph->nodes[n].payload_size == sizeof(np_service_payload_t))
            {
                const np_service_payload_t *svc = (const np_service_payload_t *)graph->nodes[n].payload;
                views[w].port = svc->port;
                views[w].proto = svc->proto[0] ? svc->proto : "tcp";
                views[w].service = svc->service[0] ? svc->service : np_service_name(svc->port);
                views[w].state = "unknown";
                views[w].product = svc->product;
                views[w].version = svc->version;
                views[w].tls_detected = false;
            }
            else
            {
                continue;
            }

            w++;
            break;
        }
    }

    *out = views;
    return (uint32_t)w;
}

uint32_t np_query_evidence(np_recon_context_t *ctx,
                           uint64_t node_id,
                           np_evidence_view_t **out)
{
    if (!ctx || !ctx->evidence || !out || node_id == 0)
        return 0;

    *out = NULL;
    np_evidence_store_t *store = (np_evidence_store_t *)ctx->evidence;

    size_t count = 0;
    for (size_t i = 0; i < store->count; i++)
        if (store->items[i].node_id == node_id)
            count++;

    if (count == 0)
        return 0;

    np_evidence_view_t *views = calloc(count, sizeof(*views));
    if (!views)
        return 0;

    size_t w = 0;
    for (size_t i = 0; i < store->count; i++)
    {
        if (store->items[i].node_id != node_id)
            continue;

        views[w].id = store->items[i].id;
        views[w].source = store->items[i].source_module;
        views[w].description = store->items[i].description;
        views[w].timestamp = store->items[i].timestamp;
        views[w].confidence = store->items[i].confidence;
        w++;
    }

    *out = views;
    return (uint32_t)w;
}

uint32_t np_query_host_os(np_recon_context_t *ctx,
                          uint64_t host_id,
                          np_os_view_t **out)
{
    if (!ctx || !ctx->graph || !out || host_id == 0)
        return 0;

    *out = NULL;
    np_graph_store_t *graph = (np_graph_store_t *)ctx->graph;

    size_t count = 0;
    for (size_t i = 0; i < graph->edge_count; i++)
    {
        const np_graph_edge_store_t *edge = &graph->edges[i];
        if (edge->src == host_id && strcmp(edge->relation, NP_RECON_REL_RUNS) == 0)
            count++;
    }

    if (count == 0)
        return 0;

    np_os_view_t *views = calloc(count, sizeof(*views));
    if (!views)
        return 0;

    size_t w = 0;
    for (size_t i = 0; i < graph->edge_count; i++)
    {
        const np_graph_edge_store_t *edge = &graph->edges[i];
        if (edge->src != host_id || strcmp(edge->relation, NP_RECON_REL_RUNS) != 0)
            continue;

        for (size_t n = 0; n < graph->node_count; n++)
        {
            if (graph->nodes[n].id != edge->dst ||
                graph->nodes[n].type != NP_NODE_OS ||
                !graph->nodes[n].payload ||
                graph->nodes[n].payload_size != sizeof(np_os_result_t))
                continue;

            const np_os_result_t *os = (const np_os_result_t *)graph->nodes[n].payload;
            views[w].name = os->best_os[0] ? os->best_os : "unknown";
            views[w].confidence = os->best_confidence / 100.0;
            w++;
            break;
        }
    }

    *out = views;
    return (uint32_t)w;
}

void np_query_free(void *ptr)
{
    free(ptr);
}
