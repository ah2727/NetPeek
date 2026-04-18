#define _POSIX_C_SOURCE 200809L

#include "route/route.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#include "recon/graph.h"
#include "recon/graph_types.h"
#include "recon/output.h"
#include "utils.h"

static void resolve_hostnames(np_route_result_t *result)
{
    for (uint32_t i = 0; i < result->hop_count; i++)
    {
        np_route_hop_t *hop = &result->hops[i];
        if (hop->timeout || hop->ip[0] == '\0' || hop->hostname[0] != '\0')
            continue;

        char host[NI_MAXHOST];
        memset(host, 0, sizeof(host));

        if (hop->is_ipv6)
        {
            struct sockaddr_in6 sa6;
            memset(&sa6, 0, sizeof(sa6));
            sa6.sin6_family = AF_INET6;
            if (inet_pton(AF_INET6, hop->ip, &sa6.sin6_addr) != 1)
                continue;

            if (getnameinfo((struct sockaddr *)&sa6, sizeof(sa6), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0)
                strncpy(hop->hostname, host, sizeof(hop->hostname) - 1);
        }
        else
        {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            if (inet_pton(AF_INET, hop->ip, &sa.sin_addr) != 1)
                continue;

            if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0)
                strncpy(hop->hostname, host, sizeof(hop->hostname) - 1);
        }
    }
}

static np_status_t build_route_graph(np_recon_context_t *ctx, const np_route_result_t *result)
{
    if (!ctx || !result)
        return NP_ERR_ARGS;

    for (uint32_t i = 0; i < result->hop_count; i++)
    {
        const np_route_hop_t *hop = &result->hops[i];
        if (hop->timeout || hop->ip[0] == '\0')
            continue;

        np_host_payload_t host;
        memset(&host, 0, sizeof(host));
        strncpy(host.ip, hop->ip, sizeof(host.ip) - 1);

        if (hop->hostname[0])
            strncpy(host.hostname, hop->hostname, sizeof(host.hostname) - 1);
        else
            strncpy(host.hostname, hop->ip, sizeof(host.hostname) - 1);

        uint64_t host_id = np_graph_add_host_payload(ctx, &host);
        if (host_id == 0)
            return NP_ERR_MEMORY;

        for (uint32_t p = 0; p < hop->open_port_count; p++)
        {
            np_service_payload_t svc;
            memset(&svc, 0, sizeof(svc));
            svc.port = hop->open_ports[p];
            strncpy(svc.proto, "tcp", sizeof(svc.proto) - 1);

            const char *name = np_service_name(svc.port);
            if (name)
                strncpy(svc.service, name, sizeof(svc.service) - 1);

            uint64_t svc_id = np_graph_add_service_payload(ctx, &svc);
            if (svc_id == 0)
                return NP_ERR_MEMORY;

            np_graph_link(ctx, host_id, svc_id, NP_RECON_REL_EXPOSES);
        }
    }

    return NP_OK;
}

np_status_t np_route_write_output(np_route_result_t *result,
                                  const np_route_options_t *opts)
{
    if (!result || !opts)
        return NP_ERR_ARGS;

    resolve_hostnames(result);

    np_config_t *cfg = np_config_create();
    if (!cfg)
        return NP_ERR_MEMORY;

    cfg->recon_cli_mode = true;
    cfg->recon_subcommand = "route";
    cfg->recon_output_format = opts->json_output ? "json" : "text";
    cfg->output_file = opts->output_file;

    np_recon_context_t *ctx = np_recon_create(cfg);
    if (!ctx)
    {
        np_config_destroy(cfg);
        return NP_ERR_MEMORY;
    }

    np_status_t rc = build_route_graph(ctx, result);
    if (rc == NP_OK)
        rc = np_output_stage_run(ctx);

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
    return rc;
}
