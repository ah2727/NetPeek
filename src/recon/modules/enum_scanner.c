#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ports.h"
#include "recon/evidence.h"
#include "recon/graph.h"
#include "recon/graph_types.h"
#include "recon/modules/enum_scanner.h"
#include "runtime/stats.h"
#include "recon/submodules/scanner/scanner.h"
#include "target.h"

static const char *np_enum_proto_name(np_scan_type_t scan_type)
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

static np_status_t scanner_enum_collect_from_targets(np_recon_context_t *ctx,
                                                     np_target_t *targets,
                                                     uint32_t target_count,
                                                     np_scan_type_t scan_type,
                                                     const char *source_module)
{
    const char *scan_proto = np_enum_proto_name(scan_type);

    for (uint32_t t = 0; t < target_count; t++)
    {
        np_target_t *target = &targets[t];
        uint64_t host_id = np_graph_get_or_add_host(ctx, target);
        if (!host_id)
            return NP_ERR_MEMORY;

        for (uint32_t p = 0; p < target->port_count; p++)
        {
            np_port_result_t *r = &target->results[p];
            if (r->state != NP_PORT_OPEN && r->state != NP_PORT_OPEN_FILTERED)
                continue;

            if (!r->proto[0])
            {
                strncpy(r->proto, scan_proto, sizeof(r->proto) - 1);
                r->proto[sizeof(r->proto) - 1] = '\0';
            }

            uint64_t svc_id = np_graph_add_service(ctx, r);
            if (!svc_id)
                return NP_ERR_MEMORY;

            np_graph_link(ctx, host_id, svc_id, NP_RECON_REL_EXPOSES);
            ctx->services_seen++;

            char evidence_desc[112];
            snprintf(evidence_desc,
                     sizeof(evidence_desc),
                     "%s/%u state=%d reason=%s",
                     r->proto[0] ? r->proto : scan_proto,
                     r->port,
                     (int)r->state,
                     r->reason[0] ? r->reason : "unknown");

            np_evidence_t ev = {
                .source_module = source_module,
                .description = evidence_desc,
                .timestamp = time(NULL),
                .confidence = (r->state == NP_PORT_OPEN) ? 0.85 : 0.45,
                .raw_data = r,
            };
            (void)np_evidence_add(ctx, svc_id, &ev);
        }
    }

    return NP_OK;
}

static np_status_t scanner_enum_scan_and_collect_cfg(np_recon_context_t *ctx,
                                                     np_config_t *cfg,
                                                     const char *source_module)
{
    volatile sig_atomic_t interrupted = 0;

    bool prev_framework_mode = cfg->framework_mode;
    cfg->framework_mode = true;

    np_status_t rc = np_scanner_run(cfg, &interrupted);
    cfg->framework_mode = prev_framework_mode;
    if (rc != NP_OK)
        return rc;

    np_stats_snapshot_t snap;
    np_stats_snapshot(&snap);
    ctx->packets_sent = snap.pkts_sent;
    ctx->packets_recv = snap.pkts_recv;

    return scanner_enum_collect_from_targets(ctx,
                                             cfg->targets,
                                             cfg->target_count,
                                             cfg->scan_type,
                                             source_module);
}

static np_status_t scanner_enum_scan_and_collect(np_recon_context_t *ctx,
                                                 const char *source_module)
{
    return scanner_enum_scan_and_collect_cfg(ctx, ctx->cfg, source_module);
}

static void np_build_top_udp_ports(np_port_spec_t *spec)
{
    if (!spec)
        return;

    memset(spec, 0, sizeof(*spec));

    uint32_t max_ports = np_top_ports_count;
    if (max_ports > 1000)
        max_ports = 1000;
    if (max_ports > NP_MAX_PORT_RANGES)
        max_ports = NP_MAX_PORT_RANGES;

    for (uint32_t i = 0; i < max_ports; i++)
    {
        spec->ranges[spec->count].start = np_top_ports_top_1000[i];
        spec->ranges[spec->count].end = np_top_ports_top_1000[i];
        spec->count++;
    }
}

static np_status_t scanner_enum_run(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    if (ctx->cfg->recon_subcommand &&
        strcmp(ctx->cfg->recon_subcommand, "analyze") == 0 &&
        ctx->cfg->scan_type == NP_SCAN_UDP)
    {
        np_scan_type_t prev_scan_type = ctx->cfg->scan_type;
        bool prev_forced = ctx->cfg->scan_type_forced;

        ctx->cfg->scan_type_forced = false;
        ctx->cfg->scan_type = NP_SCAN_TCP_CONNECT;

        np_status_t rc = scanner_enum_scan_and_collect(ctx, "scanner.enum");

        ctx->cfg->scan_type_forced = prev_forced;
        ctx->cfg->scan_type = prev_scan_type;
        return rc;
    }

    return scanner_enum_scan_and_collect(ctx, "scanner.enum");
}

static np_status_t scanner_enum_udp_run(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    if (!ctx->cfg->recon_subcommand || strcmp(ctx->cfg->recon_subcommand, "analyze") != 0)
        return NP_OK;

    np_port_spec_t udp_ports;
    np_build_top_udp_ports(&udp_ports);
    if (udp_ports.count == 0)
        return NP_ERR_ARGS;

    np_config_t udp_cfg = *ctx->cfg;
    np_target_t *udp_targets = NULL;

    if (udp_cfg.target_count > 0)
    {
        if (!ctx->cfg->targets)
            return NP_ERR_ARGS;

        udp_targets = calloc(udp_cfg.target_count, sizeof(*udp_targets));
        if (!udp_targets)
            return NP_ERR_MEMORY;

        for (uint32_t i = 0; i < udp_cfg.target_count; i++)
        {
            udp_targets[i] = ctx->cfg->targets[i];
            udp_targets[i].results = NULL;
            udp_targets[i].port_count = 0;
        }
    }

    udp_cfg.targets = udp_targets;
    udp_cfg.scan_type = NP_SCAN_UDP;
    udp_cfg.scan_type_forced = true;
    udp_cfg.ports = udp_ports;
    udp_cfg.framework_mode = true;

    np_status_t rc = scanner_enum_scan_and_collect_cfg(ctx,
                                                       &udp_cfg,
                                                       "scanner.enum.udp");

    for (uint32_t i = 0; i < udp_cfg.target_count; i++)
        np_target_free_results(&udp_cfg.targets[i]);
    free(udp_targets);

    return rc;
}

static const char *g_enum_deps[] = {
    "builtin.discovery",
};

static const char *g_enum_udp_deps[] = {
    "builtin.discovery",
};

np_module_t np_scanner_enum_module = {
    .name = "scanner.enum",
    .stage = NP_STAGE_ENUM,
    .impact = NP_IMPACT_INTRUSIVE,
    .priority = 10,
    .depends_on = g_enum_deps,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .init = NULL,
    .run = scanner_enum_run,
    .cleanup = NULL,
};

np_module_t np_scanner_enum_udp_module = {
    .name = "scanner.enum.udp",
    .stage = NP_STAGE_ENRICH,
    .impact = NP_IMPACT_INTRUSIVE,
    .priority = 90,
    .depends_on = g_enum_udp_deps,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .init = NULL,
    .run = scanner_enum_udp_run,
    .cleanup = NULL,
};
