#include "recon/recon.h"

#include <string.h>

#include "discovery/host_discovery.h"
#include "recon/evidence.h"
#include "recon/graph.h"
#include "recon/modules/enum_scanner.h"
#include "recon/modules/enrich_tls.h"
#include "recon/modules/fingerprint_os.h"
#include "recon/modules/fingerprint_service.h"
#include "recon/modules/report_output.h"
#include "recon/submodules/scanner/scanner.h"
#include "target.h"
#include <time.h>

static uint64_t np_recon_now_monotonic_ns(void)
{
    struct timespec ts;
#if defined(CLOCK_MONOTONIC)
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
    timespec_get(&ts, TIME_UTC);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static np_status_t np_module_discovery_run(np_recon_context_t *ctx)
{
    return np_recon_run_discovery(ctx, NULL);
}

static np_module_t g_builtin_discovery_module = {
    .name = "builtin.discovery",
    .stage = NP_STAGE_DISCOVERY,
    .impact = NP_IMPACT_SAFE,
    .priority = 10,
    .depends_on = NULL,
    .depends_on_count = 0,
    .parallel_safe = false,
    .required = true,
    .init = NULL,
    .run = np_module_discovery_run,
    .cleanup = NULL,
};

np_status_t np_recon_register_builtin_modules(np_recon_context_t *ctx)
{
    np_status_t rc = np_module_register(ctx, &g_builtin_discovery_module);
    if (rc != NP_OK)
        return rc;

    rc = np_module_register(ctx, &np_scanner_enum_module);
    if (rc != NP_OK)
        return rc;

    rc = np_module_register(ctx, &np_scanner_enum_udp_module);
    if (rc != NP_OK)
        return rc;

    rc = np_module_register(ctx, &np_service_fingerprint_module);
    if (rc != NP_OK)
        return rc;

    rc = np_module_register(ctx, &np_tls_enrich_module);
    if (rc != NP_OK)
        return rc;

    rc = np_module_register(ctx, &np_os_fingerprint_module);
    if (rc != NP_OK)
        return rc;

    return np_module_register(ctx, &np_report_output_module);
}

np_status_t np_recon_execute_pipeline(np_recon_context_t *ctx,
                                      np_stage_t from,
                                      np_stage_t to,
                                      volatile sig_atomic_t *interrupted)
{
    if (!ctx)
        return NP_ERR_ARGS;

    if (from > to)
        return NP_ERR_ARGS;

    if (interrupted && *interrupted)
        return NP_ERR_SYSTEM;

    ctx->interrupted = interrupted;

    np_status_t pipeline_rc = NP_OK;
    pipeline_rc = np_module_run_range(ctx, from, to);

    ctx->end_ts = time(NULL);
    ctx->end_mono_ns = np_recon_now_monotonic_ns();
    ctx->interrupted = NULL;

    return pipeline_rc;
}

np_status_t np_recon_run_discovery(np_recon_context_t *ctx,
                                   volatile sig_atomic_t *interrupted)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    np_status_t rc = np_discovery_resolve_targets(ctx->cfg);
    if (rc != NP_OK)
        return rc;

    rc = np_host_discovery_run(ctx->cfg, interrupted);
    if (rc != NP_OK)
        return rc;

    return np_recon_graph_ingest_discovery(ctx);
}

np_status_t np_recon_graph_ingest_discovery(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    for (uint32_t target_idx = 0; target_idx < ctx->cfg->target_count; target_idx++)
    {
        np_target_t *target = &ctx->cfg->targets[target_idx];
        bool keep = target->host_discovered || target->host_up;
        if (ctx->cfg->host_discovery_mode == NP_HOST_DISCOVERY_LIST_ONLY)
            keep = true;

        if (!keep)
            continue;

        uint64_t host_node = np_graph_get_or_add_host(ctx, target);
        if (!host_node)
            return NP_ERR_MEMORY;

        if (target->host_reason[0])
        {
            np_evidence_t evidence = {
                .source_module = "builtin.discovery",
                .description = target->host_reason,
                .timestamp = time(NULL),
                .confidence = target->host_up ? 0.95 : 0.60,
                .raw_data = target,
            };
            (void)np_evidence_add(ctx, host_node, &evidence);
        }
    }

    return NP_OK;
}

np_status_t np_recon_run_enum(np_recon_context_t *ctx,
                              volatile sig_atomic_t *interrupted)
{
    if (!ctx)
        return NP_ERR_ARGS;

    np_module_clear(ctx);
    np_status_t rc = np_recon_register_builtin_modules(ctx);
    if (rc != NP_OK)
        return rc;

    return np_recon_execute_pipeline(ctx,
                                     NP_STAGE_DISCOVERY,
                                     NP_STAGE_ENUM,
                                     interrupted);
}

np_status_t np_recon_graph_ingest_scan(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    for (uint32_t target_idx = 0; target_idx < ctx->cfg->target_count; target_idx++)
    {
        np_target_t *target = &ctx->cfg->targets[target_idx];
        uint64_t host_node = np_graph_get_or_add_host(ctx, target);
        if (!host_node)
            return NP_ERR_MEMORY;

        for (uint32_t port_idx = 0; port_idx < target->port_count; port_idx++)
        {
            np_port_result_t *port = &target->results[port_idx];
            if (port->state != NP_PORT_OPEN && port->state != NP_PORT_OPEN_FILTERED)
                continue;

            uint64_t service_node = np_graph_add_service(ctx, port);
            if (!service_node)
                return NP_ERR_MEMORY;

            np_graph_link(ctx, host_node, service_node, NP_RECON_REL_EXPOSES);
            ctx->services_seen++;

            np_evidence_t evidence = {
                .source_module = "builtin.enum",
                .description = port->service[0] ? port->service : "open-port",
                .timestamp = time(NULL),
                .confidence = port->service_confidence > 0
                                  ? ((double)port->service_confidence / 100.0)
                                  : ((port->state == NP_PORT_OPEN) ? 0.5 : 0.35),
                .raw_data = port,
            };
            (void)np_evidence_add(ctx, service_node, &evidence);
        }

    }

    return NP_OK;
}

np_status_t np_recon_graph_ingest_os(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    for (uint32_t target_idx = 0; target_idx < ctx->cfg->target_count; target_idx++)
    {
        np_target_t *target = &ctx->cfg->targets[target_idx];
        if (!target->os_result_valid)
            continue;

        uint64_t host_node = np_graph_get_or_add_host(ctx, target);
        if (!host_node)
            return NP_ERR_MEMORY;

        uint64_t os_node = np_graph_add_os(ctx, &target->os_result);
        if (!os_node)
            return NP_ERR_MEMORY;

        np_graph_link(ctx, host_node, os_node, NP_RECON_REL_RUNS);

        np_evidence_t os_evidence = {
            .source_module = "os.fingerprint",
            .description = target->os_result.best_os,
            .timestamp = time(NULL),
            .confidence = target->os_result.best_confidence / 100.0,
            .raw_data = &target->os_result,
        };
        (void)np_evidence_add(ctx, os_node, &os_evidence);
    }

    return NP_OK;
}

np_status_t np_recon_run_analyze(np_recon_context_t *ctx,
                                 volatile sig_atomic_t *interrupted)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    np_module_clear(ctx);
    np_status_t rc = np_recon_register_builtin_modules(ctx);
    if (rc != NP_OK)
        return rc;

    return np_recon_execute_pipeline(ctx,
                                     NP_STAGE_DISCOVERY,
                                     NP_STAGE_ENRICH,
                                     interrupted);
}

np_status_t np_recon_run_report(np_recon_context_t *ctx,
                                volatile sig_atomic_t *interrupted)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    np_module_clear(ctx);
    np_status_t rc = np_recon_register_builtin_modules(ctx);
    if (rc != NP_OK)
        return rc;

    return np_recon_execute_pipeline(ctx,
                                     NP_STAGE_DISCOVERY,
                                     NP_STAGE_REPORT,
                                     interrupted);
}
