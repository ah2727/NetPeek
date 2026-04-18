#include "recon/modules/fingerprint_service.h"

#include "recon/graph.h"
#include "recon/submodules/scanner/service_detect.h"
#include "recon/submodules/scanner/service_version.h"

static np_status_t service_fp_run(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    if (!ctx->cfg->service_version_detect)
        return NP_OK;

    np_status_t rc = np_service_version_run(ctx->cfg);
    if (rc != NP_OK)
        return rc;

    rc = np_service_detect_run(ctx->cfg);
    if (rc != NP_OK)
        return rc;

    return np_graph_sync_services_from_targets(ctx);
}

static const char *g_service_fp_deps[] = {
    "scanner.enum",
};

np_module_t np_service_fingerprint_module = {
    .name = "service.fingerprint",
    .stage = NP_STAGE_FINGERPRINT,
    .impact = NP_IMPACT_SAFE,
    .priority = 20,
    .depends_on = g_service_fp_deps,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .init = NULL,
    .run = service_fp_run,
    .cleanup = NULL,
};
