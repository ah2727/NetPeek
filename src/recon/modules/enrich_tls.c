#include "recon/modules/enrich_tls.h"

#include "recon/submodules/scanner/tls_probe.h"

static np_status_t tls_enrich_run(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    if (!ctx->cfg->tls_info)
        return NP_OK;

    return np_tls_probe_run(ctx->cfg);
}

static const char *g_tls_enrich_deps[] = {
    "scanner.enum",
};

np_module_t np_tls_enrich_module = {
    .name = "tls.enrich",
    .stage = NP_STAGE_ENRICH,
    .impact = NP_IMPACT_SAFE,
    .priority = 30,
    .depends_on = g_tls_enrich_deps,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .init = NULL,
    .run = tls_enrich_run,
    .cleanup = NULL,
};
