#include "recon/modules/report_output.h"

#include "recon/output.h"

static np_status_t report_output_run(np_recon_context_t *ctx)
{
    return np_output_stage_run(ctx);
}

static const char *g_report_deps[] = {
    "service.fingerprint",
    "tls.enrich",
    "os.fingerprint",
};

np_module_t np_report_output_module = {
    .name = "report.output",
    .stage = NP_STAGE_REPORT,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 100,
    .depends_on = g_report_deps,
    .depends_on_count = 3,
    .parallel_safe = false,
    .required = true,
    .init = NULL,
    .run = report_output_run,
    .cleanup = NULL,
};
