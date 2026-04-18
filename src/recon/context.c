#include "recon/context.h"

#include <stdlib.h>
#include <string.h>

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

#include "recon_internal.h"

static uint64_t np_recon_make_run_id(void)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return ((uint64_t)ts.tv_sec << 32) ^ (uint64_t)ts.tv_nsec;
}

np_recon_context_t *np_recon_create(np_config_t *cfg)
{
    if (!cfg)
        return NULL;

    np_recon_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->cfg = cfg;
    ctx->run_id = np_recon_make_run_id();
    ctx->start_ts = time(NULL);
    ctx->start_mono_ns = np_recon_now_monotonic_ns();

    ctx->graph = np_graph_store_create();
    ctx->modules = np_module_registry_create();
    ctx->evidence = np_evidence_store_create();
    ctx->interrupted = NULL;
    if (!ctx->graph || !ctx->modules || !ctx->evidence)
    {
        np_recon_destroy(ctx);
        return NULL;
    }

    return ctx;
}

void np_recon_destroy(np_recon_context_t *ctx)
{
    if (!ctx)
        return;

    ctx->end_ts = time(NULL);
    ctx->end_mono_ns = np_recon_now_monotonic_ns();

    np_graph_store_destroy((np_graph_store_t *)ctx->graph);
    np_module_registry_destroy((np_module_registry_t *)ctx->modules);
    np_evidence_store_destroy((np_evidence_store_t *)ctx->evidence);

    free(ctx);
}
