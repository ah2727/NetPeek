#include "test.h"

#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "recon/context.h"
#include "recon/evidence.h"
#include "recon/graph.h"
#include "recon/module.h"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_running = 0;
static int g_peak_running = 0;
static int g_downstream_runs = 0;
static int g_local_cfg_runs = 0;

static void reset_state(void)
{
    pthread_mutex_lock(&g_lock);
    g_running = 0;
    g_peak_running = 0;
    g_downstream_runs = 0;
    g_local_cfg_runs = 0;
    pthread_mutex_unlock(&g_lock);
}

static void mark_enter(void)
{
    pthread_mutex_lock(&g_lock);
    g_running++;
    if (g_running > g_peak_running)
        g_peak_running = g_running;
    pthread_mutex_unlock(&g_lock);
}

static void mark_leave(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_running > 0)
        g_running--;
    pthread_mutex_unlock(&g_lock);
}

static np_status_t run_base(np_recon_context_t *ctx)
{
    (void)ctx;
    usleep(20000);
    return NP_OK;
}

static np_status_t run_parallel(np_recon_context_t *ctx)
{
    (void)ctx;
    mark_enter();
    usleep(120000);
    mark_leave();
    return NP_OK;
}

static np_status_t run_fail(np_recon_context_t *ctx)
{
    (void)ctx;
    usleep(10000);
    return NP_ERR_SYSTEM;
}

static np_status_t run_downstream(np_recon_context_t *ctx)
{
    (void)ctx;
    pthread_mutex_lock(&g_lock);
    g_downstream_runs++;
    pthread_mutex_unlock(&g_lock);
    return NP_OK;
}

static np_status_t run_local_cfg_mutation(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    np_config_t local = *ctx->cfg;
    local.scan_type = NP_SCAN_UDP;
    local.scan_type_forced = true;
    local.framework_mode = true;
    local.ports.count = 1;
    local.ports.ranges[0].start = 53;
    local.ports.ranges[0].end = 53;

    mark_enter();
    usleep(80000);
    mark_leave();

    if (ctx->cfg->scan_type != NP_SCAN_TCP_CONNECT ||
        ctx->cfg->scan_type_forced ||
        ctx->cfg->framework_mode)
    {
        return NP_ERR_SYSTEM;
    }

    pthread_mutex_lock(&g_lock);
    g_local_cfg_runs++;
    pthread_mutex_unlock(&g_lock);

    return NP_OK;
}

static np_status_t run_host_upsert(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg || ctx->cfg->target_count == 0)
        return NP_ERR_ARGS;

    for (int i = 0; i < 200; i++)
    {
        if (!np_graph_get_or_add_host(ctx, &ctx->cfg->targets[0]))
            return NP_ERR_MEMORY;
    }

    return NP_OK;
}

static np_status_t run_evidence_parallel(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg || ctx->cfg->target_count == 0)
        return NP_ERR_ARGS;

    uint64_t host = np_graph_get_or_add_host(ctx, &ctx->cfg->targets[0]);
    if (!host)
        return NP_ERR_MEMORY;

    np_evidence_t ev = {
        .source_module = "unit.evidence",
        .description = "parallel-evidence",
        .confidence = 0.95,
    };

    for (int i = 0; i < 200; i++)
    {
        if (!np_evidence_add(ctx, host, &ev))
            return NP_ERR_MEMORY;
    }

    return NP_OK;
}

static const char *dep_base[] = {"unit.base"};
static const char *dep_fail[] = {"unit.fail"};

static const np_module_t module_base = {
    .name = "unit.base",
    .stage = NP_STAGE_DISCOVERY,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 1,
    .depends_on = NULL,
    .depends_on_count = 0,
    .parallel_safe = false,
    .required = true,
    .run = run_base,
};

static const np_module_t module_parallel_a = {
    .name = "unit.parallel.a",
    .stage = NP_STAGE_FINGERPRINT,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 1,
    .depends_on = dep_base,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .run = run_parallel,
};

static const np_module_t module_parallel_b = {
    .name = "unit.parallel.b",
    .stage = NP_STAGE_ENRICH,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 2,
    .depends_on = dep_base,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .run = run_parallel,
};

static const np_module_t module_fail = {
    .name = "unit.fail",
    .stage = NP_STAGE_FINGERPRINT,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 10,
    .depends_on = dep_base,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .run = run_fail,
};

static const np_module_t module_downstream = {
    .name = "unit.downstream",
    .stage = NP_STAGE_REPORT,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 20,
    .depends_on = dep_fail,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .run = run_downstream,
};

static const np_module_t module_host_upsert_a = {
    .name = "unit.host.upsert.a",
    .stage = NP_STAGE_FINGERPRINT,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 5,
    .depends_on = dep_base,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .run = run_host_upsert,
};

static const np_module_t module_host_upsert_b = {
    .name = "unit.host.upsert.b",
    .stage = NP_STAGE_ENRICH,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 6,
    .depends_on = dep_base,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .run = run_host_upsert,
};

static const np_module_t module_evidence_a = {
    .name = "unit.evidence.a",
    .stage = NP_STAGE_FINGERPRINT,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 30,
    .depends_on = dep_base,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .run = run_evidence_parallel,
};

static const np_module_t module_evidence_b = {
    .name = "unit.evidence.b",
    .stage = NP_STAGE_ENRICH,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 31,
    .depends_on = dep_base,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .run = run_evidence_parallel,
};

static const np_module_t module_local_cfg_a = {
    .name = "unit.local.cfg.a",
    .stage = NP_STAGE_FINGERPRINT,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 50,
    .depends_on = dep_base,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .run = run_local_cfg_mutation,
};

static const np_module_t module_local_cfg_b = {
    .name = "unit.local.cfg.b",
    .stage = NP_STAGE_ENRICH,
    .impact = NP_IMPACT_PASSIVE,
    .priority = 51,
    .depends_on = dep_base,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .run = run_local_cfg_mutation,
};

NP_TEST(recon_scheduler_runs_independent_modules_in_parallel)
{
    reset_state();
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_base));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_parallel_a));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_parallel_b));

    ASSERT_EQ_INT(NP_OK, np_module_run_range(ctx, NP_STAGE_DISCOVERY, NP_STAGE_ENRICH));

    pthread_mutex_lock(&g_lock);
    int peak = g_peak_running;
    pthread_mutex_unlock(&g_lock);
    ASSERT_TRUE(peak >= 2);

    np_module_progress_snapshot_t progress;
    np_module_progress_snapshot(&progress);
    ASSERT_EQ_INT(3, (int)progress.total_modules);
    ASSERT_EQ_INT(3, (int)progress.completed_modules);
    ASSERT_EQ_INT(1, (int)progress.stage_total[NP_STAGE_DISCOVERY]);
    ASSERT_EQ_INT(1, (int)progress.stage_total[NP_STAGE_FINGERPRINT]);
    ASSERT_EQ_INT(1, (int)progress.stage_total[NP_STAGE_ENRICH]);
    ASSERT_EQ_INT(1, (int)progress.stage_completed[NP_STAGE_DISCOVERY]);
    ASSERT_EQ_INT(1, (int)progress.stage_completed[NP_STAGE_FINGERPRINT]);
    ASSERT_EQ_INT(1, (int)progress.stage_completed[NP_STAGE_ENRICH]);

    np_module_run_record_t *records = NULL;
    uint32_t record_count = np_module_last_run_snapshot(ctx, &records);
    ASSERT_EQ_INT(3, (int)record_count);
    np_module_run_snapshot_free(records);

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

NP_TEST(recon_scheduler_serial_flag_disables_parallelism)
{
    reset_state();
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);
    cfg->recon_force_serial = true;

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_base));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_parallel_a));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_parallel_b));

    ASSERT_EQ_INT(NP_OK, np_module_run_range(ctx, NP_STAGE_DISCOVERY, NP_STAGE_ENRICH));

    pthread_mutex_lock(&g_lock);
    int peak = g_peak_running;
    pthread_mutex_unlock(&g_lock);
    ASSERT_EQ_INT(1, peak);

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

NP_TEST(recon_scheduler_respects_worker_cap)
{
    reset_state();
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);
    cfg->recon_workers = 1;

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_base));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_parallel_a));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_parallel_b));

    ASSERT_EQ_INT(NP_OK, np_module_run_range(ctx, NP_STAGE_DISCOVERY, NP_STAGE_ENRICH));

    pthread_mutex_lock(&g_lock);
    int peak = g_peak_running;
    pthread_mutex_unlock(&g_lock);
    ASSERT_EQ_INT(1, peak);

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

NP_TEST(recon_scheduler_best_effort_skips_failed_dependents)
{
    reset_state();
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_base));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_parallel_a));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_fail));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_downstream));

    ASSERT_EQ_INT(NP_ERR_SYSTEM,
                  np_module_run_range(ctx, NP_STAGE_DISCOVERY, NP_STAGE_REPORT));

    pthread_mutex_lock(&g_lock);
    int downstream_runs = g_downstream_runs;
    pthread_mutex_unlock(&g_lock);
    ASSERT_EQ_INT(0, downstream_runs);

    np_module_run_record_t *records = NULL;
    uint32_t record_count = np_module_last_run_snapshot(ctx, &records);
    ASSERT_EQ_INT(4, (int)record_count);

    bool saw_fail = false;
    bool saw_skip = false;
    for (uint32_t i = 0; i < record_count; i++)
    {
        if (strcmp(records[i].module_name, "unit.fail") == 0 &&
            records[i].run_status == NP_MODULE_RUN_FAILED)
            saw_fail = true;
        if (strcmp(records[i].module_name, "unit.downstream") == 0 &&
            records[i].run_status == NP_MODULE_RUN_SKIPPED_DEP)
            saw_skip = true;
    }
    ASSERT_TRUE(saw_fail);
    ASSERT_TRUE(saw_skip);

    np_module_progress_snapshot_t progress;
    np_module_progress_snapshot(&progress);
    ASSERT_EQ_INT(4, (int)progress.total_modules);
    ASSERT_EQ_INT(4, (int)progress.completed_modules);
    ASSERT_EQ_INT(1, (int)progress.stage_total[NP_STAGE_REPORT]);
    ASSERT_EQ_INT(1, (int)progress.stage_completed[NP_STAGE_REPORT]);

    np_module_run_snapshot_free(records);
    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

NP_TEST(recon_scheduler_parallel_host_upsert_prevents_duplicates)
{
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    cfg->target_count = 1;
    cfg->targets = calloc(1, sizeof(np_target_t));
    ASSERT_TRUE(cfg->targets != NULL);
    strncpy(cfg->targets[0].ip, "10.0.0.1", sizeof(cfg->targets[0].ip) - 1);
    strncpy(cfg->targets[0].hostname, "unit-host", sizeof(cfg->targets[0].hostname) - 1);

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_base));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_host_upsert_a));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_host_upsert_b));

    ASSERT_EQ_INT(NP_OK, np_module_run_range(ctx, NP_STAGE_DISCOVERY, NP_STAGE_ENRICH));
    ASSERT_EQ_INT(1, (int)np_graph_node_count(ctx));

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

NP_TEST(recon_scheduler_parallel_evidence_add_is_consistent)
{
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    cfg->target_count = 1;
    cfg->targets = calloc(1, sizeof(np_target_t));
    ASSERT_TRUE(cfg->targets != NULL);
    strncpy(cfg->targets[0].ip, "10.0.0.2", sizeof(cfg->targets[0].ip) - 1);
    strncpy(cfg->targets[0].hostname, "evidence-host", sizeof(cfg->targets[0].hostname) - 1);

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_base));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_evidence_a));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_evidence_b));

    ASSERT_EQ_INT(NP_OK, np_module_run_range(ctx, NP_STAGE_DISCOVERY, NP_STAGE_ENRICH));
    ASSERT_EQ_INT(400, (int)np_evidence_count(ctx));

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

NP_TEST(recon_scheduler_parallel_local_cfg_mutation_isolation)
{
    reset_state();
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    cfg->scan_type = NP_SCAN_TCP_CONNECT;
    cfg->scan_type_forced = false;
    cfg->framework_mode = false;

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_base));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_local_cfg_a));
    ASSERT_EQ_INT(NP_OK, np_module_register(ctx, &module_local_cfg_b));

    ASSERT_EQ_INT(NP_OK, np_module_run_range(ctx, NP_STAGE_DISCOVERY, NP_STAGE_ENRICH));

    pthread_mutex_lock(&g_lock);
    int peak = g_peak_running;
    int runs = g_local_cfg_runs;
    pthread_mutex_unlock(&g_lock);

    ASSERT_TRUE(peak >= 2);
    ASSERT_EQ_INT(2, runs);
    ASSERT_EQ_INT(NP_SCAN_TCP_CONNECT, (int)cfg->scan_type);
    ASSERT_TRUE(!cfg->scan_type_forced);
    ASSERT_TRUE(!cfg->framework_mode);

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

void register_recon_scheduler_tests(void)
{
    NP_REGISTER(recon_scheduler_runs_independent_modules_in_parallel);
    NP_REGISTER(recon_scheduler_serial_flag_disables_parallelism);
    NP_REGISTER(recon_scheduler_respects_worker_cap);
    NP_REGISTER(recon_scheduler_best_effort_skips_failed_dependents);
    NP_REGISTER(recon_scheduler_parallel_host_upsert_prevents_duplicates);
    NP_REGISTER(recon_scheduler_parallel_evidence_add_is_consistent);
    NP_REGISTER(recon_scheduler_parallel_local_cfg_mutation_isolation);
}
