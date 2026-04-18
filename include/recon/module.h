#ifndef NP_RECON_MODULE_H
#define NP_RECON_MODULE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "recon/context.h"

#define NP_RECON_MODULE_ABI_V1 1u

typedef enum {
    NP_STAGE_DISCOVERY = 0,
    NP_STAGE_ENUM,
    NP_STAGE_FINGERPRINT,
    NP_STAGE_ENRICH,
    NP_STAGE_ANALYZE,
    NP_STAGE_REPORT
} np_stage_t;

#define NP_STAGE_COUNT ((size_t)NP_STAGE_REPORT + 1u)

typedef enum {
    NP_IMPACT_PASSIVE = 0,
    NP_IMPACT_SAFE,
    NP_IMPACT_INTRUSIVE
} np_impact_t;

typedef struct np_module {
    const char *name;
    np_stage_t stage;
    np_impact_t impact;
    uint32_t priority;
    const char **depends_on;
    size_t depends_on_count;
    bool parallel_safe;
    bool required;

    np_status_t (*init)(np_recon_context_t *ctx);
    np_status_t (*run)(np_recon_context_t *ctx);
    void (*cleanup)(np_recon_context_t *ctx);
} np_module_t;

typedef enum {
    NP_MODULE_RUN_OK = 0,
    NP_MODULE_RUN_FAILED,
    NP_MODULE_RUN_SKIPPED_DEP,
    NP_MODULE_RUN_SKIPPED_INTERRUPT
} np_module_run_status_t;

typedef struct {
    char module_name[64];
    np_stage_t stage;
    np_module_run_status_t run_status;
    np_status_t rc;
    uint64_t started_ns;
    uint64_t ended_ns;
} np_module_run_record_t;

typedef struct {
    uint64_t total_modules;
    uint64_t completed_modules;
    uint64_t stage_total[NP_STAGE_COUNT];
    uint64_t stage_completed[NP_STAGE_COUNT];
} np_module_progress_snapshot_t;

typedef struct {
    void *dl_handle;
    const np_module_t *module;
} np_module_plugin_t;

typedef struct {
    const char *module_name;
    const char *module_version;
    const char *signer;
    const char *signature;
    np_impact_t impact;
} np_module_manifest_t;

np_status_t np_module_register(np_recon_context_t *ctx, const np_module_t *module);
np_status_t np_module_run_stage(np_recon_context_t *ctx, np_stage_t stage);
np_status_t np_module_run_range(np_recon_context_t *ctx,
                                np_stage_t from,
                                np_stage_t to);
void np_module_clear(np_recon_context_t *ctx);
uint32_t np_module_last_run_snapshot(np_recon_context_t *ctx,
                                     np_module_run_record_t **out);
void np_module_run_snapshot_free(np_module_run_record_t *records);
void np_module_progress_reset(void);
void np_module_progress_snapshot(np_module_progress_snapshot_t *out);

np_status_t np_module_load_plugin(np_recon_context_t *ctx,
                                  const char *path,
                                  np_module_plugin_t *out_plugin);
np_status_t np_module_load_dir(np_recon_context_t *ctx,
                               const char *dirpath,
                               size_t *loaded_count);
void np_module_unload_plugin(np_module_plugin_t *plugin);

#endif
