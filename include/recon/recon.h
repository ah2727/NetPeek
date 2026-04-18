#ifndef NP_RECON_RECON_H
#define NP_RECON_RECON_H

#include <signal.h>

#include "recon/context.h"
#include "recon/module.h"

np_status_t np_recon_register_builtin_modules(np_recon_context_t *ctx);
np_status_t np_recon_execute_pipeline(np_recon_context_t *ctx,
                                      np_stage_t from,
                                      np_stage_t to,
                                      volatile sig_atomic_t *interrupted);
np_status_t np_recon_run_discovery(np_recon_context_t *ctx,
                                   volatile sig_atomic_t *interrupted);
np_status_t np_recon_run_enum(np_recon_context_t *ctx,
                              volatile sig_atomic_t *interrupted);
np_status_t np_recon_run_analyze(np_recon_context_t *ctx,
                                 volatile sig_atomic_t *interrupted);
np_status_t np_recon_run_report(np_recon_context_t *ctx,
                                volatile sig_atomic_t *interrupted);

np_status_t np_recon_graph_ingest_scan(np_recon_context_t *ctx);
np_status_t np_recon_graph_ingest_discovery(np_recon_context_t *ctx);
np_status_t np_recon_graph_ingest_os(np_recon_context_t *ctx);

#endif
