/* ============================================================
   include/os_detect/os_pipeline_parallel.h
   Parallel fingerprint + banner stage definitions
   ============================================================ */
#ifndef NP_OS_PIPELINE_PARALLEL_H
#define NP_OS_PIPELINE_PARALLEL_H

#include "os_pipeline_priv.h"
#include <pthread.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────
   Thread result containers — each thread writes to its own
   isolated struct, so no mutex is needed during execution.
   ──────────────────────────────────────────────────────────── */

typedef struct np_parallel_fp_result {
    bool     valid;
    uint32_t score;
    int      candidate_count;
    /* First candidate OS name for quick log access */
    char     best_os[NP_OS_NAME_LEN];
} np_parallel_fp_result_t;

typedef struct np_parallel_banner_result {
    bool     valid;
    int      banner_count;
    double   best_confidence;
    char     best_os[NP_OS_NAME_LEN];
    /* Full banner array copied after join */
    np_os_banner_t banners[NP_OS_MAX_BANNERS];
} np_parallel_banner_result_t;

/* ────────────────────────────────────────────────────────────
   Thread argument — passed to each worker thread.
   Contains a READ-ONLY pointer to the shared pipeline ctx
   plus a pointer to the thread's own result struct.
   ──────────────────────────────────────────────────────────── */

typedef struct np_fp_thread_arg {
    const np_pipeline_ctx_t      *ctx;    /* read-only */
    np_parallel_fp_result_t      *out;    /* thread-local write */
} np_fp_thread_arg_t;

typedef struct np_banner_thread_arg {
    np_pipeline_ctx_t            *ctx;    /* needs write for banner I/O */
    np_parallel_banner_result_t  *out;    /* thread-local write */
} np_banner_thread_arg_t;

/* ────────────────────────────────────────────────────────────
   Public API
   ──────────────────────────────────────────────────────────── */

/**
 * Run fingerprint match + banner grab in parallel.
 * Blocks until both complete, then merges results into ctx.
 *
 * @return 0 on success, -1 if thread creation failed.
 */
int np_pipeline_run_parallel_stages(np_pipeline_ctx_t *ctx);

/**
 * Individual thread entry points (exposed for testing).
 */
void *np_parallel_fp_match_worker(void *arg);
void *np_parallel_banner_grab_worker(void *arg);

/**
 * Merge parallel results back into the pipeline context.
 * Called automatically by np_pipeline_run_parallel_stages().
 */
void np_parallel_merge_fp_result(
    np_pipeline_ctx_t *ctx,
    const np_parallel_fp_result_t *fp_res);

void np_parallel_merge_banner_result(
    np_pipeline_ctx_t *ctx,
    const np_parallel_banner_result_t *ban_res);

#ifdef __cplusplus
}
#endif

#endif /* NP_OS_PIPELINE_PARALLEL_H */
