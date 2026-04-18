/* ============================================================
   src/os_detect/os_pipeline_parallel.c
   Parallel execution of fingerprint match + banner grab
   ============================================================ */
#include "os_pipeline_parallel.h"
#include "os_pipeline_priv.h"
#include "recon/submodules/os_detect/os_detect_pipeline.h"
#include "logger.h"

#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#define LOG_STAGE "parallel"

/* ────────────────────────────────────────────────────────────
   Fingerprint Match Worker Thread
   ──────────────────────────────────────────────────────────── */
void *np_parallel_fp_match_worker(void *arg)
{
    if (!arg)
        return NULL;

    np_fp_thread_arg_t *ta = (np_fp_thread_arg_t *)arg;

    /*
     * We need a mutable copy because stage_fingerprint_match()
     * writes into ctx->candidates[], ctx->fp_valid, etc.
     * This is the thread-local working copy.
     */
    np_pipeline_ctx_t local_ctx;
    memcpy(&local_ctx, ta->ctx, sizeof(np_pipeline_ctx_t));

    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "[FP thread] Starting fingerprint match");

    stage_fingerprint_match(&local_ctx);

    /* ── Write results into thread-local output struct ── */
    ta->out->valid           = local_ctx.fp_valid;
    ta->out->score           = local_ctx.fp_score;
    ta->out->candidate_count = local_ctx.candidate_count;

    if (local_ctx.fp_valid && local_ctx.candidate_count > 0)
    {
        strncpy(ta->out->best_os,
                local_ctx.candidates[0].os_name,
                sizeof(ta->out->best_os) - 1);
        ta->out->best_os[sizeof(ta->out->best_os) - 1] = '\0';
    }
    else
    {
        ta->out->best_os[0] = '\0';
    }

    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "[FP thread] Done: valid=%d score=%u os='%s'",
             ta->out->valid,
             ta->out->score,
             ta->out->best_os);

    return NULL;
}

/* ────────────────────────────────────────────────────────────
   Banner Grab Worker Thread
   ──────────────────────────────────────────────────────────── */
void *np_parallel_banner_grab_worker(void *arg)
{
    if (!arg)
        return NULL;

    np_banner_thread_arg_t *ta =
        (np_banner_thread_arg_t *)arg;

    /*
     * Banner grab needs network I/O, so we work on a
     * local copy of ctx to avoid races with the FP thread.
     */
    np_pipeline_ctx_t local_ctx;
    memcpy(&local_ctx, ta->ctx, sizeof(np_pipeline_ctx_t));

    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "[Banner thread] Starting banner collect + grab");

    stage_banner_collect(&local_ctx);
    stage_banner_grab(&local_ctx);

    /* ── Bridge: os_result.banners → local banners ── */
    int count = (int)local_ctx.os_result.banner_count;
    if (count > NP_OS_MAX_BANNERS)
        count = NP_OS_MAX_BANNERS;

    ta->out->banner_count = count;

    if (count > 0)
    {
        memcpy(ta->out->banners,
               local_ctx.os_result.banners,
               count * sizeof(np_os_banner_t));
    }

    /* ── Find best confidence in grabbed banners ── */
    ta->out->best_confidence = 0.0;
    ta->out->best_os[0]     = '\0';
    ta->out->valid           = false;

    for (int i = 0; i < count; i++)
    {
        double c =
            (double)ta->out->banners[i].os_hint_confidence;

        if (c > ta->out->best_confidence)
        {
            ta->out->best_confidence = c;
            ta->out->valid           = true;

            if (ta->out->banners[i].os_hint[0])
            {
                strncpy(ta->out->best_os,
                        ta->out->banners[i].os_hint,
                        sizeof(ta->out->best_os) - 1);
                ta->out->best_os[
                    sizeof(ta->out->best_os) - 1] = '\0';
            }
        }
    }

    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "[Banner thread] Done: valid=%d count=%d "
             "best_conf=%.2f os='%s'",
             ta->out->valid,
             ta->out->banner_count,
             ta->out->best_confidence,
             ta->out->best_os);

    return NULL;
}

/* ────────────────────────────────────────────────────────────
   Merge Functions
   ──────────────────────────────────────────────────────────── */
void np_parallel_merge_fp_result(
    np_pipeline_ctx_t *ctx,
    const np_parallel_fp_result_t *fp_res)
{
    if (!ctx || !fp_res)
        return;

    ctx->fp_valid        = fp_res->valid;
    ctx->fp_score        = fp_res->score;
    ctx->candidate_count = fp_res->candidate_count;

    if (fp_res->valid && fp_res->best_os[0])
    {
        strncpy(ctx->candidates[0].os_name,
                fp_res->best_os,
                sizeof(ctx->candidates[0].os_name) - 1);
        ctx->candidates[0].os_name[
            sizeof(ctx->candidates[0].os_name) - 1] = '\0';
    }

    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "Merged FP result: valid=%d score=%u "
             "os='%s'",
             ctx->fp_valid,
             ctx->fp_score,
             fp_res->best_os);
}

void np_parallel_merge_banner_result(
    np_pipeline_ctx_t *ctx,
    const np_parallel_banner_result_t *ban_res)
{
    if (!ctx || !ban_res)
        return;

    /* Copy banner array into ctx->banners[] */
    ctx->banner_count = ban_res->banner_count;

    if (ctx->banner_count > NP_OS_MAX_BANNERS)
        ctx->banner_count = NP_OS_MAX_BANNERS;

    if (ctx->banner_count > 0)
    {
        memcpy(ctx->banners,
               ban_res->banners,
               ctx->banner_count * sizeof(np_os_banner_t));
    }

    /* Also update os_result.banners for final output */
    ctx->os_result.banner_count =
        (uint32_t)ctx->banner_count;

    if (ctx->banner_count > 0)
    {
        memcpy(ctx->os_result.banners,
               ban_res->banners,
               ctx->banner_count * sizeof(np_os_banner_t));
    }

    /* Set aggregate fields */
    ctx->banner_valid      = ban_res->valid;
    ctx->banner_confidence = ban_res->best_confidence;

    if (ban_res->best_os[0])
    {
        strncpy(ctx->banner_os_name,
                ban_res->best_os,
                sizeof(ctx->banner_os_name) - 1);
        ctx->banner_os_name[
            sizeof(ctx->banner_os_name) - 1] = '\0';
    }
    else
    {
        ctx->banner_os_name[0] = '\0';
    }

    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "Merged banner result: valid=%d count=%d "
             "conf=%.2f os='%s'",
             ctx->banner_valid,
             ctx->banner_count,
             ctx->banner_confidence,
             ctx->banner_os_name);
}

/* ────────────────────────────────────────────────────────────
   Main Parallel Orchestrator
   ──────────────────────────────────────────────────────────── */
int np_pipeline_run_parallel_stages(np_pipeline_ctx_t *ctx)
{
    if (!ctx)
        return -1;

    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "Launching parallel FP match + banner grab");

    /* ── Allocate thread-local result structs ── */
    np_parallel_fp_result_t     fp_res;
    np_parallel_banner_result_t ban_res;

    memset(&fp_res,  0, sizeof(fp_res));
    memset(&ban_res, 0, sizeof(ban_res));

    /* ── Prepare thread arguments ── */
    np_fp_thread_arg_t fp_arg = {
        .ctx = ctx,
        .out = &fp_res
    };

    np_banner_thread_arg_t ban_arg = {
        .ctx = ctx,
        .out = &ban_res
    };

    /* ── Spawn threads ── */
    pthread_t fp_thread, banner_thread;
    int fp_rc, ban_rc;

    fp_rc = pthread_create(
        &fp_thread, NULL,
        np_parallel_fp_match_worker, &fp_arg);

    ban_rc = pthread_create(
        &banner_thread, NULL,
        np_parallel_banner_grab_worker, &ban_arg);

    if (fp_rc != 0)
    {
        pipe_log(NP_PIPE_LOG_ERR, LOG_STAGE,
                 "Failed to create FP thread: %d", fp_rc);
    }

    if (ban_rc != 0)
    {
        pipe_log(NP_PIPE_LOG_ERR, LOG_STAGE,
                 "Failed to create banner thread: %d",
                 ban_rc);
    }

    /* ── Join threads ── */
    if (fp_rc == 0)
    {
        pthread_join(fp_thread, NULL);
        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "FP thread joined");
    }

    if (ban_rc == 0)
    {
        pthread_join(banner_thread, NULL);
        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "Banner thread joined");
    }

    /* ── Fallback: run sequentially if thread failed ── */
    if (fp_rc != 0)
    {
        pipe_log(NP_PIPE_LOG_WARN, LOG_STAGE,
                 "FP thread failed — running sequentially");
        stage_fingerprint_match(ctx);
        fp_res.valid           = ctx->fp_valid;
        fp_res.score           = ctx->fp_score;
        fp_res.candidate_count = ctx->candidate_count;
    }

    if (ban_rc != 0)
    {
        pipe_log(NP_PIPE_LOG_WARN, LOG_STAGE,
                 "Banner thread failed — running "
                 "sequentially");
        stage_banner_collect(ctx);
        stage_banner_grab(ctx);

        ban_res.banner_count =
            (int)ctx->os_result.banner_count;
        ban_res.valid = (ban_res.banner_count > 0);

        if (ban_res.banner_count > 0)
        {
            memcpy(ban_res.banners,
                   ctx->os_result.banners,
                   ban_res.banner_count
                       * sizeof(np_os_banner_t));
        }
    }

    /* ── Merge results back into ctx ── */
    np_parallel_merge_fp_result(ctx, &fp_res);
    np_parallel_merge_banner_result(ctx, &ban_res);

    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "Parallel stages complete: "
             "fp_valid=%d banner_valid=%d",
             ctx->fp_valid,
             ctx->banner_valid);

    return 0;
}
