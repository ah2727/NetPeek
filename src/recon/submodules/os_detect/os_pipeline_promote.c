/* ============================================================
   src/os_detect/os_pipeline_promote.c
   Banner and fingerprint promotion helpers (shared code)
   ============================================================ */
#include "os_pipeline_priv.h"
#include "recon/submodules/os_detect/os_detect_pipeline.h"
#include "logger.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#define LOG_STAGE "promote"

/* ────────────────────────────────────────────────────────────
   Promote best per-banner result into aggregate ctx fields
   (banner_valid, banner_os_name, banner_confidence).

   Reads from ctx->banners[] — caller must ensure that array
   is populated (either directly or via the bridge copy).
   ──────────────────────────────────────────────────────────── */
void pipeline_promote_banner_result(np_pipeline_ctx_t *ctx)
{
    if (!ctx)
        return;

    double best_conf = 0.0;
    int    best_idx  = -1;

    for (int i = 0; i < ctx->banner_count; i++)
    {
        double conf = (double)ctx->banners[i].os_hint_confidence;

        if (conf > best_conf)
        {
            best_conf = conf;
            best_idx  = i;
        }
    }

    if (best_idx >= 0 && best_conf > 0.0)
    {
        ctx->banner_valid      = true;
        ctx->banner_confidence = best_conf;

        if (ctx->banners[best_idx].os_hint[0])
        {
            strncpy(ctx->banner_os_name,
                    ctx->banners[best_idx].os_hint,
                    sizeof(ctx->banner_os_name) - 1);
            ctx->banner_os_name[sizeof(ctx->banner_os_name) - 1] = '\0';
        }
        else
        {
            snprintf(ctx->banner_os_name,
                     sizeof(ctx->banner_os_name),
                     "svc:%s (port %u)",
                     ctx->banners[best_idx].service[0]
                         ? ctx->banners[best_idx].service
                         : "unknown",
                     ctx->banners[best_idx].port);
        }

        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "Banner promotion: best_idx=%d port=%u "
                 "os='%s' conf=%.2f",
                 best_idx,
                 ctx->banners[best_idx].port,
                 ctx->banner_os_name,
                 ctx->banner_confidence);
    }
    else
    {
        ctx->banner_valid      = false;
        ctx->banner_confidence = 0.0;
        ctx->banner_os_name[0] = '\0';

        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "Banner promotion: no banners with "
                 "confidence > 0");
    }
}

/* ────────────────────────────────────────────────────────────
   Bridge: copy os_result.banners[] → ctx->banners[]
   so that promotion reads from the right place.
   ──────────────────────────────────────────────────────────── */
void pipeline_bridge_banner_results(np_pipeline_ctx_t *ctx)
{
    if (!ctx)
        return;

    ctx->banner_count = (int)ctx->os_result.banner_count;

    if (ctx->banner_count > NP_OS_MAX_BANNERS)
        ctx->banner_count = NP_OS_MAX_BANNERS;

    if (ctx->banner_count > 0)
    {
        memcpy(ctx->banners,
               ctx->os_result.banners,
               ctx->banner_count * sizeof(np_os_banner_t));
    }

    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "Bridge: copied %d banners from "
             "os_result → ctx",
             ctx->banner_count);
}
