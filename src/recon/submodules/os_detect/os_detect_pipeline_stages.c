/*
 * os_detect_pipeline_stages.c
 *
 * FIXED VERSION
 *  - Proper no-match handling
 *  - TTL gating
 *  - No garbage device matches
 *  - Nmap-like scoring behavior
 *  - All logging gated behind verbose flag
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#include "recon/submodules/os_detect/os_detect.h"
#include "recon/submodules/os_detect/os_detect_pipeline.h"
#include "recon/submodules/os_detect/os_tcp_probes.h"
#include "recon/submodules/os_detect/os_fingerprint_types.h"
#include "recon/submodules/os_detect/os_signatures.h"
#include "recon/submodules/os_detect/os_sigload.h"
#include "logger.h"

/* ------------------------------------------------------------ */
/* Pipeline-internal logging (gated by verbose)                 */
/* ------------------------------------------------------------ */

typedef enum
{
    NP_PIPE_LOG_INFO  = 0,
    NP_PIPE_LOG_WARN  = 1,
    NP_PIPE_LOG_ERR   = 2,
    NP_PIPE_LOG_DEBUG = 3
} np_pipe_log_level_t;

static const char *log_level_str[] = {
    "INFO", "WARN", "ERR ", "DBG "
};

static void pipe_log(np_pipe_log_level_t level, const char *stage,
                     const char *fmt, ...)
{
    /* Errors always print; everything else only in verbose mode */
    if (level != NP_PIPE_LOG_ERR && !np_logger_is_verbose())
        return;

    if (level < NP_PIPE_LOG_INFO || level > NP_PIPE_LOG_DEBUG)
        level = NP_PIPE_LOG_INFO;

    va_list ap;
    va_start(ap, fmt);
    np_error(NP_ERR_RUNTIME, "[netpeek][pipeline][%s][%s] ",
            log_level_str[level], stage);
    np_verror(NP_ERR_RUNTIME, fmt, ap);
    np_error(NP_ERR_RUNTIME, "\n");
    va_end(ap);
}

/* ── Convenience macros that replace the old raw printf ones ── */
#define PIPE_INFO(tag, fmt, ...) \
    pipe_log(NP_PIPE_LOG_INFO, tag, fmt, ##__VA_ARGS__)

#define PIPE_DBG(tag, fmt, ...) \
    pipe_log(NP_PIPE_LOG_DEBUG, tag, fmt, ##__VA_ARGS__)

#define PIPE_WARN(tag, fmt, ...) \
    pipe_log(NP_PIPE_LOG_WARN, tag, fmt, ##__VA_ARGS__)

#define PIPE_ERR(tag, fmt, ...) \
    pipe_log(NP_PIPE_LOG_ERR, tag, fmt, ##__VA_ARGS__)

/* ── Old macros replaced ── */
#define LOGI(fmt, ...) PIPE_INFO("pipeline", fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) PIPE_DBG("pipeline",  fmt, ##__VA_ARGS__)
#define LOGR(fmt, ...) PIPE_DBG("rule",      fmt, ##__VA_ARGS__)
#define LOGV(fmt, ...) PIPE_DBG("diff",      fmt, ##__VA_ARGS__)

#define MIN_FP_MATCH_SCORE 40

/* ------------------------------------------------------------ */
/* TTL estimation                                               */
/* ------------------------------------------------------------ */

static uint8_t estimate_initial_ttl(uint8_t observed)
{
    static const uint8_t known[] = {32, 64, 128, 255};
    for (int i = 0; i < 4; ++i)
        if (observed <= known[i])
            return known[i];
    return 255;
}

/* ------------------------------------------------------------ */
/* Response pattern                                             */
/* ------------------------------------------------------------ */

static void build_response_pattern(
    const np_tcp_probe_set_t *set,
    char out[NP_MAX_TCP_PROBES + 1])
{
    for (int i = 0; i < NP_MAX_TCP_PROBES; ++i)
    {
        const np_tcp_probe_result_t *p = &set->probes[i];

        if (!p->responded)
            out[i] = 'N';
        else if (p->rst)
            out[i] = 'R';
        else if (p->ack)
            out[i] = 'A';
        else
            out[i] = 'S';
    }
    out[NP_MAX_TCP_PROBES] = '\0';
}

/* ============================================================ */
/* Stage 3 — Build fingerprint                                  */
/* ============================================================ */

int np_os_pipeline_build_fingerprint(
    const np_tcp_probe_set_t *probe_set,
    np_os_fingerprint_t *fp)
{
    LOGI("Stage 3: Building fingerprint");

    if (!probe_set || !fp)
        return -1;

    memset(fp, 0, sizeof(*fp));

    const np_tcp_probe_result_t *primary = NULL;

    for (int i = 0; i < NP_MAX_TCP_PROBES; ++i)
        if (probe_set->probes[i].responded)
        {
            primary = &probe_set->probes[i];
            break;
        }

    if (!primary)
    {
        LOGD("No responding probes");
        return -1;
    }

    fp->ttl            = primary->ttl;
    fp->ttl_initial    = estimate_initial_ttl(primary->ttl);
    fp->ttl_hop_dist   = fp->ttl_initial - fp->ttl;

    fp->window_size    = primary->window;
    fp->df_bit         = primary->df;
    fp->ip_id          = primary->ip_id;
    fp->mss            = primary->mss;
    fp->window_scale   = primary->wscale;
    fp->sack_permitted = primary->sack;
    fp->timestamp      = primary->timestamp;

    uint32_t optlen = primary->opts_len;
    if (optlen > NP_TCP_OPT_MAX)
        optlen = NP_TCP_OPT_MAX;

    memcpy(fp->tcp_options_order, primary->opts_raw, optlen);
    fp->tcp_options_count = optlen;

    int responded = 0;
    for (int i = 0; i < NP_MAX_TCP_PROBES; ++i)
        if (probe_set->probes[i].responded)
            responded++;

    fp->probes_responded = responded;
    build_response_pattern(probe_set, fp->response_pattern);

    fp->reliability =
        (uint8_t)((responded * 100) / NP_MAX_TCP_PROBES);

    LOGI("Fingerprint built (TTL=%u init=%u reliability=%u%%)",
         fp->ttl, fp->ttl_initial, fp->reliability);

    return 0;
}

/* ============================================================ */
/* Stage 4 — Fingerprint match                                  */
/* ============================================================ */

const np_os_fp_sig_t *
np_os_pipeline_fp_match(
    const np_os_fingerprint_t *fp,
    const np_os_sigdb_t *db,
    uint8_t *out_score)
{
    LOGI("Stage 4: Signature DB match");

    if (!fp || !db || !out_score || db->fp_count == 0)
    {
        if (out_score)
            *out_score = 0;
        return NULL;
    }

    const np_os_fp_sig_t *best = NULL;
    int32_t best_score = -9999;

    for (uint32_t i = 0; i < db->fp_count; ++i)
    {
        const np_os_fp_sig_t *sig = &db->fp_sigs[i];
        int32_t score = 0;

        /* ---------- TTL heuristic (soft) ---------- */
        int ttl_diff = abs((int)fp->ttl_initial - (int)sig->ttl);

        if (ttl_diff == 0)
        {
            score += 15;
            LOGR("[%s] TTL exact match +15", sig->os_name);
        }
        else if (ttl_diff <= 32)
        {
            score += 5;
            LOGR("[%s] TTL near match +5", sig->os_name);
        }
        else if (ttl_diff <= 64)
        {
            score -= 5;
            LOGR("[%s] TTL loose mismatch -5", sig->os_name);
        }
        else
        {
            score -= 15;
            LOGR("[%s] TTL implausible -15", sig->os_name);
        }

        /* ---------- Hop distance sanity ---------- */
        if (fp->ttl_hop_dist > 20)
        {
            score -= 5;
            LOGR("[%s] large hop distance -5", sig->os_name);
        }

        /* ---------- Structural score ---------- */
        score += np_os_fp_score(fp, sig);

        /* ---------- Response pattern (soft) ---------- */
        int match = 0;
        for (int j = 0; j < NP_MAX_TCP_PROBES; ++j)
            if (fp->response_pattern[j] ==
                sig->response_pattern[j])
                match++;

        score += (match * 10) / NP_MAX_TCP_PROBES;

        if (score > best_score)
        {
            best_score = score;
            best = sig;
        }
    }

    if (best_score < MIN_FP_MATCH_SCORE)
    {
        LOGI("No reliable OS fingerprint match (best=%d)",
             best_score);
        *out_score = 0;
        return NULL;
    }

    if (best_score > 255)
        best_score = 255;

    *out_score = (uint8_t)best_score;

    LOGI("Fingerprint match: %s (score=%d)",
         best->os_name, best_score);

    return best;
}

/* ============================================================ */
/* Top-level wrapper                                            */
/* ============================================================ */

int np_os_detect_pipeline(
    const char *target_ip,
    uint16_t port,
    const np_os_sigdb_t *db,
    np_os_result_t *out)
{
    LOGI("OS detection pipeline started");

    if (!target_ip || !db || !out)
        return -1;

    np_status_t st =
        np_os_detect_pipeline_run(target_ip, port, db, out);

    LOGI("OS detection pipeline finished");
    return (st == NP_OK) ? 0 : -1;
}
