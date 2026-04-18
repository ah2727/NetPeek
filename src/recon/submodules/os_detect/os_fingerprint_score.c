#include "os_fingerprint_score.h"
#include "core/error.h"
#include "os_signatures.h"
#include "recon/submodules/os_detect/os_detect.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ──────────────────────────────────────────────────────
 *  Weight system
 * ────────────────────────────────────────────────────── */
#define W_OPT_ORDER 25
#define W_RESPONSE_PAT 20
#define W_WSCALE 12
#define W_TTL 10
#define W_WINDOW 10
#define W_MSS 8
#define W_DF 5
#define W_SACK 5
#define W_TIMESTAMP 5

#define TOTAL_WEIGHT                                   \
    (W_OPT_ORDER + W_RESPONSE_PAT + W_WSCALE + W_TTL + \
     W_WINDOW + W_MSS + W_DF + W_SACK + W_TIMESTAMP)

#define PROXY_SCORE_CAP 80
#define PROXY_PENALTY 15
#define MIN_MATCH_SCORE  10

/* ── TTL normalization ───────────────────────────────── */

static uint8_t normalize_ttl(uint8_t ttl)
{
    if (ttl <= 32)
        return 32;
    if (ttl <= 64)
        return 64;
    if (ttl <= 128)
        return 128;
    return 255;
}

/* ── option-order scoring ────────────────────────────── */

static uint8_t kind_to_char(uint8_t k)
{
    switch (k)
    {
    case 2:
        return 'M';
    case 3:
        return 'W';
    case 4:
        return 'S';
    case 8:
        return 'T';
    case 1:
        return 'N';
    case 0:
        return 'E';
    default:
        return k; /* already a char or unknown */
    }
}

static uint8_t score_option_order(
    const uint8_t *obs, uint8_t obs_cnt,
    const uint8_t *exp, uint8_t exp_cnt)
{
    if (!obs || !exp || obs_cnt == 0 || exp_cnt == 0)
        return 0;

    /* Normalize expected (signature) options to char form */
    uint8_t exp_norm[32];
    uint8_t exp_norm_cnt = 0;
    for (uint8_t i = 0; i < exp_cnt && i < sizeof(exp_norm); i++)
    {
        uint8_t c = kind_to_char(exp[i]);
        if (c)
            exp_norm[exp_norm_cnt++] = c;
    }

    if (obs_cnt != exp_norm_cnt)
        return 40;

    if (memcmp(obs, exp_norm, obs_cnt) == 0)
        return 100;

    uint8_t shared = 0;
    for (uint8_t i = 0; i < obs_cnt; i++)
        for (uint8_t j = 0; j < exp_norm_cnt; j++)
            if (obs[i] == exp_norm[j])
            {
                shared++;
                break;
            }

    if (shared == obs_cnt)
        return 60;

    return (uint8_t)((shared * 30) / obs_cnt);
}

/* ── response pattern scoring ───────────────────────── */

static uint8_t score_response_pattern(
    const char *obs,
    const char *exp)
{
    if (!obs || !exp)
        return 0;

    size_t olen = strlen(obs);
    size_t elen = strlen(exp);
    if (olen == 0 || elen == 0)
        return 0;

    size_t len = olen < elen ? olen : elen;
    size_t max = olen > elen ? olen : elen;

    uint8_t m = 0;
    for (size_t i = 0; i < len; i++)
        if (obs[i] == exp[i])
            m++;

    return (uint8_t)((m * 100) / max);
}

/* ── window scale scoring ───────────────────────────── */

static uint8_t score_window_scale(int obs, int sig)
{
    if (sig < 0)
        return 0;
    if (obs == sig)
        return 100;
    if (abs(obs - sig) == 1)
        return 50;
    return 0;
}

/* ── fingerprint scoring ────────────────────────────── */
uint8_t np_fingerprint_score(
    const np_os_fingerprint_t *fp,
    const np_os_fp_sig_t      *sig,
    np_score_detail_t         *detail)
{
    if (!fp || !sig)
        return 0;

    /* ── Probe response gate ── */
    int responded = 0;
    for (int i = 0; i < 7; i++)
    {
        if (fp->probe_responded[i])
            responded++;
    }

    if (responded < 4)
        return 0;

    np_score_detail_t d;
    memset(&d, 0, sizeof(d));

    /* ═══════════════════════════════════════════════════
     *  Per-field scoring (each yields 0–100)
     * ═══════════════════════════════════════════════════ */

    /* TCP option order */
    d.opt_order_score = score_option_order(
        fp->tcp_options_order, fp->tcp_options_count,
        (const uint8_t *)sig->tcp_options, sig->tcp_opt_count);

    /* Response pattern */
    d.response_pat_score = score_response_pattern(
        fp->response_pattern,
        sig->response_pattern);

    /* Window scale */
    d.wscale_score = score_window_scale(
        fp->window_scale,
        sig->window_scale);

    /* TTL */
    d.ttl_score =
        normalize_ttl(fp->ttl) == normalize_ttl(sig->ttl)
            ? 100
            : 0;

    /* Window size */
    if (sig->window_size > 0)
    {
        uint32_t diff = (uint32_t)abs((int)fp->window_size -
                                      (int)sig->window_size);
        d.window_score =
            diff == 0                                     ? 100
            : diff <= (uint32_t)sig->window_size / 10     ?  50
                                                          :   0;
    }

    /* MSS */
    if (sig->mss > 0)
        d.mss_score = (fp->mss == (uint16_t)sig->mss) ? 100 : 0;

    /* DF bit */
    if (sig->df_bit >= 0)
        d.df_score = (fp->df_bit == sig->df_bit) ? 100 : 0;

    /* SACK permitted */
    if (sig->sack_permitted >= 0)
        d.sack_score =
            (fp->sack_permitted == sig->sack_permitted) ? 100 : 0;

    /* Timestamp */
    if (sig->timestamp >= 0)
        d.timestamp_score =
            (fp->timestamp == sig->timestamp) ? 100 : 0;

    /* ═══════════════════════════════════════════════════
     *  Dynamic weighted sum — only fields that exist
     *  in the signature contribute to max_weight
     * ═══════════════════════════════════════════════════ */
    int earned     = 0;
    int max_weight = 0;

    /* Option order: only if sig has options defined */
    if (sig->tcp_opt_count > 0)
    {
        earned     += d.opt_order_score * W_OPT_ORDER;
        max_weight += W_OPT_ORDER;
    }

    /* Response pattern: only if sig specifies one */
    if (sig->response_pattern &&
        strlen(sig->response_pattern) > 0)
    {
        earned     += d.response_pat_score * W_RESPONSE_PAT;
        max_weight += W_RESPONSE_PAT;
    }

    /* TTL: always present in any TCP response */
    earned     += d.ttl_score * W_TTL;
    max_weight += W_TTL;

    if (sig->window_size > 0)
    {
        earned     += d.window_score * W_WINDOW;
        max_weight += W_WINDOW;
    }

    if (sig->mss > 0)
    {
        earned     += d.mss_score * W_MSS;
        max_weight += W_MSS;
    }

    if (sig->window_scale >= 0)
    {
        earned     += d.wscale_score * W_WSCALE;
        max_weight += W_WSCALE;
    }

    if (sig->df_bit >= 0)
    {
        earned     += d.df_score * W_DF;
        max_weight += W_DF;
    }

    if (sig->sack_permitted >= 0)
    {
        earned     += d.sack_score * W_SACK;
        max_weight += W_SACK;
    }

    if (sig->timestamp >= 0)
    {
        earned     += d.timestamp_score * W_TIMESTAMP;
        max_weight += W_TIMESTAMP;
    }

    if (max_weight == 0)
        max_weight = 1;

    /* ═══════════════════════════════════════════════════
     *  Penalties — percentage-based deductions for
     *  missing/poor fingerprint data quality
     * ═══════════════════════════════════════════════════ */
    int penalty_pct = 0;

    if (fp->tcp_options_count == 0)
        penalty_pct += 20;

    if (fp->ipid_behavior == IPID_UNKNOWN)
        penalty_pct += 15;

    if (fp->ttl == 0)
        penalty_pct += 15;

    if (!fp->response_pattern ||
        strlen(fp->response_pattern) < 4)
        penalty_pct += 10;

    if (penalty_pct > 0)
    {
        earned = earned * (100 - penalty_pct) / 100;
        if (earned < 0)
            earned = 0;
    }

    /* ═══════════════════════════════════════════════════
     *  Normalize to 0–100
     * ═══════════════════════════════════════════════════ */
    d.normalized = (uint8_t)(max_weight > 0
                                 ? (earned / max_weight)
                                 : 0);

    /* ═══════════════════════════════════════════════════
     *  FIX B: Do NOT scale final_score by sig->weight.
     *
     *  The Nmap weight field (typically 55) is a
     *  signature QUALITY/PRIORITY indicator, not a
     *  score multiplier. Applying it as a multiplier
     *  crushes all scores:
     *
     *    norm=47 × (55/100) = 25  ← WRONG
     *
     *  This causes every family to tie at the same
     *  reduced score, destroying discriminating power.
     *
     *  Instead, weight is used for TIE-BREAKING in
     *  np_sigdb_match_fp() when two sigs from the
     *  same family have identical scores.
     * ═══════════════════════════════════════════════════ */
    d.final_score = d.normalized;


    /* ═══════════════════════════════════════════════════
     *  DEBUG — remove after diagnosis
     * ═══════════════════════════════════════════════════ */
    // if (sig->os_name)
    // {
    //     np_error(NP_ERR_RUNTIME, //             "[SCORE-DBG] os='%.40s' earned=%d max_w=%d penalty=%d%% "
    //             "norm=%u final=%u (weight=%d, NOT applied) "
    //             "ttl=%u opt=%u resp=%u wscale=%u win=%u df=%u sack=%u ts=%u\n",
    //             sig->os_name, earned, max_weight, penalty_pct,
    //             d.normalized, d.final_score, sig->weight,
    //             d.ttl_score, d.opt_order_score, d.response_pat_score,
    //             d.wscale_score, d.window_score, d.df_score,
    //             d.sack_score, d.timestamp_score);
    // }
    /* ═══════════════════════════════════════════════════
     *  END DEBUG
     * ═══════════════════════════════════════════════════ */

    /* ═══════════════════════════════════════════════════
     *  Proxy environment cap — still valid because
     *  proxied traffic genuinely reduces accuracy
     * ═══════════════════════════════════════════════════ */
    if (fp->env_flags & NP_ENV_PROXY)
    {
        if (d.final_score > PROXY_SCORE_CAP)
            d.final_score = PROXY_SCORE_CAP;
        d.final_score =
            d.final_score > PROXY_PENALTY
                ? d.final_score - PROXY_PENALTY
                : 0;
    }

    /* ═══════════════════════════════════════════════════
     *  Known-false-positive clamp — 2.11BSD matches
     *  everything because its TCP stack is primitive
     * ═══════════════════════════════════════════════════ */
    if (sig->os_name &&
        strstr(sig->os_name, "2.11BSD") &&
        d.final_score > 55)
    {
        d.final_score = 55;
    }

    /* ═══════════════════════════════════════════════════
     *  Hard floor — scores below this are noise
     *
     *  Lowered from 45 → 10 because with weight
     *  no longer crushing scores, real matches
     *  should land in the 30–70 range. A floor of
     *  10 filters only true garbage.
     * ═══════════════════════════════════════════════════ */
    if (d.final_score < MIN_MATCH_SCORE)
        d.final_score = 0;

    if (detail)
        *detail = d;

    return d.final_score;
}
