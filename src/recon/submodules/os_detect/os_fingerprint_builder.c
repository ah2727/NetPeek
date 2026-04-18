/*
 * NetPeek - OS Fingerprint Builder (Nmap-aligned, FIXED)
 *
 * Fixes:
 *  - IPID behavior misclassification
 *  - TTL entropy collapse
 *  - TCP option source selection
 *  - Timestamp rate distortion
 *  - Reliability inflation
 *
 * Guarantees:
 *  - No NULL dereference
 *  - No underflow / overflow
 *  - Deterministic output
 */

#include "recon/submodules/os_detect/os_detect.h"
#include "os_tcp_probes.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* ---------------------------------------------------- */
/* TCP option kind → character (Nmap compatible)        */
/* ---------------------------------------------------- */
static uint8_t option_char(uint8_t kind)
{
    switch (kind)
    {
        case 2: return 'M'; /* MSS */
        case 3: return 'W'; /* Window Scale */
        case 4: return 'S'; /* SACK permitted */
        case 8: return 'T'; /* Timestamp */
        case 1: return 'N'; /* NOP */
        case 0: return 'E'; /* EOL */
        default: return 0;
    }
}

/* ---------------------------------------------------- */
/* Extract TCP option order                             */
/* ---------------------------------------------------- */
static uint8_t extract_option_order(
    const uint8_t *opts,
    uint32_t opts_len,
    uint8_t *order_buf,
    uint8_t order_buf_sz)
{
    uint32_t i = 0;
    uint8_t idx = 0;

    if (!opts || opts_len == 0 || order_buf_sz < 2)
        return 0;

    while (i < opts_len && idx < order_buf_sz - 1)
    {
        uint8_t kind = opts[i];

        if (kind == 0) /* EOL */
        {
            order_buf[idx++] = 'E';
            break;
        }

        if (kind == 1) /* NOP */
        {
            order_buf[idx++] = 'N';
            i++;
            continue;
        }

        if (i + 1 >= opts_len)
            break;

        uint8_t len = opts[i + 1];
        if (len < 2 || i + len > opts_len)
            break;

        uint8_t c = option_char(kind);
        if (c)
            order_buf[idx++] = c;

        i += len;
    }

    order_buf[idx] = '\0';
    return idx;
}

/* ---------------------------------------------------- */
/* TTL normalization helper (Nmap-style)                */
/* ---------------------------------------------------- */
static uint8_t guess_initial_ttl(uint8_t ttl)
{
    if (ttl <= 32)  return 32;
    if (ttl <= 64)  return 64;
    if (ttl <= 128) return 128;
    return 255;
}

/* ---------------------------------------------------- */
/* MAIN ENTRY POINT                                     */
/* ---------------------------------------------------- */
int np_build_fingerprint_from_probes(
    const np_tcp_probe_set_t *set,
    np_os_fingerprint_t *fp)
{
    if (!set || !fp)
        return -1;

    memset(fp, 0, sizeof(*fp));

    /* ------------------------------------------------ */
    /* Step 1: Per-probe recording                      */
    /* ------------------------------------------------ */
    for (int i = 0; i < NP_MAX_TCP_PROBES; i++)
    {
        const np_tcp_probe_result_t *p = &set->probes[i];

        fp->probe_responded[i] = p->responded;

        if (!p->responded)
            continue;

        fp->probes_responded++;

        fp->probe_window[i] = p->window;
        fp->probe_ttl[i]    = p->ttl;
        fp->probe_df[i]     = p->df;
        fp->probe_rst[i]    = p->rst;
        fp->probe_ack[i]    = p->ack;

        /* First responding probe defines baseline */
        if (fp->ttl_initial == 0)
        {
            fp->ttl_initial = guess_initial_ttl(p->ttl);
            fp->ttl         = p->ttl;

            fp->ttl_hop_dist =
                (fp->ttl_initial >= p->ttl)
                ? (fp->ttl_initial - p->ttl)
                : 0;

            fp->window_size    = p->window;
            fp->df_bit         = p->df;
            fp->mss            = p->mss;
            fp->window_scale   = p->wscale;
            fp->sack_permitted = p->sack;
            fp->timestamp      = p->timestamp;
        }
    }

    /* ------------------------------------------------ */
    /* Step 2: Merge fields (DO NOT flatten TTL)        */
    /* ------------------------------------------------ */
    for (int i = 0; i < NP_MAX_TCP_PROBES; i++)
    {
        const np_tcp_probe_result_t *p = &set->probes[i];
        if (!p->responded)
            continue;

        if (p->mss && !fp->mss)
            fp->mss = p->mss;

        if (p->wscale && !fp->window_scale)
            fp->window_scale = p->wscale;

        if (p->sack)
            fp->sack_permitted = 1;

        if (p->timestamp)
            fp->timestamp = 1;
    }

    /* ------------------------------------------------ */
    /* Step 3: IPID behavior (FIXED)                    */
    /* ------------------------------------------------ */
    uint16_t last_id = 0;
    int id_samples = 0;
    int id_changes = 0;
    int id_increments = 0;

    for (int i = 0; i < NP_MAX_TCP_PROBES; i++)
    {
        const np_tcp_probe_result_t *p = &set->probes[i];
        if (!p->responded)
            continue;

        if (last_id != 0)
        {
            id_samples++;

            if (p->ip_id != last_id)
                id_changes++;

            if ((uint16_t)(p->ip_id - last_id) == 1)
                id_increments++;
        }

        last_id = p->ip_id;
    }

    if (id_samples < 2)
        fp->ipid_behavior = IPID_UNKNOWN;
    else if (id_changes == 0)
        fp->ipid_behavior = IPID_CONSTANT;
    else if (id_increments == id_samples)
        fp->ipid_behavior = IPID_INCREMENTAL;
    else
        fp->ipid_behavior = IPID_RANDOM;

    /* ------------------------------------------------ */
    /* Step 4: TCP timestamp clock rate                 */
    /* ------------------------------------------------ */
    uint32_t last_ts = 0;
    uint64_t sum = 0;
    int samples = 0;

    for (int i = 0; i < NP_MAX_TCP_PROBES; i++)
    {
        const np_tcp_probe_result_t *p = &set->probes[i];
        if (!p->responded || !p->timestamp)
            continue;

        if (last_ts && p->tsval > last_ts)
        {
            sum += (p->tsval - last_ts);
            samples++;
        }

        last_ts = p->tsval;
    }

    fp->ts_rate = samples ? (uint32_t)(sum / samples) : 0;

    /* ------------------------------------------------ */
    /* Step 5: Response pattern                         */
    /* ------------------------------------------------ */
    snprintf(fp->response_pattern,
             sizeof(fp->response_pattern),
             "%c%c%c%c%c%c%c",
             fp->probe_responded[0] ? 'R' : 'N',
             fp->probe_responded[1] ? 'R' : 'N',
             fp->probe_responded[2] ? 'R' : 'N',
             fp->probe_responded[3] ? 'R' : 'N',
             fp->probe_responded[4] ? 'R' : 'N',
             fp->probe_responded[5] ? 'R' : 'N',
             fp->probe_responded[6] ? 'R' : 'N');

    /* ------------------------------------------------ */
    /* Step 6: TCP option order (FIXED priority)        */
    /* ------------------------------------------------ */
    const np_tcp_probe_result_t *opt_src = NULL;
    int priority[] = { 0, 1, 2, 3, 4, 5, 6 };

    for (int k = 0; k < 7; k++)
    {
        int i = priority[k];
        if (set->probes[i].responded &&
            set->probes[i].opts_len > 0)
        {
            opt_src = &set->probes[i];
            break;
        }
    }

    if (opt_src)
    {
        fp->tcp_options_count =
            extract_option_order(
                opt_src->opts_raw,
                opt_src->opts_len,
                fp->tcp_options_order,
                sizeof(fp->tcp_options_order));

        fp->opt_rewritten = 0;
    }
    else
    {
        fp->tcp_options_order[0] = '\0';
        fp->tcp_options_count = 0;
        fp->opt_rewritten = 1;
    }

    /* ------------------------------------------------ */
    /* Step 7: Reliability (FIXED)                      */
    /* ------------------------------------------------ */
    fp->reliability = 100;

    if (fp->probes_responded < 3)
        fp->reliability = 30;
    else
    {
        if (fp->probes_responded < NP_MAX_TCP_PROBES)
            fp->reliability -= 20;

        if (fp->tcp_options_count == 0)
            fp->reliability -= 15;

        if (fp->opt_rewritten)
            fp->reliability -= 10;
    }

    if ((int)fp->reliability < 0)
        fp->reliability = 0;

    return 0;
}
