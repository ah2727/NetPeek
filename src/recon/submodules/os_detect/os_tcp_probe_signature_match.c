/*
 * NetPeek - TCP Probe Behavioral Signature Matching
 *
 * Compares T1–T7 probe responses with OS behavioral signatures.
 */

#include "os_tcp_probes.h"
#include "os_signatures.h"

#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------- */
/* behavioral signature structure                       */
/* ---------------------------------------------------- */

typedef struct
{
    const char *os_name;

    bool t1_response;
    bool t2_response;
    bool t3_response;
    bool t4_response;
    bool t5_response;
    bool t6_response;
    bool t7_response;

    uint8_t t1_flags;
    uint8_t t3_flags;
    uint8_t t4_flags;

    /* Apple discriminators */
    bool require_timestamps;
    bool require_window_scale;
    bool forbid_rst_flood;

} np_tcp_behavior_sig_t;

/* ---------------------------------------------------- */
/* built‑in behavior signatures                         */
/* ---------------------------------------------------- */

static const np_tcp_behavior_sig_t behavior_sigs[] = {

    /* ✅ Apple iOS / macOS — MUST be first */
    {
        "Apple iOS / macOS",

        true, false, true, true, true, true, false,
        0x12, 0x14, 0x14,

        true,  /* timestamps required */
        true,  /* window scale required */
        true   /* minimal RSTs */
    },

    /* FreeBSD */
    {
        "FreeBSD",

        true, false, true, true, true, true, false,
        0x12, 0x14, 0x14,

        false,
        false,
        false
    },

    /* Linux */
    {
        "Linux",

        true, false, true, true, true, true, false,
        0x12, 0x14, 0x14,

        false,
        false,
        false
    },

    /* Windows */
    {
        "Windows",

        true, false, true, true, true, true, false,
        0x12, 0x14, 0x14,

        false,
        false,
        false
    }
};

static const uint32_t behavior_sig_count =
    sizeof(behavior_sigs) / sizeof(behavior_sigs[0]);

/* ---------------------------------------------------- */
/* probe response helper                                */
/* ---------------------------------------------------- */

static int probe_match(bool observed, bool expected)
{
    return (observed == expected);
}

/* ---------------------------------------------------- */
/* flags compare                                        */
/* ---------------------------------------------------- */

static int flag_match(uint8_t observed, uint8_t expected)
{
    if (expected == 0)
        return 1;

    return ((observed & expected) == expected);
}

/* ---------------------------------------------------- */
/* aggregate probe traits (NO STRUCT CHANGES)           */
/* ---------------------------------------------------- */

static void aggregate_probe_traits(
    const np_tcp_probe_set_t *set,
    bool *ts_present,
    bool *ws_present,
    int *rst_count)
{
    *ts_present = false;
    *ws_present = false;
    *rst_count = 0;

    for (int i = 0; i < NP_MAX_TCP_PROBES; i++)
    {
        const np_tcp_probe_result_t *p = &set->probes[i];

        if (!p->responded)
            continue;

        if (p->timestamp)
            *ts_present = true;

        if (p->wscale > 0)
            *ws_present = true;

        if (p->rst)
            (*rst_count)++;
    }
}

/* ---------------------------------------------------- */
/* compute behavior score                               */
/* ---------------------------------------------------- */

uint8_t np_tcp_behavior_score(
    const np_tcp_probe_set_t *set,
    const np_tcp_behavior_sig_t *sig)
{
    int score = 0;
    int max = 0;

    const np_tcp_probe_result_t *p;

    /* T1 */
    p = &set->probes[0];
    max += 2;
    if (probe_match(p->responded, sig->t1_response))
        score++;
    if (p->responded && flag_match(p->tcp_flags, sig->t1_flags))
        score++;

    /* T2 */
    p = &set->probes[1];
    max += 1;
    if (probe_match(p->responded, sig->t2_response))
        score++;

    /* T3 */
    p = &set->probes[2];
    max += 2;
    if (probe_match(p->responded, sig->t3_response))
        score++;
    if (p->responded && flag_match(p->tcp_flags, sig->t3_flags))
        score++;

    /* T4 */
    p = &set->probes[3];
    max += 2;
    if (probe_match(p->responded, sig->t4_response))
        score++;
    if (p->responded && flag_match(p->tcp_flags, sig->t4_flags))
        score++;

    /* T5 */
    p = &set->probes[4];
    max += 1;
    if (probe_match(p->responded, sig->t5_response))
        score++;

    /* T6 */
    p = &set->probes[5];
    max += 1;
    if (probe_match(p->responded, sig->t6_response))
        score++;

    /* T7 */
    p = &set->probes[6];
    max += 1;
    if (probe_match(p->responded, sig->t7_response))
        score++;

    if (max == 0)
        return 0;

    /* ✅ Apple‑specific enforcement */
    bool ts_present, ws_present;
    int rst_count;

    aggregate_probe_traits(set, &ts_present, &ws_present, &rst_count);

    if (sig->require_timestamps && !ts_present)
        return 0;

    if (sig->require_window_scale && !ws_present)
        return 0;

    if (sig->forbid_rst_flood && rst_count > 1)
        return 0;

    return (uint8_t)((score * 100) / max);
}

/* ---------------------------------------------------- */
/* find best behavior signature                         */
/* ---------------------------------------------------- */

const char *np_tcp_behavior_match(
    const np_tcp_probe_set_t *set,
    uint8_t *out_score)
{
    uint8_t best = 0;
    const char *best_os = NULL;

    for (uint32_t i = 0; i < behavior_sig_count; i++)
    {
        uint8_t sc =
            np_tcp_behavior_score(set, &behavior_sigs[i]);

        if (sc > best)
        {
            best = sc;
            best_os = behavior_sigs[i].os_name;
        }
    }

    if (out_score)
        *out_score = best;

    return best_os;
}
