#ifndef NP_PASSIVE_FP_H
#define NP_PASSIVE_FP_H

#include <stdbool.h>
#include <stdint.h>

#include "netpeek.h"

typedef struct
{
    uint32_t evidence_count;

    uint32_t ttl32;
    uint32_t ttl64;
    uint32_t ttl128;
    uint32_t ttl255;

    uint32_t df_yes;
    uint32_t df_no;

    uint32_t ipid_zero;
    uint32_t ipid_seq;
    uint32_t ipid_rand;

    uint16_t last_ipid;
    bool have_last_ipid;

    uint16_t last_window;
    uint32_t win_samples;

    uint16_t last_mss;
    uint8_t last_wscale;
    bool last_sack;
    bool last_ts;
} np_passive_fp_accum_t;

void np_passive_fp_init(np_passive_fp_accum_t *acc);

void np_passive_fp_observe(np_passive_fp_accum_t *acc,
                           uint8_t ttl,
                           uint16_t window,
                           bool df,
                           uint16_t ipid,
                           uint16_t mss,
                           uint8_t wscale,
                           bool sack,
                           bool ts,
                           bool synack_only);

void np_passive_fp_finalize(const np_passive_fp_accum_t *acc,
                            bool include_low_confidence,
                            np_os_result_t *out);

#endif
