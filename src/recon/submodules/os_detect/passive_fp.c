#include "passive_fp.h"

#include <string.h>

static uint8_t infer_ttl_bucket(uint8_t ttl)
{
    if (ttl <= 32)
        return 32;
    if (ttl <= 64)
        return 64;
    if (ttl <= 128)
        return 128;
    return 255;
}

void np_passive_fp_init(np_passive_fp_accum_t *acc)
{
    if (!acc)
        return;
    memset(acc, 0, sizeof(*acc));
}

void np_passive_fp_observe(np_passive_fp_accum_t *acc,
                           uint8_t ttl,
                           uint16_t window,
                           bool df,
                           uint16_t ipid,
                           uint16_t mss,
                           uint8_t wscale,
                           bool sack,
                           bool ts,
                           bool synack_only)
{
    if (!acc || !synack_only)
        return;

    acc->evidence_count++;
    switch (infer_ttl_bucket(ttl)) {
        case 32: acc->ttl32++; break;
        case 64: acc->ttl64++; break;
        case 128: acc->ttl128++; break;
        default: acc->ttl255++; break;
    }

    if (df)
        acc->df_yes++;
    else
        acc->df_no++;

    if (ipid == 0) {
        acc->ipid_zero++;
    } else if (acc->have_last_ipid) {
        uint16_t d = (uint16_t)(ipid - acc->last_ipid);
        if (d > 0 && d < 1024)
            acc->ipid_seq++;
        else
            acc->ipid_rand++;
    }

    acc->last_ipid = ipid;
    acc->have_last_ipid = true;
    acc->last_window = window;
    acc->win_samples++;
    acc->last_mss = mss;
    acc->last_wscale = wscale;
    acc->last_sack = sack;
    acc->last_ts = ts;
}

static void set_guess(np_os_result_t *out,
                      const char *name,
                      double conf,
                      bool low)
{
    if (!out)
        return;
    strncpy(out->os_guess_passive, name, sizeof(out->os_guess_passive) - 1);
    out->os_guess_passive[sizeof(out->os_guess_passive) - 1] = '\0';
    out->passive_confidence = conf;
    out->passive_low_confidence = low;
}

void np_passive_fp_finalize(const np_passive_fp_accum_t *acc,
                            bool include_low_confidence,
                            np_os_result_t *out)
{
    if (!acc || !out)
        return;

    out->passive_evidence_count = acc->evidence_count;
    out->os_guess_passive[0] = '\0';
    out->passive_confidence = 0.0;
    out->passive_low_confidence = false;

    if (acc->evidence_count == 0)
        return;

    if (acc->ttl128 > 0) {
        if (acc->last_window == 65535 || acc->last_window == 64240) {
            set_guess(out, "Windows 10/11", 76.0, false);
            return;
        }
        set_guess(out, "Windows", 62.0, false);
        return;
    }

    if (acc->ttl64 > 0) {
        if (acc->ipid_zero > 0 && acc->last_ts && acc->last_wscale >= 7) {
            set_guess(out, "Linux", 72.0, false);
            return;
        }
        if (acc->last_window == 65535 && acc->last_ts && acc->df_yes >= acc->df_no) {
            set_guess(out, "macOS", 61.0, true);
            if (!include_low_confidence)
                out->os_guess_passive[0] = '\0';
            return;
        }
        if (acc->last_window == 65535 && !acc->last_ts) {
            set_guess(out, "FreeBSD", 58.0, true);
            if (!include_low_confidence)
                out->os_guess_passive[0] = '\0';
            return;
        }
        set_guess(out, "Linux/Unix", 45.0, true);
        if (!include_low_confidence)
            out->os_guess_passive[0] = '\0';
        return;
    }

    if (acc->ttl255 > 0) {
        set_guess(out, "Network Device/Embedded", 48.0, true);
        if (!include_low_confidence)
            out->os_guess_passive[0] = '\0';
    }
}

