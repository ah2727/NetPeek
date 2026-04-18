/* os_fingerprint.h */
#ifndef OS_FINGERPRINT_H
#define OS_FINGERPRINT_H

#include <stdint.h>
#include <stddef.h>

/* ---------- OS signature entry (used by os_signatures.c) ---------- */
typedef struct {
    const char *os_name;
    int         ttl_low;
    int         ttl_high;
    uint16_t    win_low;
    uint16_t    win_high;
    uint16_t    mss_expected;   /* 0 = don't care */
    int         df_expected;    /* -1 = don't care */
    int         sack_expected;  /* -1 = don't care */
} np_os_signature_t;

/* ---------- Public API: os_fingerprint.c ---------- */
/*
 * Uses np_os_fingerprint_t from os_detect.h.
 * Forward-declare it here so callers that only need the
 * fingerprint function don't have to pull in all of os_detect.h.
 */
struct np_os_fingerprint;

/* ---------- Public API: os_signatures.c ---------- */
const char *np_match_fingerprint(const void *fp,
                                 double *out_confidence);

/* ---------- Public API: os_banner.c ---------- */
const char *np_match_banner(const void *banner,
                            double *out_confidence);

/* ---------- Utility ---------- */
uint8_t     np_os_normalize_ttl(uint8_t ttl);

#endif /* OS_FINGERPRINT_H */
