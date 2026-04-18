#ifndef NP_OS_SIGLOAD_H
#define NP_OS_SIGLOAD_H

#include <stdint.h>
#include <stdbool.h>

#include "os_signatures.h"       /* np_os_fp_sig_t, np_os_banner_sig_t */
#include "os_fingerprint_types.h"   /* np_os_fingerprint_t */
#include "netpeek.h"
/*
 * Forward declarations — full definitions live in os_detect.h.
 * Only pointer usage here, so the compiler doesn't need the layout.
 */
struct np_os_result;


/* ── Loaded signature database ───────────────────────── */
typedef struct np_os_sigdb
{
    np_os_fp_sig_t     *fp_sigs;
    uint32_t            fp_count;
    uint32_t            fp_capacity;

    np_os_banner_sig_t *banner_sigs;
    uint32_t            banner_count;
    uint32_t            banner_capacity;

    /* string pool */
    char              **strings;
    uint32_t            string_count;
    uint32_t            string_capacity;

    bool                loaded;
} np_os_sigdb_t;


/* ── API ─────────────────────────────────────────────── */

void np_sigdb_init(np_os_sigdb_t *db);

void np_sigdb_free(np_os_sigdb_t *db);

int np_sigdb_load(np_os_sigdb_t *db, const char *path);

int np_sigdb_merge_builtin(np_os_sigdb_t *db);

const char *np_sigdb_match_fp(
        const np_os_sigdb_t       *db,
        const np_os_fingerprint_t *fp,
        double                    *out_confidence);

const char *np_sigdb_match_banner(
        const np_os_sigdb_t   *db,
        const np_os_banner_t  *banner,
        double                *out_confidence);

char *np_sigdb_default_path(void);

/**
 * np_sigdb_count – return total number of loaded signatures
 *                  (fingerprint + banner combined).
 *
 * Returns 0 if db is NULL or empty.
 */
int np_sigdb_count(const np_os_sigdb_t *db);

#endif /* NP_OS_SIGLOAD_H */
