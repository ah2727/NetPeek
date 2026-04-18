/*
 * NetPeek - Banner Grabbing (Nmap Probe Engine)
 *
 * Uses the Nmap service-probes database (via generated headers) to:
 *   1. Select probes by port and rarity
 *   2. Send exact Nmap probe payloads
 *   3. Match responses with PCRE2 regex
 *   4. Extract service/version via capture groups ($1..$9)
 */

#ifndef NP_OS_BANNER_H
#define NP_OS_BANNER_H

#include "recon/submodules/os_detect/os_detect.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/* Tuning knobs                                                       */
/* ------------------------------------------------------------------ */

/* Maximum number of probes to attempt per port (sorted by rarity) */
#ifndef NP_MAX_PROBES_PER_PORT
#define NP_MAX_PROBES_PER_PORT  16
#endif

/* Maximum rarity level to try (1 = most common, 9 = rarest)
 * Set lower for faster scans, higher for more coverage. */
#ifndef NP_MAX_PROBE_RARITY
#define NP_MAX_PROBE_RARITY     7
#endif

/* Maximum number of PCRE2 capture groups we extract */
#ifndef NP_MAX_CAPTURES
#define NP_MAX_CAPTURES         10
#endif

/* Maximum length of a single capture group string */
#ifndef NP_CAPTURE_MAX_LEN
#define NP_CAPTURE_MAX_LEN      256
#endif

#define NP_OS_BANNER_MAX_COUNT     30

/* ── Banner engine tuning constants ── */
#define NP_BANNER_TIMEOUT_MS      3000
#define NP_BANNER_RECV_BUF_SIZE   4096
#define NP_MAX_PROBES_PER_PORT      16
#define NP_MAX_PROBE_RARITY          9
#define NP_MAX_CAPTURES             10
#define NP_CAPTURE_MAX_LEN         256
/* ------------------------------------------------------------------ */
/* Result of a single probe+match cycle                               */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Which probe produced this result */
    int          probe_idx;
    uint16_t     port;

    /* Raw banner */
    char         banner[NP_OS_BANNER_MAX];
    uint32_t     banner_len;

    /* Matched service info (populated by regex matching) */
    char         service[NP_OS_NAME_LEN];       /* e.g. "http", "ssh"    */
    char         product[NP_OS_NAME_LEN];       /* e.g. "Apache httpd"   */
    char         version[NP_OS_NAME_LEN];       /* e.g. "2.4.51"         */
    char         info[NP_OS_NAME_LEN];          /* e.g. "Ubuntu"         */
    char         hostname[NP_OS_NAME_LEN];      /* from h/ field         */
    char         os_name[NP_OS_NAME_LEN];       /* from o/ field         */
    char         device_type[NP_OS_NAME_LEN];   /* from d/ field         */
    char         cpe[NP_OS_NAME_LEN];           /* first cpe:/ string    */

    /* Match metadata */
    int          match_idx;     /* index into g_nmap_matches[], -1 = none */
    bool         is_soft_match; /* true if only a softmatch was found     */
    uint8_t      confidence;    /* 0-100 */
} np_banner_result_t;

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

/**
 * Grab banners from open ports on a single target using the Nmap probe
 * database.  For each port, probes are selected by port list and rarity,
 * sent in order, and responses are matched against Nmap's regex signatures.
 *
 * Populates result->banners[] and result->banner_count, then appends
 * OS-level matches to result->matches[].
 *
 * @param target       Target IP (in target->ip)
 * @param ports        Array of open port numbers to probe
 * @param port_count   Number of ports
 * @param timeout_ms   Per-probe timeout in milliseconds
 * @param proxy        Optional SOCKS/HTTP proxy (NULL = direct)
 * @param result       Output structure (caller must zero-initialize)
 * @return NP_STATUS_OK on success (even if no banners captured)
 */
np_status_t np_os_banner_grab(const np_target_t *target,
                              const uint16_t    *ports,
                              uint32_t           port_count,
                              uint32_t           timeout_ms,
                              const np_proxy_t  *proxy,
                              np_os_result_t    *result);

/**
 * Match already-collected banners in result->banners[] against
 * the Nmap signature database.  Appends matches to result->matches[].
 *
 * This is called automatically by np_os_banner_grab(), but can also
 * be invoked separately if banners were collected by other means.
 *
 * @param result  Result structure with banners[] populated
 * @param db      Signature database (unused in new engine — kept for API compat)
 * @return NP_STATUS_OK
 */
np_status_t np_os_banner_match(np_os_result_t    *result,
                               const np_os_sigdb_t *db);

/**
 * Initialize the PCRE2 regex cache for all Nmap match patterns.
 * Call once at program startup.  Thread-safe after initialization.
 * Returns 0 on success, -1 on failure.
 */
int np_banner_engine_init(void);

/**
 * Free all compiled PCRE2 patterns.
 * Call once at program shutdown.
 */
void np_banner_engine_cleanup(void);

#endif /* NP_OS_BANNER_H */
