/*****************************************************************************
 * npe_registry.h — Global script and service fingerprint registry
 * ───────────────────────────────────────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *
 * The registry is a centralised, engine-wide data store that provides:
 *
 *   1. **Script catalogue**  – all loaded npe_script_t objects indexed by
 *      name, category, phase, and port interest.
 *
 *   2. **Service fingerprint table** – known service signatures used by
 *      scripts during the rule() phase for quick matching.
 *
 *   3. **Shared data store** – a thread-safe key-value map that scripts
 *      can read/write to exchange information across contexts (e.g.
 *      one script discovers a software version; another uses it).
 *
 * Thread-safety: all public functions are internally synchronised with
 *                a read-write lock.  Callers do NOT need external locking.
 *****************************************************************************/

#ifndef NPE_REGISTRY_H
#define NPE_REGISTRY_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Forward declarations ────────────────────────────────────────────────── */
typedef struct npe_script   npe_script_t;
typedef struct npe_engine   npe_engine_t;

/* ── Opaque handles ──────────────────────────────────────────────────────── */
typedef struct npe_registry          npe_registry_t;
typedef struct npe_registry_iter     npe_registry_iter_t;

/* ── Service fingerprint entry ───────────────────────────────────────────── */
typedef struct npe_service_fp {
    char                 name[NPE_MAX_NAME];       /* e.g. "http", "ssh"     */
    char                 product[NPE_MAX_NAME];    /* e.g. "Apache httpd"    */
    char                 version[64];              /* e.g. "2.4.52"          */
    char                 extra_info[128];          /* free-form info         */
    npe_protocol_t       protocol;                 /* TCP / UDP              */
    uint16_t             port;                     /* canonical port or 0    */
    const uint8_t       *probe;                    /* probe payload (may be NULL) */
    size_t               probe_len;
    const uint8_t       *match_pattern;            /* regex / literal match  */
    size_t               match_len;
    bool                 is_regex;                 /* true = regex match     */
} npe_service_fp_t;

/* ── Shared data store value wrapper ─────────────────────────────────────── */
typedef struct npe_shared_entry {
    char                 key[NPE_MAX_NAME];
    npe_value_t          value;
    uint64_t             timestamp_us;   /* monotonic time of last write   */
    const char          *writer_script;  /* name of script that wrote it   */
} npe_shared_entry_t;

/* ── Script query filter ─────────────────────────────────────────────────── */
typedef struct npe_script_filter {
    const char          *name_pattern;    /* glob / NULL = any              */
    const char          *category;        /* exact match / NULL = any       */
    npe_phase_t          phase;           /* required phase / -1 = any      */
    npe_protocol_t       protocol;        /* protocol interest / -1 = any   */
    uint16_t             port;            /* port interest    / 0  = any    */
    bool                 safe_only;       /* if true, exclude "intrusive"   */
} npe_script_filter_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  LIFECYCLE
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Create a new registry.  Typically one per engine instance.
 */
npe_error_t npe_registry_create(npe_registry_t **out);

/**
 * Destroy the registry and free all internal data.
 * Does NOT destroy script objects; ownership remains with the loader.
 */
void npe_registry_destroy(npe_registry_t *reg);

/**
 * Remove all entries (scripts, fingerprints, shared data).
 */
void npe_registry_clear(npe_registry_t *reg);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SCRIPT CATALOGUE
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Register a loaded script.  The registry indexes it by name, categories,
 * port interests, and phases.  Duplicate names are rejected.
 */
npe_error_t npe_registry_add_script(npe_registry_t     *reg,
                                    const npe_script_t *script);

/**
 * Remove a script by name.
 */
npe_error_t npe_registry_remove_script(npe_registry_t *reg,
                                       const char     *name);

/**
 * Look up a single script by exact name.
 */
npe_error_t npe_registry_find_script(const npe_registry_t  *reg,
                                     const char            *name,
                                     const npe_script_t   **out);

/**
 * Query scripts matching a filter.
 *
 * @param reg     registry to search
 * @param filter  filter criteria (NULL = return all)
 * @param out     receives a NULL-terminated array of script pointers
 * @param count   receives the number of matching scripts
 * @return NPE_OK on success
 *
 * The caller must free `*out` with npe_registry_free_query().
 */
npe_error_t npe_registry_query_scripts(const npe_registry_t     *reg,
                                       const npe_script_filter_t *filter,
                                       const npe_script_t      ***out,
                                       size_t                    *count);

void npe_registry_free_query(const npe_script_t **list);

/**
 * Return total number of registered scripts.
 */
size_t npe_registry_script_count(const npe_registry_t *reg);

/* ── Script iteration ────────────────────────────────────────────────────── */

npe_registry_iter_t *npe_registry_script_iter_begin(const npe_registry_t *reg);
const npe_script_t  *npe_registry_script_iter_next(npe_registry_iter_t *iter);
void                 npe_registry_script_iter_end(npe_registry_iter_t *iter);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SCRIPT DEPENDENCY RESOLUTION
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Verify that all declared dependencies of every registered script can
 * be satisfied.  Returns the names of missing scripts via `missing`.
 *
 * @param reg       registry
 * @param missing   receives NULL-terminated array of missing names (caller frees)
 * @param count     number of missing dependencies
 * @return NPE_OK if all dependencies are met, NPE_ERR_DEPENDENCY otherwise
 */
npe_error_t npe_registry_check_dependencies(const npe_registry_t *reg,
                                            char               ***missing,
                                            size_t               *count);

/**
 * Produce a topologically sorted execution order honouring dependencies.
 *
 * @param reg     registry
 * @param order   receives NULL-terminated array of script pointers
 * @param count   number of scripts in the order
 * @return NPE_OK, or NPE_ERR_DEPENDENCY on circular dependencies
 */
npe_error_t npe_registry_resolve_order(const npe_registry_t  *reg,
                                       const npe_script_t  ***order,
                                       size_t                *count);

void npe_registry_free_order(const npe_script_t **order);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SERVICE FINGERPRINT TABLE
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_error_t npe_registry_add_service_fp(npe_registry_t        *reg,
                                        const npe_service_fp_t *fp);

npe_error_t npe_registry_remove_service_fp(npe_registry_t *reg,
                                           const char     *name,
                                           npe_protocol_t  proto,
                                           uint16_t        port);

/**
 * Match a probe response against all registered fingerprints.
 *
 * @param reg       registry
 * @param proto     protocol of the probed port
 * @param port      port number
 * @param response  raw response data
 * @param resp_len  length of response
 * @param out       receives best-matching fingerprint (or NULL)
 * @return NPE_OK if a match was found, NPE_ERROR_NOT_FOUND otherwise
 */
npe_error_t npe_registry_match_service(const npe_registry_t   *reg,
                                       npe_protocol_t          proto,
                                       uint16_t                port,
                                       const uint8_t          *response,
                                       size_t                  resp_len,
                                       const npe_service_fp_t **out);

size_t npe_registry_service_fp_count(const npe_registry_t *reg);

/**
 * Load service fingerprints from an npe-service-probes file.
 */
npe_error_t npe_registry_load_service_fp_file(npe_registry_t *reg,
                                              const char     *path);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SHARED DATA STORE  (cross-script communication)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Write a value into the shared store.  If the key already exists, the
 * previous value is overwritten.  `writer` is the name of the calling
 * script (for auditing); may be NULL.
 */
npe_error_t npe_registry_shared_set(npe_registry_t    *reg,
                                    const char        *key,
                                    const npe_value_t *value,
                                    const char        *writer);

/**
 * Read a value from the shared store.
 * Returns NPE_ERROR_NOT_FOUND if the key does not exist.
 */
npe_error_t npe_registry_shared_get(const npe_registry_t  *reg,
                                    const char            *key,
                                    npe_shared_entry_t    *out);

npe_error_t npe_registry_shared_remove(npe_registry_t *reg,
                                       const char     *key);

void   npe_registry_shared_clear(npe_registry_t *reg);
size_t npe_registry_shared_count(const npe_registry_t *reg);

/**
 * Iterate all shared entries.  Set `*iter` to NULL to begin.
 * Returns NULL when exhausted.
 */
const npe_shared_entry_t *
npe_registry_shared_next(const npe_registry_t     *reg,
                         const npe_shared_entry_t *iter);

/* ═══════════════════════════════════════════════════════════════════════════
 *  STATISTICS
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct npe_registry_stats {
    size_t  total_scripts;
    size_t  scripts_by_phase[4];     /* indexed by npe_phase_t         */
    size_t  total_service_fps;
    size_t  shared_entries;
    size_t  categories_count;        /* number of distinct categories  */
} npe_registry_stats_t;

npe_error_t npe_registry_get_stats(const npe_registry_t *reg,
                                   npe_registry_stats_t *out);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SERIALISATION  (optional persistence of the catalogue index)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Save the current script catalogue index to a binary cache file.
 * This speeds up subsequent engine starts by avoiding full re-parsing.
 */
npe_error_t npe_registry_save_cache(const npe_registry_t *reg,
                                    const char           *path);

/**
 * Load a previously saved cache.  Scripts whose on-disk `.npe` files
 * have a newer mtime than the cache entry are automatically re-parsed.
 */
npe_error_t npe_registry_load_cache(npe_registry_t *reg,
                                    const char     *path);

#ifdef __cplusplus
}
#endif

#endif /* NPE_REGISTRY_H */
