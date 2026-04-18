/* include/npe/npe.h
 *
 * NPE — NetPeek Extension Engine
 *
 * This is the single "umbrella" header.  Application code only needs:
 *
 *     #include <npe/npe.h>
 *
 * All sub-headers are pulled in automatically.
 */

#ifndef NPE_H
#define NPE_H

/* ---- Foundation (order matters: types first) --------------------------- */
#include "npe_types.h"
#include "npe_error.h"

/* ---- Engine ------------------------------------------------------------ */
#include "npe_engine.h"

/* ---- Script model ------------------------------------------------------ */
#include "npe_script.h"
#include "npe_loader.h"
#include "npe_registry.h"

/* ---- Execution --------------------------------------------------------- */
#include "npe_scheduler.h"
#include "npe_runtime.h"
#include "npe_context.h"

/* ---- Output & safety --------------------------------------------------- */
#include "npe_result.h"
#include "npe_sandbox.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Convenience — One-Shot Execution
 *
 * For callers that just want "run these scripts and give me results" without
 * manual engine wiring.
 *============================================================================*/

/**
 * npe_quick_run — minimal-setup entry point.
 *
 * Creates an engine with the supplied config, loads the script directory,
 * selects scripts matching @p script_expr, adds a single target host,
 * executes, and copies results into a caller-supplied buffer.
 *
 * @param[in]  config        Engine configuration (NULL → defaults).
 * @param[in]  script_expr   --script expression (e.g. "default", "http-*").
 * @param[in]  target_ip     Single target IP address string.
 * @param[in]  target_ports  Array of port descriptors for the target
 *                           (may be NULL if port_count == 0).
 * @param[in]  port_count    Number of entries in target_ports.
 * @param[out] results       Heap-allocated result array.  Caller must free
 *                           each element with npe_result_free() then free()
 *                           the array itself.
 * @param[out] result_count  Number of results written.
 *
 * @return NPE_OK on success; the relevant error otherwise.
 */
npe_error_t npe_quick_run(const npe_engine_config_t *config,
                          const char                *script_expr,
                          const char                *target_ip,
                          const npe_port_t          *target_ports,
                          size_t                     port_count,
                          npe_result_t             **results,
                          size_t                    *result_count);

/*============================================================================
 * Global Initialisation / Tear-down
 *
 * Optional.  If you only ever use one engine at a time you can ignore these.
 * Call npe_global_init() early (before threads) and npe_global_cleanup() at
 * program exit.
 *============================================================================*/

/**
 * One-time library-wide initialisation (Lua allocator caches, SSL library
 * init, etc.).  Safe to call more than once — subsequent calls are no-ops.
 */
npe_error_t npe_global_init(void);

/**
 * Free library-wide resources.  After this call no NPE function except
 * npe_global_init() may be used.
 */
void npe_global_cleanup(void);

/*============================================================================
 * Compile-Time Feature Query
 *============================================================================*/

/** Returns non-zero if the library was built with SSL/TLS support. */
int npe_has_ssl(void);

/** Returns non-zero if the library was built with raw-socket support. */
int npe_has_raw_sockets(void);

/** Returns non-zero if the library was built with IPv6 support. */
int npe_has_ipv6(void);

/*============================================================================
 * Utility — Buffer helpers (thin wrappers, always available)
 *============================================================================*/

/** Allocate a new empty buffer with the given initial capacity. */
npe_error_t npe_buffer_create(npe_buffer_t **out, size_t initial_cap);

/** Append raw bytes.  Grows automatically. */
npe_error_t npe_buffer_append(npe_buffer_t *buf,
                              const void   *data,
                              size_t        len);

/** Reset size to 0 without freeing the backing allocation. */
void        npe_buffer_clear(npe_buffer_t *buf);

/** Free the buffer and (if owned) its data.  Sets *buf to NULL. */
void        npe_buffer_free(npe_buffer_t **buf);

/*============================================================================
 * Utility — Value helpers
 *============================================================================*/

/** Deep-copy a value.  The destination must later be freed via npe_value_free. */
npe_error_t npe_value_copy(npe_value_t       *dst,
                           const npe_value_t *src);

/** Release any heap storage inside a value (string, buffer, table, …). */
void        npe_value_free(npe_value_t *val);

/** Return a static string describing the value type ("nil","int",…). */
const char *npe_value_type_name(npe_value_type_t type);

/*============================================================================
 * Utility — Table helpers
 *============================================================================*/

/** Create a new empty table. */
npe_error_t npe_table_create(npe_table_t **out);

/** Set a key to a value (deep-copied).  Replaces if key exists. */
npe_error_t npe_table_set(npe_table_t       *tbl,
                          const char        *key,
                          const npe_value_t *val);

/** Lookup by key.  Returns NULL if not found. */
const npe_value_t *npe_table_get(const npe_table_t *tbl,
                                 const char        *key);

/** Free the table and all contained keys/values.  Sets *tbl to NULL. */
void npe_table_free(npe_table_t **tbl);

/*============================================================================
 * Utility — Host / Port helpers
 *============================================================================*/

/** Deep-copy a host (including its port array). */
npe_error_t npe_host_copy(npe_host_t       *dst,
                          const npe_host_t *src);

/** Free heap members inside a host struct (ports, os_info, …). */
void npe_host_free_members(npe_host_t *host);

#ifdef __cplusplus
}
#endif

#endif /* NPE_H */
