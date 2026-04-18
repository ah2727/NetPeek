/* include/npe/npe_engine.h
 *
 * Engine lifecycle — initialisation, configuration, execution, shutdown.
 *
 * Typical call order:
 *   1. npe_engine_create()
 *   2. npe_engine_set_*()          (configure)
 *   3. npe_engine_load_scripts()   (populate registry)
 *   4. npe_engine_select()         (choose which scripts to run)
 *   5. npe_engine_run()            (execute)
 *   6. npe_engine_destroy()
 */

#ifndef NPE_ENGINE_H
#define NPE_ENGINE_H

#include "npe_types.h"
#include "npe_result.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Engine Configuration (passed into create, or set piecemeal)
 *============================================================================*/

typedef struct npe_engine_config {
    /* ---- Paths --------------------------------------------------------- */
    const char         *script_dir;       /* NULL → "scripts/"              */
    const char         *script_db_path;   /* NULL → "scripts/script.db"    */

    /* ---- Concurrency --------------------------------------------------- */
    uint32_t            max_concurrent;   /* 0 → NPE_MAX_CONCURRENT_SCRIPTS*/
    uint32_t            thread_pool_size; /* 0 → auto (num CPUs)           */

    /* ---- Timing -------------------------------------------------------- */
    uint32_t            default_timeout_ms; /* 0 → NPE_DEFAULT_TIMEOUT_MS  */

    /* ---- Verbosity / logging ------------------------------------------- */
    npe_log_level_t     log_level;
    npe_log_fn          log_callback;     /* NULL → internal stderr logger  */
    void               *log_userdata;

    /* ---- Callbacks ----------------------------------------------------- */
    npe_progress_fn     progress_callback;
    void               *progress_userdata;
    npe_result_fn       result_callback;
    void               *result_userdata;

    /* ---- Security ------------------------------------------------------ */
    bool                sandbox_enable;   /* true → restrict FS / net / exec*/
    bool                allow_raw_sockets;/* only meaningful when sandboxed */

    /* ---- Script arguments (--script-args) ------------------------------ */
    const npe_args_t   *script_args;      /* NULL → no extra args          */
} npe_engine_config_t;

/*============================================================================
 * Engine Lifecycle
 *============================================================================*/

/**
 * Allocate and return a new engine instance.
 *
 * @param[in]  config  Optional configuration.  Pass NULL for all defaults.
 * @param[out] out     Receives the new engine pointer on success.
 * @return NPE_OK on success; relevant error code otherwise.
 *
 * The caller owns the returned engine and MUST call npe_engine_destroy().
 */
npe_error_t npe_engine_create(const npe_engine_config_t *config,
                              npe_engine_t             **out);

/**
 * Release all resources associated with the engine.
 *
 * Safe to call with NULL.  After this call, *engine is set to NULL.
 */
void npe_engine_destroy(npe_engine_t **engine);

/*============================================================================
 * Post-Create Configuration (any of these may be called before run)
 *============================================================================*/

/** Override the script directory. */
npe_error_t npe_engine_set_script_dir(npe_engine_t *engine,
                                      const char   *path);

/** Override the script database path. */
npe_error_t npe_engine_set_script_db(npe_engine_t *engine,
                                     const char   *path);

/** Change the default per-script timeout (milliseconds). */
npe_error_t npe_engine_set_timeout(npe_engine_t *engine,
                                   uint32_t      timeout_ms);

/** Change log level at runtime. */
npe_error_t npe_engine_set_log_level(npe_engine_t   *engine,
                                     npe_log_level_t level);

/** Install / replace the log callback. */
npe_error_t npe_engine_set_log_callback(npe_engine_t *engine,
                                        npe_log_fn    fn,
                                        void         *userdata);

/** Set maximum concurrent script executions. */
npe_error_t npe_engine_set_concurrency(npe_engine_t *engine,
                                       uint32_t      max_concurrent);

/** Provide the script argument table (--script-args). */
npe_error_t npe_engine_set_args(npe_engine_t   *engine,
                                const npe_args_t *args);

/** Enable or disable the sandbox globally. */
npe_error_t npe_engine_set_sandbox(npe_engine_t *engine,
                                   bool          enable);

/*============================================================================
 * Script Loading
 *============================================================================*/

/**
 * Scan the script directory and the script database, load and parse all
 * discovered .npe files, and populate the internal registry.
 *
 * This must be called before npe_engine_select() or npe_engine_run().
 */
npe_error_t npe_engine_load_scripts(npe_engine_t *engine);

/**
 * Return the total number of scripts currently in the registry.
 */
size_t npe_engine_script_count(const npe_engine_t *engine);

/*============================================================================
 * Script Selection
 *============================================================================*/

/**
 * Select scripts by category bitmask.
 *
 * All scripts whose categories intersect with @p mask are selected.
 * May be called multiple times; selections accumulate.
 */
npe_error_t npe_engine_select_by_category(npe_engine_t *engine,
                                          uint32_t      mask);

/**
 * Select a single script by its filesystem name (without path or extension).
 *
 * Example: npe_engine_select_by_name(eng, "http-title");
 */
npe_error_t npe_engine_select_by_name(npe_engine_t *engine,
                                      const char   *name);

/**
 * Select scripts by a comma-separated expression (same grammar as
 * the --script CLI flag).
 *
 * Examples:
 *   "default"
 *   "safe and not brute"
 *   "http-*,ssh-brute"
 */
npe_error_t npe_engine_select_by_expression(npe_engine_t *engine,
                                            const char   *expr);

/**
 * Clear all current selections.
 */
npe_error_t npe_engine_select_clear(npe_engine_t *engine);

/**
 * Return how many scripts are currently selected.
 */
size_t npe_engine_selected_count(const npe_engine_t *engine);

/*============================================================================
 * Target Registration
 *============================================================================*/

/**
 * Add a target host that scripts will be executed against.
 *
 * @param host   Pointer to a populated npe_host_t.  The engine makes a
 *               deep copy; the caller may free the original afterwards.
 */
npe_error_t npe_engine_add_host(npe_engine_t   *engine,
                                const npe_host_t *host);

/**
 * Convenience — add a host by IP string alone (no port / OS info).
 */
npe_error_t npe_engine_add_host_ip(npe_engine_t *engine,
                                   const char   *ip);

/**
 * Remove all registered target hosts.
 */
npe_error_t npe_engine_clear_hosts(npe_engine_t *engine);

/**
 * Return the current target host count.
 */
size_t npe_engine_host_count(const npe_engine_t *engine);

/*============================================================================
 * Execution
 *============================================================================*/

/**
 * Execute all selected scripts against all registered targets.
 *
 * The function blocks until every script has completed, timed out, or been
 * aborted.  Internally it drives the scheduler and Lua runtimes.
 *
 * Results are delivered via the result callback (if set) *and* are stored
 * internally for later retrieval with npe_engine_get_results().
 *
 * @return NPE_OK             All scripts finished (possibly with individual errors).
 * @return NPE_ERROR_*        A fatal engine-level error prevented execution.
 */
npe_error_t npe_engine_run(npe_engine_t *engine);

/**
 * Request a graceful abort of all running scripts.
 *
 * Safe to call from a signal handler or another thread.  Sets an internal
 * flag that the scheduler checks between script steps.
 */
npe_error_t npe_engine_abort(npe_engine_t *engine);

/*============================================================================
 * Result Retrieval (after run)
 *============================================================================*/

/**
 * Get a read-only pointer to the result array.
 *
 * @param[out] results  Receives the base pointer.
 * @param[out] count    Receives the element count.
 *
 * The memory is owned by the engine and remains valid until the next
 * npe_engine_run() or npe_engine_destroy() call.
 */
npe_error_t npe_engine_get_results(const npe_engine_t  *engine,
                                   const npe_result_t **results,
                                   size_t              *count);

/**
 * Get a deep-copied array of full result entries.
 *
 * Unlike npe_engine_get_results(), entries include script/host/port metadata
 * and are suitable for rich CLI formatting. Caller must free each entry's
 * members via npe_result_free_members(&entry.result), then free() the array.
 */
npe_error_t npe_engine_get_result_entries(const npe_engine_t *engine,
                                          npe_result_entry_t **entries,
                                          size_t             *count);

/*============================================================================
 * Status / Diagnostics
 *============================================================================*/

typedef struct npe_engine_stats {
    size_t      scripts_total;       /* In registry              */
    size_t      scripts_selected;    /* Currently selected       */
    size_t      scripts_finished;    /* Completed (ok + failed)  */
    size_t      scripts_running;     /* Currently executing      */
    size_t      scripts_queued;      /* Waiting in work queue    */
    size_t      scripts_failed;      /* Finished with error      */
    size_t      scripts_timed_out;
    size_t      hosts_total;
    double      uptime_ms;           /* Since engine_create      */
} npe_engine_stats_t;

/**
 * Snapshot engine counters.  Safe to call while scripts are running.
 */
npe_error_t npe_engine_get_stats(const npe_engine_t *engine,
                                 npe_engine_stats_t *stats);

/**
 * Return a human-readable description for an error code.
 */
const char *npe_error_string(npe_error_t err);

/**
 * Return the engine version string (same as NPE_VERSION_STRING).
 */
const char *npe_engine_version(void);

#ifdef __cplusplus
}
#endif

#endif /* NPE_ENGINE_H */
