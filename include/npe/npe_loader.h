/*****************************************************************************
 * npe_loader.h — Script file loading and parsing
 *
 * The loader is responsible for:
 *   1. Scanning a directory (recursively) for .npe files.
 *   2. Loading each file into memory.
 *   3. Parsing metadata from the Lua source (description, categories, etc.).
 *   4. Validating that required entry points exist.
 *   5. Building / updating the script.db index.
 *****************************************************************************/

#ifndef NPE_LOADER_H
#define NPE_LOADER_H

#include "npe_types.h"
#include "npe_script.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Forward declarations ────────────────────────────────────────────────── */
typedef struct npe_registry npe_registry_t;

/* ── Loader configuration ────────────────────────────────────────────────── */
typedef struct npe_loader_config {
    const char     *script_dir;         /* Root directory for .npe files    */
    const char     *script_db_path;     /* Path to script.db               */
    bool            recursive;          /* Recurse into sub-directories    */
    bool            update_db;          /* Regenerate script.db on load    */
    npe_log_fn      log_fn;
    void           *log_userdata;
    npe_log_level_t log_level;
} npe_loader_config_t;

/* ── Loader handle ───────────────────────────────────────────────────────── */
typedef struct npe_loader npe_loader_t;

/*============================================================================
 * Lifecycle
 *============================================================================*/

/**
 * Create a new loader.
 *
 * @param[in]  config  Loader options (NULL → defaults: "scripts/", recursive).
 * @param[out] out     Receives the new loader handle.
 * @return NPE_OK or NPE_ERROR_MEMORY.
 */
npe_error_t npe_loader_create(const npe_loader_config_t *config,
                              npe_loader_t             **out);

/**
 * Destroy the loader.  Sets *loader to NULL.
 */
void npe_loader_destroy(npe_loader_t **loader);

/*============================================================================
 * Directory Scanning
 *============================================================================*/

/**
 * Scan the configured script directory for .npe files.
 *
 * Populates an internal file list.  Does NOT load file contents yet.
 *
 * @param loader   Loader handle.
 * @param[out] count  Receives the number of .npe files discovered.
 * @return NPE_OK, NPE_ERROR_IO, NPE_ERROR_NOT_FOUND.
 */
npe_error_t npe_loader_scan_directory(npe_loader_t *loader,
                                      size_t       *count);

/*============================================================================
 * Script Loading
 *============================================================================*/

/**
 * Load ALL discovered scripts (scan + parse + validate).
 *
 * Equivalent to calling scan_directory, then load_script for each file,
 * then validate on each result.  Successfully loaded scripts are registered
 * into @p registry.
 *
 * @param loader    Loader handle.
 * @param registry  Target registry to populate.
 * @return NPE_OK on success (individual script failures are logged but do
 *         not abort the batch).
 */
npe_error_t npe_loader_load_all(npe_loader_t  *loader,
                                npe_registry_t *registry);

/**
 * Load a single script by file path.
 *
 * Reads the file, creates a temporary Lua state to extract metadata, then
 * populates an npe_script_t.
 *
 * @param loader      Loader handle.
 * @param path        Absolute or relative path to the .npe file.
 * @param[out] out    Receives a heap-allocated npe_script_t.
 * @return NPE_OK, NPE_ERROR_IO, NPE_ERROR_SCRIPT_SYNTAX,
 *         NPE_ERROR_PARSE.
 */
npe_error_t npe_loader_load_script(npe_loader_t  *loader,
                                   const char    *path,
                                   npe_script_t **out);

/*============================================================================
 * Validation
 *============================================================================*/

/**
 * Validate a loaded script.
 *
 * Checks:
 *   - At least one rule function (portrule / hostrule / prerule / postrule).
 *   - An action() function.
 *   - Name is non-empty.
 *   - No circular dependencies (requires registry context).
 *
 * @return NPE_OK or NPE_ERROR_SCRIPT_SYNTAX.
 */
npe_error_t npe_loader_validate(npe_loader_t       *loader,
                                const npe_script_t *script);

/*============================================================================
 * Metadata Extraction (low-level)
 *============================================================================*/

/**
 * Extract metadata from an already-loaded Lua state.
 *
 * Expects that the script chunk has been loaded (but not necessarily
 * executed).  Reads the global variables:
 *   description, author, license, categories, dependencies,
 *   and tests for the existence of prerule/hostrule/portrule/postrule/action.
 *
 * @param loader     Loader handle.
 * @param lua_state  A lua_State* that has had the script loaded.
 * @param[out] meta  Receives extracted metadata.
 * @return NPE_OK, NPE_ERROR_PARSE.
 */
npe_error_t npe_loader_parse_metadata(npe_loader_t      *loader,
                                      void              *lua_state,
                                      npe_script_meta_t *meta);

/*============================================================================
 * Script Database (script.db)
 *============================================================================*/

/**
 * Rebuild the script.db index from the current set of loaded scripts in
 * the registry.
 *
 * @param loader    Loader handle.
 * @param registry  Registry containing all loaded scripts.
 * @return NPE_OK, NPE_ERROR_IO.
 */
npe_error_t npe_loader_build_database(npe_loader_t       *loader,
                                      const npe_registry_t *registry);

/**
 * Load the script.db index from disk and populate the registry.
 *
 * This is a fast alternative to scan_directory + load_all when the
 * scripts have not changed since the last build.
 *
 * @param loader    Loader handle.
 * @param registry  Target registry.
 * @return NPE_OK, NPE_ERROR_IO, NPE_ERROR_PARSE.
 */
npe_error_t npe_loader_load_database(npe_loader_t  *loader,
                                     npe_registry_t *registry);

/*============================================================================
 * Statistics
 *============================================================================*/

typedef struct npe_loader_stats {
    size_t files_found;         /* .npe files discovered                */
    size_t files_loaded;        /* Successfully loaded                  */
    size_t files_failed;        /* Failed to load or validate           */
    double load_time_ms;        /* Total wall-clock load time           */
} npe_loader_stats_t;

/**
 * Retrieve loader statistics.
 */
npe_error_t npe_loader_get_stats(const npe_loader_t *loader,
                                 npe_loader_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LOADER_H */
