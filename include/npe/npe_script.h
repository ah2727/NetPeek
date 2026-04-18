/* include/npe/npe_script.h
 *
 * Script structure definition.
 *
 * An npe_script_t represents a single .npe Lua script as parsed from disk.
 * It holds the metadata extracted from the script header block (description,
 * author, categories, rule functions present, dependencies, …) plus the
 * raw source text that will be compiled into a Lua chunk at execution time.
 *
 * Scripts are created by the loader (npe_loader.h) and stored in the
 * registry (npe_registry.h).  The scheduler creates per-target execution
 * contexts (npe_context.h) that reference back to the originating script.
 */

#ifndef NPE_SCRIPT_H
#define NPE_SCRIPT_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Script Metadata — extracted from the script header comment block
 *============================================================================*/

typedef struct npe_script_meta {
    char        name[NPE_MAX_SCRIPT_NAME];
    char        author[NPE_MAX_SCRIPT_AUTHOR];
    char        description[NPE_MAX_SCRIPT_DESC];
    char        license[NPE_MAX_SCRIPT_NAME];          /* e.g. "MIT"        */
    char        version[64];                            /* script version    */
    char        usage[NPE_MAX_SCRIPT_DESC];             /* --script-help txt */

    /* Categories — bitmask of npe_category_t values */
    uint32_t    categories;

    /* Which rule / action entry points are defined in the script */
    bool        has_prerule;
    bool        has_hostrule;
    bool        has_portrule;
    bool        has_postrule;
    bool        has_action;

    /* Optional: ports the portrule is interested in (hint for scheduler).
     * Zero-terminated list.  Empty → "any port". */
    uint16_t    interest_ports[NPE_MAX_PORTS_RULE];
    size_t      interest_port_count;

    /* Optional: protocols the script cares about */
    npe_protocol_t  interest_protocols[4];
    size_t          interest_protocol_count;

    /* Dependencies — names of other scripts that must run first */
    char        dependencies[NPE_MAX_DEPENDENCIES][NPE_MAX_SCRIPT_NAME];
    size_t      dependency_count;

    /* Recon metadata (dual-parser compatible with legacy fields) */
    char        stage[32];
    char        impact[16];
    char        requires[NPE_MAX_DEPENDENCIES][NPE_MAX_SCRIPT_NAME];
    size_t      requires_count;
} npe_script_meta_t;

/*============================================================================
 * Script Source
 *============================================================================*/

typedef struct npe_script_source {
    char       *path;            /* Absolute filesystem path of the .npe file */
    char       *text;            /* Raw Lua source (heap, NUL-terminated)     */
    size_t      text_len;        /* strlen(text)                              */
    uint64_t    checksum;        /* CRC-64 or xxHash of text (for caching)    */
    time_t      mtime;           /* Last-modified timestamp of the file       */
} npe_script_source_t;

/*============================================================================
 * Script Structure
 *============================================================================*/

struct npe_script {
    /* ---- Identity ------------------------------------------------------ */
    uint32_t                id;          /* Engine-wide unique id            */
    char                    filename[NPE_MAX_SCRIPT_NAME]; /* e.g. "http-title" */

    /* ---- Metadata (parsed from header block) --------------------------- */
    npe_script_meta_t       meta;

    /* ---- Source -------------------------------------------------------- */
    npe_script_source_t     source;

    /* ---- Runtime bookkeeping ------------------------------------------- */
    npe_script_state_t      state;
    bool                    selected;    /* true if user/engine chose it     */
    uint32_t                run_count;   /* how many times executed so far   */
    uint32_t                timeout_ms;  /* per-script override (0 = default)*/

    /* ---- Ordering / scheduling ----------------------------------------- */
    int32_t                 priority;    /* lower = runs first (default 50)  */
    uint32_t                dep_ids[NPE_MAX_DEPENDENCIES]; /* resolved ids  */
    size_t                  dep_id_count;

    /* ---- Linked list / intrusive hook (used by registry) --------------- */
    npe_script_t           *next;
};

/*============================================================================
 * Script Lifecycle Helpers
 *============================================================================*/

/**
 * Allocate and zero-initialise a new script.
 *
 * @param[out] out  Receives the new script pointer on success.
 * @return NPE_OK or NPE_ERROR_MEMORY.
 */
npe_error_t npe_script_create(npe_script_t **out);

/**
 * Deep-copy a script.
 *
 * @param[out] dst  Receives a newly heap-allocated copy.
 * @param[in]  src  Source script.
 * @return NPE_OK or NPE_ERROR_MEMORY.
 */
npe_error_t npe_script_clone(npe_script_t       **dst,
                             const npe_script_t  *src);

/**
 * Release all heap members and the script itself.  Sets *script to NULL.
 */
void npe_script_destroy(npe_script_t **script);

/*============================================================================
 * Metadata Queries
 *============================================================================*/

/** Return true if the script's categories intersect the given mask. */
bool npe_script_matches_category(const npe_script_t *script,
                                 uint32_t            mask);

/** Return true if the script defines an entry point for the given phase. */
bool npe_script_has_phase(const npe_script_t *script,
                          npe_phase_t         phase);

/** Return true if @p script lists @p dep_name in its dependency array. */
bool npe_script_depends_on(const npe_script_t *script,
                           const char         *dep_name);

/** Return a human-readable comma-separated category string.
 *  Writes into @p buf (at most @p bufsz bytes including NUL).
 *  Returns the number of characters written (excluding NUL). */
size_t npe_script_categories_str(const npe_script_t *script,
                                 char               *buf,
                                 size_t              bufsz);

/*============================================================================
 * Port Interest Matching
 *============================================================================*/

/**
 * Evaluate whether the script's portrule *hint* matches a given port.
 *
 * This is a fast pre-filter only (the real portrule is the Lua function).
 * Returns true if:
 *   - The script has no interest_ports (wildcard), OR
 *   - The port number appears in interest_ports AND (interest_protocols is
 *     empty OR the protocol matches).
 */
bool npe_script_port_interest(const npe_script_t *script,
                              uint16_t            port,
                              npe_protocol_t      proto);

/*============================================================================
 * Sorting / Comparison (for scheduler ordering)
 *============================================================================*/

/**
 * Compare two scripts by priority (ascending), then by name (lexicographic).
 * Returns <0, 0, >0 — suitable for qsort().
 */
int npe_script_compare(const void *a, const void *b);

/*============================================================================
 * Debug / Dump
 *============================================================================*/

/**
 * Write a human-readable summary of the script to @p fp (e.g. stderr).
 */
void npe_script_dump(const npe_script_t *script, void *fp /* FILE* */);

#ifdef __cplusplus
}
#endif

#endif /* NPE_SCRIPT_H */
