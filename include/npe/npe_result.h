/*****************************************************************************
 * npe_result.h — Script result collection and formatting
 *****************************************************************************/

#ifndef NPE_RESULT_H
#define NPE_RESULT_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Extended Result (associates a result with its origin)
 *============================================================================*/

typedef struct npe_result_entry {
    char            script_name[NPE_MAX_SCRIPT_NAME];
    char            host_ip[64];
    uint16_t        port_number;
    npe_protocol_t  protocol;
    npe_phase_t     phase;
    npe_result_t    result;
    struct npe_result_entry *next;
} npe_result_entry_t;

/*============================================================================
 * Result Collector (thread-safe accumulator)
 *============================================================================*/

typedef struct npe_result_collector npe_result_collector_t;

npe_error_t npe_result_collector_create(npe_result_collector_t **out);
void        npe_result_collector_destroy(npe_result_collector_t **collector);

/**
 * Add a result.  Thread-safe.  Deep-copies the entry.
 */
npe_error_t npe_result_collector_add(npe_result_collector_t  *collector,
                                     const npe_result_entry_t *entry);

/**
 * Retrieve all collected results as a flat array.
 * Caller must free the array and each entry's members.
 */
npe_error_t npe_result_collector_get_all(const npe_result_collector_t *collector,
                                         npe_result_entry_t          **out,
                                         size_t                       *count);

/** Number of entries. */
size_t npe_result_collector_count(const npe_result_collector_t *collector);

/*============================================================================
 * Result Lifecycle Helpers
 *============================================================================*/

/** Zero-initialise a result. */
void npe_result_init(npe_result_t *result);

/** Free heap members inside a result (output value, etc.). */
void npe_result_free_members(npe_result_t *result);

/*============================================================================
 * Formatting
 *============================================================================*/

/**
 * Format a result as a human-readable text string.
 * Returns a heap-allocated string; caller must free().
 */
char *npe_result_format_text(const npe_result_entry_t *entry);

/**
 * Format a result as a JSON object string.
 * Returns a heap-allocated string; caller must free().
 */
char *npe_result_format_json(const npe_result_entry_t *entry);

/**
 * Format a result as a single CSV row.
 * Returns a heap-allocated string; caller must free().
 */
char *npe_result_format_csv(const npe_result_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif /* NPE_RESULT_H */
