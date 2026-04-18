/*
 * NetPeek - Target Resolution & Management
 *
 * Handles hostname resolution, IPv4/IPv6 detection,
 * CIDR expansion, and target list lifecycle.
 */

#ifndef NP_TARGET_H
#define NP_TARGET_H

#include "netpeek.h"
#include <stdbool.h>

/**
 * Resolve all targets in cfg->targets[].
 * Populates addr4/addr6 and is_ipv6 for each target.
 * Expands CIDR notation (e.g., 192.168.1.0/24) into individual targets.
 *
 * Returns NP_OK on success, NP_ERR_RESOLVE if any target fails.
 */
np_status_t np_target_resolve_all(np_config_t *cfg);

/**
 * Resolve a single target by hostname or IP string.
 * Fills in the sockaddr and is_ipv6 fields.
 *
 * Returns NP_OK on success.
 */
np_status_t np_target_resolve(np_target_t *target);

/**
 * Check if a string is CIDR notation (contains '/').
 */
bool np_target_is_cidr(const char *str);

/**
 * Expand a CIDR string into an array of np_target_t.
 * Caller must free *out_targets when done.
 *
 * @param cidr_str    e.g. "192.168.1.0/24"
 * @param out_targets pointer to receive allocated array
 * @param out_count   pointer to receive number of targets
 *
 * Returns NP_OK on success, NP_ERR_ARGS on bad CIDR,
 * NP_ERR_MEMORY on allocation failure.
 */
np_status_t np_target_expand_cidr(const char *cidr_str,
                                  np_target_t **out_targets,
                                  uint32_t *out_count);

/**
 * Allocate the results array for a target based on port count.
 * Zeroes all port states to NP_PORT_UNKNOWN.
 */
np_status_t np_target_alloc_results(np_config_t *cfg, uint32_t port_count);

/**
 * Free the results array inside a target.
 */
void np_target_free_results(np_target_t *target);

/**
 * Shuffle the target array in-place (Fisher-Yates).
 * Used when cfg->randomize_hosts is true.
 */
void np_target_shuffle(np_target_t *targets, uint32_t count);

/**
 * Print a summary line for a target (debug/verbose).
 */
void np_target_print_info(const np_target_t *target);

#endif /* NP_TARGET_H */
