#ifndef NP_SCANNER_PARALLEL_H
#define NP_SCANNER_PARALLEL_H

#include "netpeek.h"
#include <signal.h>
#include <stdint.h>

/*
 * Maximum number of hosts scanned concurrently.
 * Each host-worker spawns its own port-level thread pool,
 * so total threads ≈ host_parallelism × cfg->threads.
 * Keep this modest to avoid fd exhaustion.
 */
#define NP_DEFAULT_HOST_PARALLELISM  16
#define NP_MAX_HOST_PARALLELISM      64

/*
 * Compute optimal host parallelism based on target count
 * and available resources.
 */
uint32_t np_compute_host_parallelism(const np_config_t *cfg);

#endif /* NP_SCANNER_PARALLEL_H */
