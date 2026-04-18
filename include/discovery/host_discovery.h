#ifndef NP_HOST_DISCOVERY_H
#define NP_HOST_DISCOVERY_H

#include <signal.h>
#include "netpeek.h"

np_status_t np_host_discovery_run(np_config_t *cfg,
                                  volatile sig_atomic_t *interrupted);

np_status_t np_discovery_resolve_targets(np_config_t *cfg);

#endif
