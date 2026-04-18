#ifndef NP_TLS_PROBE_H
#define NP_TLS_PROBE_H

#include "netpeek.h"

np_status_t np_tls_probe_run(np_config_t *cfg);
np_status_t np_tls_probe_run_target(np_config_t *cfg, uint32_t target_idx);

#endif
