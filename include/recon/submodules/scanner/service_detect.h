#ifndef NP_SERVICE_DETECT_H
#define NP_SERVICE_DETECT_H

#include "netpeek.h"

np_status_t np_service_detect_run(np_config_t *cfg);
np_status_t np_service_detect_run_target(np_config_t *cfg, uint32_t target_idx);

#endif
