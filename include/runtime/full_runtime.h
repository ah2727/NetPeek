#ifndef NP_FULL_RUNTIME_H
#define NP_FULL_RUNTIME_H

#include "netpeek.h"
#include <signal.h>

bool np_full_mode_supported(np_scan_type_t scan_type);
np_status_t np_full_runtime_run(np_config_t *cfg,
                                volatile sig_atomic_t *interrupted);

#endif
