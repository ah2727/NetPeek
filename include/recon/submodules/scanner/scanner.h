#ifndef NP_SCANNER_H
#define NP_SCANNER_H

#include <signal.h>
#include <stdbool.h>
#include "netpeek.h" 

np_status_t np_scanner_run(np_config_t *cfg,
                           volatile sig_atomic_t *interrupted);

#endif /* NP_SCANNER_H */
