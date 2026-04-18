#ifndef NP_ARGS_H
#define NP_ARGS_H

#include "netpeek.h"

/**
 * Parse command-line arguments into the config struct.
 * Returns NP_OK on success, NP_ERR_ARGS on bad input.
 */
np_status_t np_args_parse(int argc, char *argv[], np_config_t *cfg);

/**
 * Print usage / help text.
 */
void np_args_usage(const char *progname);

#endif /* NP_ARGS_H */
