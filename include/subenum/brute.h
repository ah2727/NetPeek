#ifndef NP_SUBENUM_BRUTE_H
#define NP_SUBENUM_BRUTE_H

#include "subenum/dns_resolver.h"
#include "subenum/subenum_types.h"

int np_brute_run(np_dns_engine_t *engine,
                 const char *domain,
                 const np_subenum_config_t *cfg,
                 uint16_t depth);

#endif
