#ifndef NP_SUBENUM_PERMUTE_H
#define NP_SUBENUM_PERMUTE_H

#include "subenum/dns_resolver.h"
#include "subenum/result_store.h"

int np_permute_run(np_dns_engine_t *engine,
                   const char *domain,
                   np_result_store_t *store,
                   uint16_t depth);

#endif
