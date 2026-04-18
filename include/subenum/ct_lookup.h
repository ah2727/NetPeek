#ifndef NP_SUBENUM_CT_LOOKUP_H
#define NP_SUBENUM_CT_LOOKUP_H

#include "subenum/dns_resolver.h"
#include "subenum/subenum_types.h"

int np_ct_lookup(const char *domain,
                 const np_subenum_config_t *cfg,
                 np_dns_engine_t *engine,
                 uint16_t depth);

int np_ct_lookup_multi(const char *domain,
                       const np_subenum_config_t *cfg,
                       np_dns_engine_t *engine,
                       uint16_t depth);

#endif
