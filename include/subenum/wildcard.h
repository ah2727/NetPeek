#ifndef NP_SUBENUM_WILDCARD_H
#define NP_SUBENUM_WILDCARD_H

#include <stdbool.h>
#include "subenum/subenum_types.h"
#include "subenum/dns_resolver.h"

int np_wildcard_detect(np_dns_engine_t *engine,
                       const char *domain,
                       np_wildcard_info_t *info);
bool np_wildcard_is_false_positive(const np_wildcard_info_t *info,
                                   const np_subdomain_entry_t *entry);

#endif
