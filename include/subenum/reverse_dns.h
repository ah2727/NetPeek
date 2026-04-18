#ifndef NP_SUBENUM_REVERSE_DNS_H
#define NP_SUBENUM_REVERSE_DNS_H

#include "subenum/result_store.h"

int np_reverse_dns_sweep(const char *domain,
                         np_result_store_t *store,
                         uint16_t depth);

#endif
