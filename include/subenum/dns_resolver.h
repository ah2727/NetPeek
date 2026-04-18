#ifndef NP_SUBENUM_DNS_RESOLVER_H
#define NP_SUBENUM_DNS_RESOLVER_H

#include <stdbool.h>
#include "subenum/subenum_types.h"
#include "subenum/result_store.h"

typedef struct np_dns_engine np_dns_engine_t;

np_dns_engine_t *np_dns_engine_create(const np_subenum_config_t *cfg,
                                      np_result_store_t *store);
int np_dns_engine_submit(np_dns_engine_t *engine,
                         const char *fqdn,
                         np_dns_record_type_t qtype,
                         np_subenum_source_t src,
                         uint16_t depth);
int np_dns_engine_run(np_dns_engine_t *engine);
int np_dns_engine_resolve_name(np_dns_engine_t *engine,
                               const char *fqdn,
                               np_resolved_addr_t *out,
                               size_t out_cap,
                               size_t *out_count,
                               double *out_rtt_ms);
np_result_store_t *np_dns_engine_store(np_dns_engine_t *engine);
void np_dns_engine_destroy(np_dns_engine_t *engine);

#endif
