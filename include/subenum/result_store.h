#ifndef NP_SUBENUM_RESULT_STORE_H
#define NP_SUBENUM_RESULT_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include "subenum/subenum_types.h"

typedef struct np_result_store
{
    np_subdomain_entry_t **buckets;
    size_t bucket_count;
    size_t entry_count;
    pthread_rwlock_t rwlock;
} np_result_store_t;

np_result_store_t *np_result_store_create(size_t initial_buckets);
bool np_result_store_insert(np_result_store_t *store,
                            const char *fqdn,
                            const np_resolved_addr_t *addrs,
                            size_t addr_count,
                            np_subenum_source_t source,
                            uint16_t depth,
                            double rtt_ms,
                            const char *cname);
np_subdomain_entry_t *np_result_store_lookup(np_result_store_t *store,
                                             const char *fqdn);
void np_result_store_foreach(np_result_store_t *store,
                             void (*cb)(const np_subdomain_entry_t *, void *),
                             void *userdata);
size_t np_result_store_count(const np_result_store_t *store);
void np_result_store_destroy(np_result_store_t *store);

#endif
