#ifndef NP_UDP_PROBE_CACHE_H
#define NP_UDP_PROBE_CACHE_H

#include <stddef.h>
#include <stdint.h>

#include "netpeek.h"

#define NP_UDP_MAX_CHAIN_MATCHES 4
#define NP_UDP_MAX_CHAIN_PROBES (NP_UDP_MAX_CHAIN_MATCHES + 1)

typedef struct np_udp_probe_desc
{
    const char *name;
    const uint8_t *payload;
    size_t len;
    uint32_t wait_ms;
} np_udp_probe_desc_t;

typedef struct np_udp_probe_chain
{
    uint16_t port;
    np_udp_probe_desc_t probes[NP_UDP_MAX_CHAIN_PROBES];
    size_t probe_count;
} np_udp_probe_chain_t;

typedef struct np_udp_probe_cache
{
    np_udp_probe_chain_t *chains;
    size_t chain_count;
} np_udp_probe_cache_t;

int np_udp_probe_cache_init(np_udp_probe_cache_t *cache, const np_config_t *cfg);
void np_udp_probe_cache_destroy(np_udp_probe_cache_t *cache);
const np_udp_probe_chain_t *np_udp_probe_cache_find(const np_udp_probe_cache_t *cache,
                                                    uint16_t port);

#endif
