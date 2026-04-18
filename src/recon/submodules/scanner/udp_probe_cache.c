#include "udp_probe_cache.h"
#include "recon/submodules/os_detect/nmap_probes_generated.h"

#include <stdlib.h>
#include <string.h>

#define NP_UDP_PROBE_LEN 1

typedef struct udp_probe_match
{
    int probe_idx;
    int rarity;
    uint32_t wait_ms;
} udp_probe_match_t;

static const uint8_t g_udp_default_probe[NP_UDP_PROBE_LEN] = {0};

static int cmp_udp_probe_match(const void *a, const void *b)
{
    const udp_probe_match_t *lhs = (const udp_probe_match_t *)a;
    const udp_probe_match_t *rhs = (const udp_probe_match_t *)b;

    if (lhs->rarity != rhs->rarity)
        return lhs->rarity - rhs->rarity;
    if (lhs->wait_ms != rhs->wait_ms)
        return (lhs->wait_ms < rhs->wait_ms) ? -1 : 1;
    return lhs->probe_idx - rhs->probe_idx;
}

static void build_probe_chain(uint16_t port, np_udp_probe_chain_t *out)
{
    memset(out, 0, sizeof(*out));
    out->port = port;

    udp_probe_match_t matches[NP_NMAP_PROBE_COUNT];
    size_t match_count = 0;

    for (int i = 0; i < NP_NMAP_PROBE_COUNT; i++)
    {
        const np_nmap_probe_t *probe = &g_nmap_probes[i];
        if (!probe->protocol || strcmp(probe->protocol, "UDP") != 0)
            continue;

        bool port_match = false;
        for (int p = 0; p < probe->port_count; p++)
        {
            if (probe->ports[p] == port)
            {
                port_match = true;
                break;
            }
        }

        if (!port_match)
            continue;

        matches[match_count].probe_idx = i;
        matches[match_count].rarity = probe->rarity;
        matches[match_count].wait_ms = probe->total_wait_ms;
        match_count++;
    }

    if (match_count > 1)
        qsort(matches, match_count, sizeof(matches[0]), cmp_udp_probe_match);

    for (size_t i = 0; i < match_count && out->probe_count < NP_UDP_MAX_CHAIN_MATCHES; i++)
    {
        const np_nmap_probe_t *probe = &g_nmap_probes[matches[i].probe_idx];
        np_udp_probe_desc_t *dst = &out->probes[out->probe_count++];
        dst->name = probe->name;
        dst->payload = (const uint8_t *)probe->send_data;
        dst->len = (size_t)probe->send_len;
        dst->wait_ms = probe->total_wait_ms;
    }

    out->probes[out->probe_count++] = (np_udp_probe_desc_t){
        .name = "empty-fallback",
        .payload = g_udp_default_probe,
        .len = sizeof(g_udp_default_probe),
        .wait_ms = 0,
    };
}

static int append_unique_port(uint16_t **ports, size_t *count, size_t *cap, uint16_t port)
{
    for (size_t i = 0; i < *count; i++)
    {
        if ((*ports)[i] == port)
            return 0;
    }

    if (*count == *cap)
    {
        size_t new_cap = (*cap == 0) ? 128 : (*cap * 2);
        uint16_t *next = realloc(*ports, new_cap * sizeof(*next));
        if (!next)
            return -1;
        *ports = next;
        *cap = new_cap;
    }

    (*ports)[(*count)++] = port;
    return 0;
}

int np_udp_probe_cache_init(np_udp_probe_cache_t *cache, const np_config_t *cfg)
{
    if (!cache || !cfg)
        return -1;

    memset(cache, 0, sizeof(*cache));

    uint16_t *ports = NULL;
    size_t count = 0;
    size_t cap = 0;

    for (uint32_t ti = 0; ti < cfg->target_count; ti++)
    {
        const np_target_t *target = &cfg->targets[ti];
        for (uint32_t pi = 0; pi < target->port_count; pi++)
        {
            uint16_t port = target->results ? target->results[pi].port : 0;
            if (port == 0)
                continue;
            if (append_unique_port(&ports, &count, &cap, port) < 0)
            {
                free(ports);
                return -1;
            }
        }
    }

    if (count == 0)
    {
        free(ports);
        return 0;
    }

    cache->chains = calloc(count, sizeof(*cache->chains));
    if (!cache->chains)
    {
        free(ports);
        return -1;
    }

    cache->chain_count = count;
    for (size_t i = 0; i < count; i++)
        build_probe_chain(ports[i], &cache->chains[i]);

    free(ports);
    return 0;
}

void np_udp_probe_cache_destroy(np_udp_probe_cache_t *cache)
{
    if (!cache)
        return;

    free(cache->chains);
    memset(cache, 0, sizeof(*cache));
}

const np_udp_probe_chain_t *np_udp_probe_cache_find(const np_udp_probe_cache_t *cache,
                                                    uint16_t port)
{
    if (!cache || !cache->chains)
        return NULL;

    for (size_t i = 0; i < cache->chain_count; i++)
    {
        if (cache->chains[i].port == port)
            return &cache->chains[i];
    }

    return NULL;
}
