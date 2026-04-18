/*
 * NetPeek - Target resolution, CIDR expansion, and utilities
 */

#define _POSIX_C_SOURCE 200809L

#include "target.h"
#include "netpeek.h"
#include "utils.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

/* ────────────────────────────────────── */
/* CIDR detection                        */
/* ────────────────────────────────────── */

bool np_target_is_cidr(const char *str)
{
    return (strchr(str, '/') != NULL);
}

/* ────────────────────────────────────── */
/* Resolve single host                   */
/* ────────────────────────────────────── */

np_status_t np_target_resolve(np_target_t *target)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    int rc = getaddrinfo(target->hostname, NULL, &hints, &res);
    if (rc != 0 || !res)
        return NP_ERR_RESOLVE;

    for (struct addrinfo *p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            memcpy(&target->addr4, p->ai_addr, sizeof(struct sockaddr_in));
            target->is_ipv6 = false;

            inet_ntop(AF_INET, &target->addr4.sin_addr,
                      target->ip, sizeof(target->ip));

            freeaddrinfo(res);
            return NP_OK;
        }
        if (p->ai_family == AF_INET6) {
            memcpy(&target->addr6, p->ai_addr, sizeof(struct sockaddr_in6));
            target->is_ipv6 = true;

            inet_ntop(AF_INET6, &target->addr6.sin6_addr,
                      target->ip, sizeof(target->ip));

            freeaddrinfo(res);
            return NP_OK;
        }
    }

    freeaddrinfo(res);
    return NP_ERR_RESOLVE;
}

/* ────────────────────────────────────────────────── */
/* Helper: check if a target is already resolved     */
/* (ip[] is non-empty and addr4/addr6 is filled in)  */
/* ────────────────────────────────────────────────── */

static bool
target_is_resolved(const np_target_t *t)
{
    return (t->ip[0] != '\0');
}

static void mask_ipv6_prefix(uint8_t bytes[16], int prefix)
{
    int full = prefix / 8;
    int rem = prefix % 8;

    for (int i = full + (rem ? 1 : 0); i < 16; i++)
        bytes[i] = 0;

    if (rem && full < 16)
        bytes[full] &= (uint8_t)(0xffu << (8 - rem));
}

static void add_u32_to_ipv6(uint8_t bytes[16], uint32_t add)
{
    int idx = 15;
    uint32_t carry = add;

    while (idx >= 0 && carry > 0)
    {
        uint32_t v = (uint32_t)bytes[idx] + (carry & 0xffu);
        bytes[idx] = (uint8_t)(v & 0xffu);
        carry = (carry >> 8) + (v >> 8);
        idx--;
    }
}

/* ────────────────────────────────────── */
/* CIDR expansion (IPv4 + IPv6)          */
/* ────────────────────────────────────── */

np_status_t np_target_expand_cidr(const char *cidr_str,
                                  np_target_t **out_targets,
                                  uint32_t *out_count)
{
    char ip_str[64];
    int prefix;

    if (sscanf(cidr_str, "%63[^/]/%d", ip_str, &prefix) != 2)
        return NP_ERR_ARGS;

    bool is_ipv6 = strchr(ip_str, ':') != NULL;
    np_target_t *targets = NULL;
    uint32_t hosts = 0;

    if (!is_ipv6)
    {
        if (prefix < 0 || prefix > 32)
            return NP_ERR_ARGS;

        struct in_addr base_addr;
        if (inet_pton(AF_INET, ip_str, &base_addr) != 1)
            return NP_ERR_ARGS;

        uint32_t base = ntohl(base_addr.s_addr);
        uint32_t mask = prefix == 0 ? 0 : (~0U << (32 - prefix));
        uint32_t network = base & mask;
        hosts = 1U << (32 - prefix);

        if (hosts > NP_MAX_TARGETS)
            return NP_ERR_ARGS;

        targets = calloc(hosts, sizeof(np_target_t));
        if (!targets)
            return NP_ERR_MEMORY;

        for (uint32_t i = 0; i < hosts; i++) {
            uint32_t ip = network + i;
            struct in_addr addr;
            addr.s_addr = htonl(ip);

            inet_ntop(AF_INET, &addr,
                      targets[i].hostname,
                      sizeof(targets[i].hostname));
            targets[i].addr4.sin_family = AF_INET;
            targets[i].addr4.sin_addr = addr;
            strncpy(targets[i].ip, targets[i].hostname,
                    sizeof(targets[i].ip) - 1);
            targets[i].ip[sizeof(targets[i].ip) - 1] = '\0';
            targets[i].is_ipv6 = false;
        }
    }
    else
    {
        if (prefix < 0 || prefix > 128)
            return NP_ERR_ARGS;

        int host_bits = 128 - prefix;
        if (host_bits > 12)
            return NP_ERR_ARGS;

        struct in6_addr base6;
        if (inet_pton(AF_INET6, ip_str, &base6) != 1)
            return NP_ERR_ARGS;

        hosts = 1u << host_bits;
        if (hosts > NP_MAX_TARGETS)
            return NP_ERR_ARGS;

        targets = calloc(hosts, sizeof(np_target_t));
        if (!targets)
            return NP_ERR_MEMORY;

        uint8_t network[16];
        memcpy(network, base6.s6_addr, 16);
        mask_ipv6_prefix(network, prefix);

        for (uint32_t i = 0; i < hosts; i++)
        {
            uint8_t cur[16];
            memcpy(cur, network, 16);
            add_u32_to_ipv6(cur, i);

            inet_ntop(AF_INET6, cur,
                      targets[i].hostname,
                      sizeof(targets[i].hostname));

            targets[i].addr6.sin6_family = AF_INET6;
            memcpy(&targets[i].addr6.sin6_addr, cur, 16);
            strncpy(targets[i].ip, targets[i].hostname,
                    sizeof(targets[i].ip) - 1);
            targets[i].ip[sizeof(targets[i].ip) - 1] = '\0';
            targets[i].is_ipv6 = true;
        }
    }

    *out_targets = targets;
    *out_count = hosts;

    LOGI("Expanded CIDR %s → %u hosts", cidr_str, hosts);
    return NP_OK;
}

/* ────────────────────────────────────────────── */
/* Parallel DNS resolution                       */
/* ────────────────────────────────────────────── */

#define NP_RESOLVE_BATCH_SIZE  32
#define NP_RESOLVE_MAX_THREADS 16

typedef struct {
    np_target_t *targets;       /* array slice start       */
    uint32_t     count;         /* number in this batch    */
    uint32_t     resolved;      /* count successfully done */
    uint32_t     failed;        /* count failed            */
} np_resolve_batch_t;

static void *
np_resolve_worker(void *arg)
{
    np_resolve_batch_t *batch = arg;

    batch->resolved = 0;
    batch->failed   = 0;

    for (uint32_t i = 0; i < batch->count; i++) {
        np_target_t *t = &batch->targets[i];

        /* Skip targets already resolved (e.g., from CIDR expansion) */
        if (target_is_resolved(t)) {
            batch->resolved++;
            continue;
        }

        np_status_t rc = np_target_resolve(t);
        if (rc == NP_OK) {
            batch->resolved++;
        } else {
            LOGW("Failed to resolve: %s", t->hostname);
            batch->failed++;
        }
    }

    return NULL;
}

/*
 * Matches declaration: np_status_t np_target_resolve_all(np_config_t *cfg);
 */
np_status_t np_target_resolve_all(np_config_t *cfg)
{
    if (!cfg || !cfg->targets || cfg->target_count == 0)
        return NP_ERR_ARGS;

    np_target_t *targets = cfg->targets;
    uint32_t     count   = cfg->target_count;

    /* Single target: resolve directly, no threading overhead */
    if (count == 1) {
        if (target_is_resolved(&targets[0]))
            return NP_OK;
        return np_target_resolve(&targets[0]);
    }

    /* Split into batches and resolve in parallel */
    uint32_t nbatches = (count + NP_RESOLVE_BATCH_SIZE - 1)
                        / NP_RESOLVE_BATCH_SIZE;

    /* Cap thread count */
    if (nbatches > NP_RESOLVE_MAX_THREADS)
        nbatches = NP_RESOLVE_MAX_THREADS;

    /* Recompute batch size based on capped thread count */
    uint32_t batch_size = (count + nbatches - 1) / nbatches;

    np_resolve_batch_t *batches = calloc(nbatches, sizeof(*batches));
    pthread_t          *threads = calloc(nbatches, sizeof(*threads));

    if (!batches || !threads) {
        free(batches);
        free(threads);
        return NP_ERR_MEMORY;
    }

    LOGI("Resolving %u targets using %u threads...", count, nbatches);

    /* Launch resolver threads */
    uint32_t offset = 0;
    uint32_t actual_batches = 0;

    for (uint32_t i = 0; i < nbatches && offset < count; i++) {
        uint32_t this_batch = batch_size;
        if (offset + this_batch > count)
            this_batch = count - offset;

        batches[i].targets = &targets[offset];
        batches[i].count   = this_batch;
        offset += this_batch;

        int err = pthread_create(&threads[i], NULL,
                                 np_resolve_worker, &batches[i]);
        if (err != 0) {
            LOGW("Resolver thread %u failed, falling back to inline", i);
            np_resolve_worker(&batches[i]);
            threads[i] = 0;
        }

        actual_batches++;
    }

    /* Join all resolver threads */
    uint32_t total_resolved = 0;
    uint32_t total_failed   = 0;

    for (uint32_t i = 0; i < actual_batches; i++) {
        if (threads[i])
            pthread_join(threads[i], NULL);

        total_resolved += batches[i].resolved;
        total_failed   += batches[i].failed;
    }

    free(batches);
    free(threads);

    LOGI("Resolution complete: %u resolved, %u failed",
         total_resolved, total_failed);

    if (total_resolved == 0)
        return NP_ERR_RESOLVE;

    return NP_OK;
}

/* ────────────────────────────────────── */
/* Shuffle targets (for evasion)         */
/* ────────────────────────────────────── */

void np_target_shuffle(np_target_t *targets, uint32_t count)
{
    if (count < 2)
        return;

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    for (uint32_t i = count - 1; i > 0; i--) {
        uint32_t j = (uint32_t)(rand() % (i + 1));

        np_target_t tmp = targets[i];
        targets[i]      = targets[j];
        targets[j]      = tmp;
    }
}

/* ────────────────────────────────────── */
/* Free results for a single target      */
/* ────────────────────────────────────── */

/*
 * Matches declaration: void np_target_free_results(np_target_t *target);
 */
void np_target_free_results(np_target_t *target)
{
    if (!target)
        return;

    if (target->results) {
        free(target->results);
        target->results    = NULL;
        target->port_count = 0;
    }
}
