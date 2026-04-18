#define _POSIX_C_SOURCE 200809L

#include "subenum/result_store.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static uint64_t hash_fqdn(const char *s)
{
    uint64_t hash = 1469598103934665603ULL;
    while (*s)
    {
        unsigned char c = (unsigned char)tolower((unsigned char)*s++);
        hash ^= c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static int fqdn_eq_ci(const char *a, const char *b)
{
    while (*a && *b)
    {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

np_result_store_t *np_result_store_create(size_t initial_buckets)
{
    np_result_store_t *store;

    if (initial_buckets < 128)
        initial_buckets = 128;

    store = calloc(1, sizeof(*store));
    if (!store)
        return NULL;

    store->buckets = calloc(initial_buckets, sizeof(*store->buckets));
    if (!store->buckets)
    {
        free(store);
        return NULL;
    }

    store->bucket_count = initial_buckets;
    pthread_rwlock_init(&store->rwlock, NULL);
    return store;
}

static void merge_addrs(np_subdomain_entry_t *entry,
                        const np_resolved_addr_t *addrs,
                        size_t addr_count)
{
    if (!addrs || addr_count == 0)
        return;

    free(entry->addrs);
    entry->addrs = calloc(addr_count, sizeof(*entry->addrs));
    if (!entry->addrs)
    {
        entry->addr_count = 0;
        return;
    }

    memcpy(entry->addrs, addrs, addr_count * sizeof(*addrs));
    entry->addr_count = addr_count;
}

bool np_result_store_insert(np_result_store_t *store,
                            const char *fqdn,
                            const np_resolved_addr_t *addrs,
                            size_t addr_count,
                            np_subenum_source_t source,
                            uint16_t depth,
                            double rtt_ms,
                            const char *cname)
{
    size_t idx;
    np_subdomain_entry_t *entry;

    if (!store || !fqdn || !*fqdn)
        return false;

    idx = (size_t)(hash_fqdn(fqdn) % store->bucket_count);
    pthread_rwlock_wrlock(&store->rwlock);

    for (entry = store->buckets[idx]; entry; entry = entry->next)
    {
        if (fqdn_eq_ci(entry->fqdn, fqdn))
        {
            entry->sources |= (uint32_t)source;
            if (depth < entry->depth)
                entry->depth = depth;
            if (rtt_ms > 0.0)
                entry->rtt_ms = rtt_ms;
            if (cname && cname[0])
            {
                strncpy(entry->cname, cname, sizeof(entry->cname) - 1);
                entry->cname[sizeof(entry->cname) - 1] = '\0';
            }
            if (addr_count > 0)
                merge_addrs(entry, addrs, addr_count);
            pthread_rwlock_unlock(&store->rwlock);
            return false;
        }
    }

    entry = calloc(1, sizeof(*entry));
    if (!entry)
    {
        pthread_rwlock_unlock(&store->rwlock);
        return false;
    }

    strncpy(entry->fqdn, fqdn, sizeof(entry->fqdn) - 1);
    entry->depth = depth;
    entry->sources = (uint32_t)source;
    entry->rtt_ms = rtt_ms;
    if (cname && cname[0])
    {
        strncpy(entry->cname, cname, sizeof(entry->cname) - 1);
        entry->cname[sizeof(entry->cname) - 1] = '\0';
    }
    if (addr_count > 0)
        merge_addrs(entry, addrs, addr_count);

    entry->next = store->buckets[idx];
    store->buckets[idx] = entry;
    store->entry_count++;

    pthread_rwlock_unlock(&store->rwlock);
    return true;
}

np_subdomain_entry_t *np_result_store_lookup(np_result_store_t *store,
                                             const char *fqdn)
{
    size_t idx;
    np_subdomain_entry_t *entry;

    if (!store || !fqdn || !*fqdn)
        return NULL;

    idx = (size_t)(hash_fqdn(fqdn) % store->bucket_count);
    pthread_rwlock_rdlock(&store->rwlock);
    for (entry = store->buckets[idx]; entry; entry = entry->next)
    {
        if (fqdn_eq_ci(entry->fqdn, fqdn))
        {
            pthread_rwlock_unlock(&store->rwlock);
            return entry;
        }
    }
    pthread_rwlock_unlock(&store->rwlock);
    return NULL;
}

void np_result_store_foreach(np_result_store_t *store,
                             void (*cb)(const np_subdomain_entry_t *, void *),
                             void *userdata)
{
    size_t i;
    if (!store || !cb)
        return;

    pthread_rwlock_rdlock(&store->rwlock);
    for (i = 0; i < store->bucket_count; i++)
    {
        np_subdomain_entry_t *entry;
        for (entry = store->buckets[i]; entry; entry = entry->next)
            cb(entry, userdata);
    }
    pthread_rwlock_unlock(&store->rwlock);
}

size_t np_result_store_count(const np_result_store_t *store)
{
    if (!store)
        return 0;
    return store->entry_count;
}

void np_result_store_destroy(np_result_store_t *store)
{
    size_t i;
    if (!store)
        return;

    for (i = 0; i < store->bucket_count; i++)
    {
        np_subdomain_entry_t *entry = store->buckets[i];
        while (entry)
        {
            np_subdomain_entry_t *next = entry->next;
            free(entry->addrs);
            free(entry);
            entry = next;
        }
    }

    free(store->buckets);
    pthread_rwlock_destroy(&store->rwlock);
    free(store);
}
