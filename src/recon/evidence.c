#include "recon/evidence.h"

#include <stdlib.h>
#include <string.h>

#include "recon_internal.h"

static bool np_evidence_reserve(np_evidence_store_t *store)
{
    if (store->count < store->cap)
        return true;

    size_t next_cap = store->cap ? store->cap * 2 : 32;
    np_evidence_entry_t *next = realloc(store->items, next_cap * sizeof(*next));
    if (!next)
        return false;

    store->items = next;
    store->cap = next_cap;
    return true;
}

np_evidence_store_t *np_evidence_store_create(void)
{
    np_evidence_store_t *store = calloc(1, sizeof(np_evidence_store_t));
    if (!store)
        return NULL;

    if (pthread_mutex_init(&store->lock, NULL) != 0)
    {
        free(store);
        return NULL;
    }

    return store;
}

void np_evidence_store_destroy(np_evidence_store_t *store)
{
    if (!store)
        return;

    pthread_mutex_destroy(&store->lock);
    free(store->items);
    free(store);
}

uint64_t np_evidence_add(np_recon_context_t *ctx,
                         uint64_t node_id,
                         const np_evidence_t *evidence)
{
    if (!ctx || !ctx->evidence || node_id == 0 || !evidence)
        return 0;

    np_evidence_store_t *store = (np_evidence_store_t *)ctx->evidence;
    pthread_mutex_lock(&store->lock);

    if (!np_evidence_reserve(store))
    {
        pthread_mutex_unlock(&store->lock);
        return 0;
    }

    np_evidence_entry_t *entry = &store->items[store->count++];
    memset(entry, 0, sizeof(*entry));

    entry->id = ++store->next_id;
    entry->node_id = node_id;
    entry->timestamp = evidence->timestamp ? evidence->timestamp : time(NULL);
    entry->confidence = evidence->confidence;
    entry->raw_data = evidence->raw_data;

    if (evidence->source_module)
        strncpy(entry->source_module, evidence->source_module, sizeof(entry->source_module) - 1);
    if (evidence->description)
        strncpy(entry->description, evidence->description, sizeof(entry->description) - 1);

    uint64_t id = entry->id;
    pthread_mutex_unlock(&store->lock);
    return id;
}

uint64_t np_evidence_count(const np_recon_context_t *ctx)
{
    if (!ctx || !ctx->evidence)
        return 0;

    np_evidence_store_t *store = (np_evidence_store_t *)ctx->evidence;
    pthread_mutex_lock(&store->lock);
    uint64_t count = (uint64_t)store->count;
    pthread_mutex_unlock(&store->lock);
    return count;
}
