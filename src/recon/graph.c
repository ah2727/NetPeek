#include "recon/graph.h"

#include <stdlib.h>
#include <string.h>

#include "recon_internal.h"

static bool np_graph_reserve_nodes(np_graph_store_t *store)
{
    if (store->node_count < store->node_cap)
        return true;

    size_t next_cap = store->node_cap ? store->node_cap * 2 : 32;
    np_graph_node_store_t *next = realloc(store->nodes, next_cap * sizeof(*next));
    if (!next)
        return false;

    store->nodes = next;
    store->node_cap = next_cap;
    return true;
}

static bool np_graph_reserve_edges(np_graph_store_t *store)
{
    if (store->edge_count < store->edge_cap)
        return true;

    size_t next_cap = store->edge_cap ? store->edge_cap * 2 : 64;
    np_graph_edge_store_t *next = realloc(store->edges, next_cap * sizeof(*next));
    if (!next)
        return false;

    store->edges = next;
    store->edge_cap = next_cap;
    return true;
}

static uint64_t np_graph_add_payload_locked(np_graph_store_t *store,
                                            np_node_type_t type,
                                            const void *payload,
                                            size_t payload_size)
{
    if (!store)
        return 0;

    if (!np_graph_reserve_nodes(store))
        return 0;

    np_graph_node_store_t *node = &store->nodes[store->node_count++];
    memset(node, 0, sizeof(*node));
    node->id = ++store->next_node_id;
    node->type = type;

    if (payload && payload_size)
    {
        node->payload = malloc(payload_size);
        if (!node->payload)
        {
            store->node_count--;
            return 0;
        }
        memcpy(node->payload, payload, payload_size);
        node->payload_size = payload_size;
    }

    return node->id;
}

static uint64_t np_graph_find_host_locked(np_graph_store_t *store, const np_target_t *target)
{
    if (!store || !target)
        return 0;

    for (size_t i = 0; i < store->node_count; i++)
    {
        np_graph_node_store_t *node = &store->nodes[i];
        if (node->type != NP_NODE_HOST ||
            node->payload_size != sizeof(np_target_t) ||
            !node->payload)
            continue;

        const np_target_t *existing = (const np_target_t *)node->payload;
        if (strcmp(existing->ip, target->ip) == 0 &&
            strcmp(existing->hostname, target->hostname) == 0)
            return node->id;
    }

    return 0;
}

np_graph_store_t *np_graph_store_create(void)
{
    np_graph_store_t *store = calloc(1, sizeof(np_graph_store_t));
    if (!store)
        return NULL;

    if (pthread_mutex_init(&store->lock, NULL) != 0)
    {
        free(store);
        return NULL;
    }

    return store;
}

void np_graph_store_destroy(np_graph_store_t *store)
{
    if (!store)
        return;

    for (size_t i = 0; i < store->node_count; i++)
        free(store->nodes[i].payload);

    pthread_mutex_destroy(&store->lock);
    free(store->nodes);
    free(store->edges);
    free(store);
}

uint64_t np_graph_add_host(np_recon_context_t *ctx, const np_target_t *target)
{
    if (!ctx || !ctx->graph)
        return 0;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;
    pthread_mutex_lock(&store->lock);
    uint64_t id = np_graph_add_payload_locked(store,
                                              NP_NODE_HOST,
                                              target,
                                              target ? sizeof(*target) : 0);
    pthread_mutex_unlock(&store->lock);
    return id;
}

uint64_t np_graph_get_or_add_host(np_recon_context_t *ctx, const np_target_t *target)
{
    if (!ctx || !ctx->graph || !target)
        return 0;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;
    pthread_mutex_lock(&store->lock);

    uint64_t existing = np_graph_find_host_locked(store, target);
    if (existing != 0)
    {
        pthread_mutex_unlock(&store->lock);
        return existing;
    }

    uint64_t created = np_graph_add_payload_locked(store,
                                                   NP_NODE_HOST,
                                                   target,
                                                   sizeof(*target));
    pthread_mutex_unlock(&store->lock);
    return created;
}

uint64_t np_graph_find_host(np_recon_context_t *ctx, const np_target_t *target)
{
    if (!ctx || !ctx->graph || !target)
        return 0;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;
    pthread_mutex_lock(&store->lock);
    uint64_t id = np_graph_find_host_locked(store, target);
    pthread_mutex_unlock(&store->lock);
    return id;
}

uint64_t np_graph_add_host_payload(np_recon_context_t *ctx, const np_host_payload_t *host)
{
    if (!ctx || !ctx->graph)
        return 0;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;
    pthread_mutex_lock(&store->lock);
    uint64_t id = np_graph_add_payload_locked(store,
                                              NP_NODE_HOST,
                                              host,
                                              host ? sizeof(*host) : 0);
    pthread_mutex_unlock(&store->lock);
    return id;
}

uint64_t np_graph_add_service(np_recon_context_t *ctx, const np_port_result_t *service)
{
    if (!ctx || !ctx->graph)
        return 0;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;
    pthread_mutex_lock(&store->lock);
    uint64_t id = np_graph_add_payload_locked(store,
                                              NP_NODE_SERVICE,
                                              service,
                                              service ? sizeof(*service) : 0);
    pthread_mutex_unlock(&store->lock);
    return id;
}

uint64_t np_graph_add_service_payload(np_recon_context_t *ctx, const np_service_payload_t *service)
{
    if (!ctx || !ctx->graph)
        return 0;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;
    pthread_mutex_lock(&store->lock);
    uint64_t id = np_graph_add_payload_locked(store,
                                              NP_NODE_SERVICE,
                                              service,
                                              service ? sizeof(*service) : 0);
    pthread_mutex_unlock(&store->lock);
    return id;
}

static np_graph_node_store_t *np_graph_find_node(np_graph_store_t *store, uint64_t id)
{
    if (!store || id == 0)
        return NULL;

    for (size_t i = 0; i < store->node_count; i++)
    {
        if (store->nodes[i].id == id)
            return &store->nodes[i];
    }

    return NULL;
}

static np_target_t *np_graph_find_target(np_recon_context_t *ctx,
                                         const char *host_ip,
                                         const char *host_name)
{
    if (!ctx || !ctx->cfg)
        return NULL;

    for (uint32_t i = 0; i < ctx->cfg->target_count; i++)
    {
        np_target_t *target = &ctx->cfg->targets[i];
        bool ip_match = host_ip && host_ip[0] && strcmp(target->ip, host_ip) == 0;
        bool name_match = host_name && host_name[0] && strcmp(target->hostname, host_name) == 0;
        if (ip_match || name_match)
            return target;
    }

    return NULL;
}

static bool np_proto_matches(const char *a, const char *b)
{
    if (!a || !a[0] || !b || !b[0])
        return true;
    return strcmp(a, b) == 0;
}

np_status_t np_graph_sync_services_from_targets(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg || !ctx->graph)
        return NP_ERR_ARGS;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;

    pthread_mutex_lock(&store->lock);

    for (size_t i = 0; i < store->edge_count; i++)
    {
        np_graph_edge_store_t *edge = &store->edges[i];
        if (strcmp(edge->relation, NP_RECON_REL_EXPOSES) != 0)
            continue;

        np_graph_node_store_t *host_node = np_graph_find_node(store, edge->src);
        np_graph_node_store_t *service_node = np_graph_find_node(store, edge->dst);
        if (!host_node || !service_node)
            continue;

        if (host_node->type != NP_NODE_HOST || !host_node->payload)
            continue;

        if (service_node->type != NP_NODE_SERVICE ||
            !service_node->payload ||
            service_node->payload_size != sizeof(np_port_result_t))
            continue;

        const char *host_ip = NULL;
        const char *host_name = NULL;

        if (host_node->payload_size == sizeof(np_target_t))
        {
            const np_target_t *host = (const np_target_t *)host_node->payload;
            host_ip = host->ip;
            host_name = host->hostname;
        }
        else if (host_node->payload_size == sizeof(np_host_payload_t))
        {
            const np_host_payload_t *host = (const np_host_payload_t *)host_node->payload;
            host_ip = host->ip;
            host_name = host->hostname;
        }
        else
        {
            continue;
        }

        np_target_t *target = np_graph_find_target(ctx, host_ip, host_name);
        if (!target)
            continue;

        np_port_result_t *service = (np_port_result_t *)service_node->payload;
        for (uint32_t p = 0; p < target->port_count; p++)
        {
            if (target->results[p].port != service->port)
                continue;
            if (!np_proto_matches(target->results[p].proto, service->proto))
                continue;

            *service = target->results[p];
            break;
        }
    }

    pthread_mutex_unlock(&store->lock);

    return NP_OK;
}

uint64_t np_graph_add_os(np_recon_context_t *ctx, const np_os_result_t *os)
{
    if (!ctx || !ctx->graph)
        return 0;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;
    pthread_mutex_lock(&store->lock);
    uint64_t id = np_graph_add_payload_locked(store,
                                              NP_NODE_OS,
                                              os,
                                              os ? sizeof(*os) : 0);
    pthread_mutex_unlock(&store->lock);
    return id;
}

void np_graph_link(np_recon_context_t *ctx,
                   uint64_t src,
                   uint64_t dst,
                   const char *relation)
{
    if (!ctx || !ctx->graph || src == 0 || dst == 0 || !relation)
        return;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;
    pthread_mutex_lock(&store->lock);
    if (!np_graph_reserve_edges(store))
    {
        pthread_mutex_unlock(&store->lock);
        return;
    }

    np_graph_edge_store_t *edge = &store->edges[store->edge_count++];
    edge->src = src;
    edge->dst = dst;
    strncpy(edge->relation, relation, sizeof(edge->relation) - 1);
    pthread_mutex_unlock(&store->lock);
}

uint64_t np_graph_node_count(const np_recon_context_t *ctx)
{
    if (!ctx || !ctx->graph)
        return 0;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;
    pthread_mutex_lock(&store->lock);
    uint64_t count = (uint64_t)store->node_count;
    pthread_mutex_unlock(&store->lock);
    return count;
}

uint64_t np_graph_edge_count(const np_recon_context_t *ctx)
{
    if (!ctx || !ctx->graph)
        return 0;

    np_graph_store_t *store = (np_graph_store_t *)ctx->graph;
    pthread_mutex_lock(&store->lock);
    uint64_t count = (uint64_t)store->edge_count;
    pthread_mutex_unlock(&store->lock);
    return count;
}
