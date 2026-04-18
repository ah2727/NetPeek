#ifndef NP_RECON_GRAPH_H
#define NP_RECON_GRAPH_H

#include <stdint.h>

#include "recon/context.h"
#include "recon/graph_types.h"

typedef enum {
    NP_NODE_HOST = 0,
    NP_NODE_SERVICE,
    NP_NODE_OS,
    NP_NODE_INTERFACE,
    NP_NODE_CREDENTIAL,
    NP_NODE_FINDING
} np_node_type_t;

typedef struct {
    uint64_t id;
    np_node_type_t type;
    void *payload;
} np_node_t;

uint64_t np_graph_add_host(np_recon_context_t *ctx, const np_target_t *target);
uint64_t np_graph_get_or_add_host(np_recon_context_t *ctx, const np_target_t *target);
uint64_t np_graph_add_service(np_recon_context_t *ctx, const np_port_result_t *service);
uint64_t np_graph_add_os(np_recon_context_t *ctx, const np_os_result_t *os);
uint64_t np_graph_find_host(np_recon_context_t *ctx, const np_target_t *target);
uint64_t np_graph_add_host_payload(np_recon_context_t *ctx, const np_host_payload_t *host);
uint64_t np_graph_add_service_payload(np_recon_context_t *ctx, const np_service_payload_t *service);
np_status_t np_graph_sync_services_from_targets(np_recon_context_t *ctx);

void np_graph_link(np_recon_context_t *ctx,
                   uint64_t src,
                   uint64_t dst,
                   const char *relation);

uint64_t np_graph_node_count(const np_recon_context_t *ctx);
uint64_t np_graph_edge_count(const np_recon_context_t *ctx);

#endif
