#ifndef NP_RECON_QUERY_H
#define NP_RECON_QUERY_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "recon/context.h"

typedef struct {
    uint64_t id;
    const char *ip;
    const char *hostname;
    bool discovered;
    bool up;
    const char *reason;
    double rtt_ms;
} np_host_view_t;

typedef struct {
    uint64_t node_id;
    uint16_t port;
    const char *proto;
    const char *service;
    const char *state;
    const char *product;
    const char *version;
    bool tls_detected;
} np_service_view_t;

typedef struct {
    uint64_t id;
    const char *source;
    const char *description;
    time_t timestamp;
    double confidence;
} np_evidence_view_t;

typedef struct {
    const char *name;
    double confidence;
} np_os_view_t;

uint32_t np_query_hosts(np_recon_context_t *ctx, np_host_view_t **out);
uint32_t np_query_services(np_recon_context_t *ctx,
                           uint64_t host_id,
                           np_service_view_t **out);
uint32_t np_query_evidence(np_recon_context_t *ctx,
                           uint64_t node_id,
                           np_evidence_view_t **out);
uint32_t np_query_host_os(np_recon_context_t *ctx,
                          uint64_t host_id,
                          np_os_view_t **out);
void np_query_free(void *ptr);

#endif
