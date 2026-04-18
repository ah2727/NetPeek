#ifndef NP_RECON_GRAPH_TYPES_H
#define NP_RECON_GRAPH_TYPES_H

#include <netinet/in.h>
#include <stdint.h>

#define NP_RECON_REL_EXPOSES "exposes"
#define NP_RECON_REL_RUNS "runs"
#define NP_RECON_REL_IDENTIFIED_BY "identified_by"

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    char hostname[256];
} np_host_payload_t;

typedef struct {
    uint16_t port;
    char proto[8];
    char service[64];
    char product[128];
    char version[64];
} np_service_payload_t;

#endif
