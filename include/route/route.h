#ifndef NP_ROUTE_H
#define NP_ROUTE_H

#include <stdbool.h>
#include <stdint.h>

#include "netpeek.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    const char *target;
    np_port_spec_t ports;
    uint32_t threads;
    uint32_t timeout_ms;
    uint32_t max_hops;
    bool verbose;
    bool json_output;
    const char *output_file;
} np_route_options_t;

typedef struct
{
    uint8_t ttl;
    char ip[NP_MAX_IP_LEN];
    char hostname[NP_MAX_HOSTNAME_LEN + 1];
    double rtt_ms;
    bool timeout;
    bool is_target;
    bool is_ipv6;

    uint16_t *open_ports;
    uint32_t open_port_count;
} np_route_hop_t;

typedef struct
{
    char target_input[NP_MAX_HOSTNAME_LEN + 1];
    char target_ip[NP_MAX_IP_LEN];
    bool target_is_ipv6;

    np_route_hop_t *hops;
    uint32_t hop_count;
} np_route_result_t;

np_status_t np_route_traceroute(const np_target_t *target,
                                const np_route_options_t *opts,
                                np_route_result_t *out);

np_status_t np_route_scan_hops(np_route_result_t *result,
                               const np_route_options_t *opts);

np_status_t np_route_write_output(np_route_result_t *result,
                                  const np_route_options_t *opts);

void np_route_result_free(np_route_result_t *result);

#ifdef __cplusplus
}
#endif

#endif
