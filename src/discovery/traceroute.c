#define _POSIX_C_SOURCE 200809L

#include "traceroute.h"

#include <string.h>

np_status_t np_traceroute_target(const np_config_t *cfg,
                                 np_target_t *target)
{
    (void)cfg;
    if (!target)
        return NP_ERR_ARGS;

    target->trace_hop_count = 0;

    if (target->ip[0] == '\0')
        return NP_OK;

    np_trace_hop_t *hop = &target->trace_hops[0];
    hop->ttl = 1;
    strncpy(hop->ip, target->ip, sizeof(hop->ip) - 1);
    hop->ip[sizeof(hop->ip) - 1] = '\0';
    hop->rtt_ms = target->host_rtt_ms;
    hop->timeout = false;

    target->trace_hop_count = 1;
    return NP_OK;
}
