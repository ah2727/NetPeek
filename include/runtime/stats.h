#ifndef NP_RUNTIME_STATS_H
#define NP_RUNTIME_STATS_H

#include <stdbool.h>
#include <stdint.h>

#include "netpeek.h"

typedef struct np_stats_snapshot
{
    uint64_t pkts_sent;
    uint64_t pkts_recv;
    uint64_t ports_open;
    uint64_t ports_closed;
    uint64_t ports_filtered;
    uint64_t hosts_completed;
    uint64_t hosts_total;
    uint64_t work_completed;
    uint64_t work_total;
    uint32_t current_rate;
    double retrans_ratio;
} np_stats_snapshot_t;

void np_stats_reset(void);
void np_stats_set_hosts_total(uint64_t total);
void np_stats_inc_hosts_completed(void);
void np_stats_set_work_total(uint64_t total);
void np_stats_inc_work_completed(uint64_t n);
void np_stats_inc_pkts_sent(uint64_t n);
void np_stats_inc_pkts_recv(uint64_t n);
void np_stats_inc_port_state(np_port_state_t state);
void np_stats_set_rate(uint32_t current_rate, double retrans_ratio);
void np_stats_snapshot(np_stats_snapshot_t *out);

bool np_stats_display_should_run(const np_config_t *cfg);
int np_stats_display_start(const np_config_t *cfg);
void np_stats_display_stop(void);

#endif
