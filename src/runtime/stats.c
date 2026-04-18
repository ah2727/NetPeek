#include "runtime/stats.h"

#include <stdatomic.h>
#include <string.h>

static _Atomic uint64_t g_pkts_sent;
static _Atomic uint64_t g_pkts_recv;
static _Atomic uint64_t g_ports_open;
static _Atomic uint64_t g_ports_closed;
static _Atomic uint64_t g_ports_filtered;
static _Atomic uint64_t g_hosts_completed;
static _Atomic uint64_t g_hosts_total;
static _Atomic uint64_t g_work_completed;
static _Atomic uint64_t g_work_total;
static _Atomic uint32_t g_current_rate;
static _Atomic uint64_t g_retrans_ppm;

void np_stats_reset(void)
{
    atomic_store(&g_pkts_sent, 0);
    atomic_store(&g_pkts_recv, 0);
    atomic_store(&g_ports_open, 0);
    atomic_store(&g_ports_closed, 0);
    atomic_store(&g_ports_filtered, 0);
    atomic_store(&g_hosts_completed, 0);
    atomic_store(&g_hosts_total, 0);
    atomic_store(&g_work_completed, 0);
    atomic_store(&g_work_total, 0);
    atomic_store(&g_current_rate, 0);
    atomic_store(&g_retrans_ppm, 0);
}

void np_stats_set_hosts_total(uint64_t total)
{
    atomic_store(&g_hosts_total, total);
}

void np_stats_inc_hosts_completed(void)
{
    atomic_fetch_add(&g_hosts_completed, 1);
    atomic_fetch_add(&g_work_completed, 1);
}

void np_stats_set_work_total(uint64_t total)
{
    atomic_store(&g_work_total, total);
}

void np_stats_inc_work_completed(uint64_t n)
{
    if (n == 0)
        return;

    atomic_fetch_add(&g_work_completed, n);
}

void np_stats_inc_pkts_sent(uint64_t n)
{
    atomic_fetch_add(&g_pkts_sent, n);
}

void np_stats_inc_pkts_recv(uint64_t n)
{
    atomic_fetch_add(&g_pkts_recv, n);
}

void np_stats_inc_port_state(np_port_state_t state)
{
    switch (state)
    {
    case NP_PORT_OPEN:
        atomic_fetch_add(&g_ports_open, 1);
        break;
    case NP_PORT_CLOSED:
        atomic_fetch_add(&g_ports_closed, 1);
        break;
    case NP_PORT_FILTERED:
    case NP_PORT_OPEN_FILTERED:
    case NP_PORT_UNKNOWN:
    default:
        atomic_fetch_add(&g_ports_filtered, 1);
        break;
    }
}

void np_stats_set_rate(uint32_t current_rate, double retrans_ratio)
{
    if (retrans_ratio < 0.0)
        retrans_ratio = 0.0;
    uint64_t ppm = (uint64_t)(retrans_ratio * 1000000.0);
    atomic_store(&g_current_rate, current_rate);
    atomic_store(&g_retrans_ppm, ppm);
}

void np_stats_snapshot(np_stats_snapshot_t *out)
{
    if (!out)
        return;

    memset(out, 0, sizeof(*out));
    out->pkts_sent = atomic_load(&g_pkts_sent);
    out->pkts_recv = atomic_load(&g_pkts_recv);
    out->ports_open = atomic_load(&g_ports_open);
    out->ports_closed = atomic_load(&g_ports_closed);
    out->ports_filtered = atomic_load(&g_ports_filtered);
    out->hosts_completed = atomic_load(&g_hosts_completed);
    out->hosts_total = atomic_load(&g_hosts_total);
    out->work_completed = atomic_load(&g_work_completed);
    out->work_total = atomic_load(&g_work_total);
    out->current_rate = atomic_load(&g_current_rate);
    out->retrans_ratio = (double)atomic_load(&g_retrans_ppm) / 1000000.0;
}
