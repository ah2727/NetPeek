#include "scanner_internal.h"
#include "core/error.h"
#include "metrics.h"
#include "runtime/stats.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

static const char *np_result_proto_name(np_scan_type_t scan_type)
{
    switch (scan_type)
    {
    case NP_SCAN_UDP:
        return "udp";
    case NP_SCAN_SCTP_INIT:
    case NP_SCAN_SCTP_COOKIE_ECHO:
        return "sctp";
    case NP_SCAN_IP_PROTOCOL:
        return "ip";
    default:
        return "tcp";
    }
}

/*
 * FINAL-STATE RESULT COMMIT
 *
 * This is the ONLY place where:
 *  - a port reaches a FINAL state
 *  - completed_work is incremented
 *  - metrics are updated
 *
 * Safe against:
 *  - retries, reconnects
 *  - interruption cleanup
 *  - queue draining
 */
void np_record_result(np_worker_ctx_t *ctx,
                      uint32_t target_idx,
                      uint32_t port_idx,
                      uint16_t port,
                      np_port_state_t state,
                      double rtt)
{
    np_target_t *target = &ctx->cfg->targets[target_idx];

    /* ✅ NEW: Bounds guard — prevent buffer overrun if port_idx is bad */
    if (port_idx >= ctx->total_work)
    {
        np_error(NP_ERR_RUNTIME, "[BUG] np_record_result: port_idx=%u >= total_work=%u (port=%u)\n",
                port_idx, ctx->total_work, port);
        return;
    }

    np_port_result_t *res = &target->results[port_idx];

    /* ---- FINAL-STATE GUARD ---- */
    if (res->completed)
        return;

    res->completed = true;

    /* ---- STORE RESULT ---- */
    res->port   = port;
    strncpy(res->proto,
            np_result_proto_name(ctx->cfg->scan_type),
            sizeof(res->proto) - 1);
    res->proto[sizeof(res->proto) - 1] = '\0';
    res->state  = state;
    res->rtt_ms = rtt;

    if (state == NP_PORT_OPEN)
    {
        const char *svc = np_service_name(port);
        strncpy(res->service, svc, sizeof(res->service) - 1);
        res->service[sizeof(res->service) - 1] = '\0';
    }
    else
    {
        res->service[0] = '\0';
    }

    /* ---- PROGRESS (ONCE, MONOTONIC) ---- */
    pthread_mutex_lock(ctx->completed_lock);
    (*ctx->completed_work)++;
    pthread_mutex_unlock(ctx->completed_lock);

    /* ---- METRICS ---- */
    pthread_mutex_lock(ctx->metrics_lock);
    np_metrics_update(ctx->metrics, state, rtt);
    pthread_mutex_unlock(ctx->metrics_lock);

    np_stats_inc_port_state(state);
}

/*
 * Mark in-flight connections as FILTERED when interrupted.
 * Safe: np_record_result() guards against double-counting.
 *
 * ✅ FIX: Use slot->item.* instead of removed slot-level fields.
 */
void np_mark_active_interrupted(np_worker_ctx_t *ctx,
                                conn_slot_t *slots,
                                int n)
{
    for (int i = 0; i < n; i++)
    {
        if (!slots[i].active)
            continue;

        double elapsed = np_timer_elapsed_ms(&slots[i].timer);

        np_record_result(ctx,
                         slots[i].item.target_idx,
                         slots[i].item.port_idx,
                         slots[i].item.port,
                         NP_PORT_FILTERED,
                         elapsed);

        slots[i].active = false;
    }
}

/*
 * Mark work items that were never started as FILTERED.
 *
 * Drains the remaining work queue so progress can reach 100%.
 */
void np_mark_unstarted_remaining(np_worker_ctx_t *ctx)
{
    np_work_item_t item;

    while (np_wq_pop(ctx->queue, &item))
    {
        np_record_result(ctx,
                         item.target_idx,
                         item.port_idx,
                         item.port,
                         NP_PORT_FILTERED,
                         0.0);
    }
}

/*
 * Progress display helper.
 */
void np_print_progress(np_work_queue_t *q,
                       uint32_t total_work,
                       uint32_t completed_work)
{
    uint32_t dispatched;
    double pct;

    dispatched = np_wq_popped_count(q);
    pct = total_work ? (100.0 * completed_work / total_work) : 100.0;

    np_error(NP_ERR_RUNTIME, "\r[*] Progress: %u/%u (%.1f%%), dispatched=%u",
            completed_work,
            total_work,
            pct,
            dispatched);

    fflush(stderr);
}
