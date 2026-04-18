#include "scanner_internal.h"
#include "logger.h"
#include "runtime/io_engine.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define NP_IDLE_USEC 1000

static int find_free_slot(conn_slot_t *slots, int n)
{
    for (int i = 0; i < n; i++)
        if (!slots[i].active)
            return i;
    return -1;
}

static void close_slot(conn_slot_t *slot)
{
    if (slot->fd >= 0)
        close(slot->fd);

    slot->fd = -1;
    slot->active = false;
    slot->completed = false;
}

static bool requeue_connect_attempt(np_worker_ctx_t *ctx, const np_work_item_t *item)
{
    if (!ctx || !item)
        return false;

    if (item->attempt >= ctx->cfg->max_retries)
        return false;

    np_work_item_t retry = *item;
    retry.attempt = (uint8_t)(item->attempt + 1);
    np_note_probe_retransmission(ctx->cfg);
    return np_wq_push(ctx->queue, &retry);
}

static int make_nonblocking_connect_socket(const np_target_t *target,
                                           uint16_t port,
                                           int *out_fd,
                                           struct sockaddr_storage *out_addr,
                                           socklen_t *out_len)
{
    if (!target || !out_fd || !out_addr || !out_len)
        return -1;

    int af = target->is_ipv6 ? AF_INET6 : AF_INET;
    int fd = socket(af, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

#ifdef __APPLE__
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    if (np_set_nonblocking(fd) < 0)
    {
        close(fd);
        return -1;
    }

    memset(out_addr, 0, sizeof(*out_addr));
    if (af == AF_INET6)
    {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)out_addr;
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);
        a6->sin6_addr = target->addr6.sin6_addr;
        *out_len = sizeof(*a6);
    }
    else
    {
        struct sockaddr_in *a4 = (struct sockaddr_in *)out_addr;
        a4->sin_family = AF_INET;
        a4->sin_port = htons(port);
        a4->sin_addr = target->addr4.sin_addr;
        *out_len = sizeof(*a4);
    }

    *out_fd = fd;
    return 0;
}

void np_scan_task(void *arg)
{
    np_task_arg_t *targ = arg;
    np_scan_ctx_t *scan_ctx = &targ->ctx;
    np_worker_ctx_t worker_ctx = {
        .cfg = scan_ctx->cfg,
        .queue = scan_ctx->queue,
        .interrupted = scan_ctx->interrupted,
        .metrics = scan_ctx->metrics,
        .metrics_lock = scan_ctx->metrics_lock,
        .total_work = scan_ctx->total_work,
        .completed_work = scan_ctx->completed_work,
        .completed_lock = scan_ctx->completed_lock,
    };
    np_worker_ctx_t *ctx = &worker_ctx;
    const np_config_t *cfg = worker_ctx.cfg;

    np_io_engine_t io_engine;
    conn_slot_t slots[CONNS_PER_THREAD];

    int active = 0;
    bool queue_empty = false;
    uint64_t last_probe_us = 0;
    uint64_t host_started_us = np_now_monotonic_us();
    uint32_t effective_timeout_ms = np_effective_timeout_ms(cfg);

    LOGD("Connect scan worker started (total_work=%u)", ctx->total_work);

    memset(slots, 0, sizeof(slots));
    for (int i = 0; i < CONNS_PER_THREAD; i++)
        slots[i].fd = -1;

    if (np_io_engine_create(&io_engine, CONNS_PER_THREAD) < 0)
    {
        LOGE("I/O engine init failed — worker exiting");
        np_completion_signal(targ->completion);
        return;
    }

    while (!(*ctx->interrupted))
    {
        if (np_host_timeout_reached(cfg, host_started_us))
            break;

        while (!queue_empty && active < CONNS_PER_THREAD)
        {
            if (np_host_timeout_reached(cfg, host_started_us))
                break;

            np_work_item_t item;
            if (!np_wq_pop(ctx->queue, &item))
            {
                queue_empty = true;
                LOGD("Work queue exhausted, draining %d active slots", active);
                break;
            }

            uint16_t port = item.port;
            if (!port)
            {
                LOGW("Skipping port 0 (target_idx=%u, port_idx=%u)",
                     item.target_idx, item.port_idx);
                np_record_result(ctx, item.target_idx, item.port_idx,
                                 0, NP_PORT_FILTERED, 0.0);
                continue;
            }

            int si = find_free_slot(slots, CONNS_PER_THREAD);
            if (si < 0)
                break;

            int fd = -1;
            struct sockaddr_storage addr;
            socklen_t addr_len = 0;
            if (make_nonblocking_connect_socket(&cfg->targets[item.target_idx],
                                                port,
                                                &fd,
                                                &addr,
                                                &addr_len) < 0)
            {
                if (!requeue_connect_attempt(ctx, &item))
                {
                    LOGD("Connect socket setup failed: port %u → FILTERED", port);
                    np_record_result(ctx, item.target_idx, item.port_idx,
                                     port, NP_PORT_FILTERED, 0.0);
                }
                continue;
            }

            np_wait_probe_budget(cfg, &last_probe_us);
            np_note_probe_sent(cfg);

            slots[si].fd = fd;
            slots[si].item = item;
            slots[si].active = true;
            slots[si].completed = false;
            np_timer_start(&slots[si].timer);

            if (io_engine.submit_connect(&io_engine,
                                         fd,
                                         (struct sockaddr *)&addr,
                                         addr_len,
                                         &slots[si]) < 0)
            {
                LOGW("submit_connect failed for fd=%d port=%u", fd, port);
                close_slot(&slots[si]);
                if (!requeue_connect_attempt(ctx, &item))
                {
                    np_record_result(ctx, item.target_idx, item.port_idx,
                                     port, NP_PORT_FILTERED, 0.0);
                }
                continue;
            }

            active++;
        }

        np_io_event_t events[CONNS_PER_THREAD];
        int nev = io_engine.poll(&io_engine, events, CONNS_PER_THREAD, 10);
        if (nev < 0)
            nev = 0;

        for (int i = 0; i < nev; i++)
        {
            conn_slot_t *slot = (conn_slot_t *)events[i].user_data;
            if (!slot || !slot->active)
                continue;

            slot->completed = true;
            double rtt = np_timer_elapsed_ms(&slot->timer);

            np_port_state_t state = NP_PORT_FILTERED;
            if (events[i].error == 0)
            {
                state = NP_PORT_OPEN;
            }
            else if (events[i].error == ECONNREFUSED)
            {
                state = NP_PORT_CLOSED;
            }
            else
            {
                if (requeue_connect_attempt(ctx, &slot->item))
                {
                    close_slot(slot);
                    active--;
                    continue;
                }
            }

            np_record_result(ctx,
                             slot->item.target_idx,
                             slot->item.port_idx,
                             slot->item.port,
                             state,
                             rtt);

            close_slot(slot);
            active--;
        }

        for (int i = 0; i < CONNS_PER_THREAD; i++)
        {
            conn_slot_t *slot = &slots[i];
            if (!slot->active)
                continue;

            double rtt = np_timer_elapsed_ms(&slot->timer);
            if (rtt <= effective_timeout_ms)
                continue;

            close_slot(slot);
            if (!requeue_connect_attempt(ctx, &slot->item))
            {
                np_record_result(ctx,
                                 slot->item.target_idx,
                                 slot->item.port_idx,
                                 slot->item.port,
                                 NP_PORT_FILTERED,
                                 rtt);
            }
            active--;
        }

        if (queue_empty && active == 0)
            break;

        if (active == 0)
            usleep(NP_IDLE_USEC);
    }

    if (np_host_timeout_reached(cfg, host_started_us))
    {
        np_mark_unstarted_remaining(ctx);
        np_mark_active_interrupted(ctx, slots, CONNS_PER_THREAD);
    }

    if (*ctx->interrupted)
        np_mark_active_interrupted(ctx, slots, CONNS_PER_THREAD);

    if (io_engine.destroy)
        io_engine.destroy(&io_engine);

    LOGD("Connect scan worker exiting");
    np_completion_signal(targ->completion);
}
