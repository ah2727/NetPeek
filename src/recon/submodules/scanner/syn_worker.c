#include "scanner_internal.h"
#include "core/error.h"
#include "evasion.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/*
 * SYN scan receive socket — shared by all workers in this process.
 * We listen for SYN-ACK / RST replies on a raw TCP socket.
 */

static int recv_sock = -1;

/* ───────────────────────────────────────────── */
/* Raw receive socket init / close               */
/* ───────────────────────────────────────────── */

static int syn_recv_init(void)
{
    if (recv_sock >= 0)
        return 0;

    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sock < 0)
    {
        np_perror("syn_recv_init: socket");
        return -1;
    }

    np_set_nonblocking(recv_sock);
    return 0;
}

static void syn_recv_close(void)
{
    if (recv_sock >= 0)
    {
        close(recv_sock);
        recv_sock = -1;
    }
}

/* ───────────────────────────────────────────── */
/* Read and classify one SYN reply               */
/* ───────────────────────────────────────────── */

static bool
syn_read_reply(const np_target_t *target,
               uint16_t port,
               int timeout_ms,
               np_port_state_t *out_state)
{
    struct pollfd pfd = {
        .fd     = recv_sock,
        .events = POLLIN
    };

    uint8_t buf[256];
    int remaining_ms = timeout_ms;

    np_timer_t deadline;
    np_timer_start(&deadline);

    while (remaining_ms > 0)
    {
        int ret = poll(&pfd, 1, remaining_ms);
        if (ret <= 0)
            break;

        ssize_t n = recv(recv_sock, buf, sizeof(buf), 0);
        if (n < (ssize_t)(sizeof(struct ip) + sizeof(struct tcphdr)))
        {
            remaining_ms = timeout_ms -
                (int)np_timer_elapsed_ms(&deadline);
            continue;
        }

        struct ip *ip = (struct ip *)buf;
        if (ip->ip_v != 4)
            continue;

        int ip_hl = ip->ip_hl * 4;
        if (n < ip_hl + (int)sizeof(struct tcphdr))
            continue;

        struct tcphdr *tcp =
            (struct tcphdr *)(buf + ip_hl);

        /* Match reply to target */
        if (ip->ip_src.s_addr != target->addr4.sin_addr.s_addr)
        {
            remaining_ms = timeout_ms -
                (int)np_timer_elapsed_ms(&deadline);
            continue;
        }

        if (ntohs(tcp->th_sport) != port)
        {
            remaining_ms = timeout_ms -
                (int)np_timer_elapsed_ms(&deadline);
            continue;
        }

        if ((tcp->th_flags & (TH_SYN | TH_ACK)) ==
            (TH_SYN | TH_ACK))
        {
            *out_state = NP_PORT_OPEN;
            return true;
        }

        if (tcp->th_flags & TH_RST)
        {
            *out_state = NP_PORT_CLOSED;
            return true;
        }

        remaining_ms = timeout_ms -
            (int)np_timer_elapsed_ms(&deadline);
    }

    *out_state = NP_PORT_FILTERED;
    return true;
}

/* ───────────────────────────────────────────── */
/* SYN scan worker                               */
/* ───────────────────────────────────────────── */
void np_syn_scan_task(void *arg)
{
    np_task_arg_t *targ = arg;
    np_scan_ctx_t *ctx  = &targ->ctx;
    const np_config_t *cfg = ctx->cfg;
    uint64_t host_started_us = np_now_monotonic_us();
    uint64_t last_probe_us = 0;

    while (!(*ctx->interrupted))
    {
        if (np_host_timeout_reached(cfg, host_started_us))
            break;

        np_work_item_t item;
        if (!np_wq_pop(ctx->queue, &item))
            break;

        const np_target_t *target =
            &cfg->targets[item.target_idx];

        for (uint32_t attempt = 0; attempt <= cfg->max_retries; attempt++)
        {
            if (attempt > 0)
                np_note_probe_retransmission(cfg);
            np_wait_probe_budget(cfg, &last_probe_us);
            np_send_syn(target, item.port, &cfg->evasion);
            np_note_probe_sent(cfg);
        }
    }

    if (np_host_timeout_reached(cfg, host_started_us))
    {
        np_worker_ctx_t timeout_ctx = {
            .cfg = ctx->cfg,
            .queue = ctx->queue,
            .interrupted = ctx->interrupted,
            .metrics = ctx->metrics,
            .metrics_lock = ctx->metrics_lock,
            .total_work = ctx->total_work,
            .completed_work = ctx->completed_work,
            .completed_lock = ctx->completed_lock,
        };
        np_mark_unstarted_remaining(&timeout_ctx);
    }

    np_completion_signal(targ->completion);
    free(targ);
}
