/* ============================================================
   os_detect_pipeline.c — Fully Logged OS Detection Pipeline
   ============================================================ */

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#include "logger.h"
#include "os_pipeline_priv.h"
#include "recon/submodules/os_detect/os_detect_pipeline.h"
#include "os_pipeline_parallel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <poll.h>

#define LOG_STAGE "pipeline"

/* ============================================================
   Global Mutexes
   ============================================================ */
pthread_mutex_t pipe_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ctx_port_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================
   Port Scan Worker (Logged)
   ============================================================ */
void *thread_port_discovery_worker(void *arg)
{
    if (!arg)
        return NULL;

    port_scan_task_t *task = (port_scan_task_t *)arg;
    np_pipeline_ctx_t *ctx = task->ctx;

    if (!ctx || !task->ports_to_scan || task->num_ports <= 0)
        return NULL;

    for (int i = 0; i < task->num_ports; i++)
    {
        uint16_t port = task->ports_to_scan[i];

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
            continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ctx->target_ip, &addr.sin_addr) <= 0)
        {
            close(sock);
            continue;
        }

        fcntl(sock, F_SETFL, O_NONBLOCK);
        int rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        if (rc < 0 && errno != EINPROGRESS)
        {
            close(sock);
            continue;
        }

        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = sock;
        pfd.events = POLLOUT;

        if (poll(&pfd, 1, 200) > 0 && (pfd.revents & POLLOUT))
        {
            int err = 0;
            socklen_t len = sizeof(err);

            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0)
            {
                pthread_mutex_lock(&ctx_port_mutex);

                if (ctx->open_port_count < NP_PIPELINE_MAX_OPEN_PORTS)
                {
                    ctx->open_ports[ctx->open_port_count++] = port;

                    if (ctx->primary_open_port == 0)
                        ctx->primary_open_port = port;

                    pipe_log(NP_PIPE_LOG_DEBUG,
                             LOG_STAGE,
                             "Open port discovered: %u",
                             port);
                }

                pthread_mutex_unlock(&ctx_port_mutex);
            }
        }

        close(sock);
    }

    return NULL;
}

/* ============================================================
   Helper: Promote best per-banner result into aggregate ctx
   fields (banner_valid, banner_os_name, banner_confidence).
   Called after stage_banner_grab() fills individual banners.
   ============================================================ */
static void pipeline_promote_banner_result(np_pipeline_ctx_t *ctx)
{
    if (!ctx)
        return;

    double best_conf = 0.0;
    int best_idx = -1;

    for (int i = 0; i < ctx->banner_count; i++)
    {
        double conf = (double)ctx->banners[i].os_hint_confidence;

        /* Accept any banner with a non-zero confidence */
        if (conf > best_conf)
        {
            best_conf = conf;
            best_idx = i;
        }
    }

    if (best_idx >= 0 && best_conf > 0.0)
    {
        ctx->banner_valid = true;
        ctx->banner_confidence = best_conf;

        /* Copy the best os_hint into the aggregate field */
        if (ctx->banners[best_idx].os_hint[0])
        {
            strncpy(ctx->banner_os_name,
                    ctx->banners[best_idx].os_hint,
                    sizeof(ctx->banner_os_name) - 1);
            ctx->banner_os_name[sizeof(ctx->banner_os_name) - 1] = '\0';
        }
        else
        {
            /* Nmap matched a service/product but no OS could be inferred.
               Still valid — use the service name as a label so fusion
               knows banner evidence exists. */
            snprintf(ctx->banner_os_name, sizeof(ctx->banner_os_name),
                     "svc:%s (port %u)",
                     ctx->banners[best_idx].service[0]
                         ? ctx->banners[best_idx].service
                         : "unknown",
                     ctx->banners[best_idx].port);
        }

        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "Banner promotion: best_idx=%d port=%u os='%s' conf=%.2f",
                 best_idx,
                 ctx->banners[best_idx].port,
                 ctx->banner_os_name,
                 ctx->banner_confidence);
    }
    else
    {
        ctx->banner_valid = false;
        ctx->banner_confidence = 0.0;
        ctx->banner_os_name[0] = '\0';

        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "Banner promotion: no banners with confidence > 0");
    }
}

/* ============================================================
   Pipeline Entry (FULL LOGGING)
   ============================================================ */
np_status_t np_os_detect_pipeline_run(
    const char *target_ip,
    uint16_t port,
    const np_os_sigdb_t *sigdb,
    np_os_result_t *result)
{
    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "OS detection started for %s (user_port=%u)",
             target_ip, port);

    np_pipeline_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.target_ip, target_ip,
            sizeof(ctx.target_ip) - 1);

    ctx.user_port = port;
    ctx.db        = sigdb;

    /* ============= Localhost Shortcut ============= */
    detect_localhost_os(&ctx);
    if (ctx.is_localhost)
    {
        pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
                 "Localhost detected, skipping deep scan");
        if (result) *result = ctx.os_result;
        return 0;
    }

    /* ============= Stage 1: Port Discovery ============= */
    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "Stage 1: Port discovery starting");

    if (stage_port_discovery(&ctx) != 0)
    {
        pipe_log(NP_PIPE_LOG_WARN, LOG_STAGE,
                 "Port discovery failed or no open ports");
    }

    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "Port discovery complete: open_count=%u "
             "primary=%u",
             ctx.open_port_count,
             ctx.primary_open_port);

    /* ============= Stage 2: TCP Probes ============= */
    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "Stage 2: TCP probe execution starting");

    if (stage_tcp_probes(&ctx) != 0 || !ctx.probes_valid)
    {
        pipe_log(NP_PIPE_LOG_ERR, LOG_STAGE,
                 "TCP probes failed or no responses");
        goto done;
    }

    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "TCP probes complete: responses=%u",
             ctx.probe_response_count);

    /* ============= Stage 3: Fingerprint Build ============= */
    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "Stage 3: Building fingerprint");

    if (stage_fingerprint_build(&ctx) != 0
        || !ctx.fingerprint_valid)
    {
        pipe_log(NP_PIPE_LOG_WARN, LOG_STAGE,
                 "Fingerprint build failed");
        goto done;
    }

    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "Fingerprint successfully built");

    /* ============= Stage 4+5: PARALLEL ============= */
    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "Stage 4+5: Parallel FP match + banner grab");

    if (np_pipeline_run_parallel_stages(&ctx) != 0)
    {
        pipe_log(NP_PIPE_LOG_ERR, LOG_STAGE,
                 "Parallel stages failed");
        goto done;
    }

    if (ctx.fp_valid)
    {
        pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
                 "Fingerprint match: %s (score=%u)",
                 ctx.candidates[0].os_name,
                 ctx.fp_score);
    }

    if (ctx.banner_valid)
    {
        pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
                 "Banner match: %s (confidence=%.2f)",
                 ctx.banner_os_name,
                 ctx.banner_confidence);
    }

    /* ============= Stage 6: Confidence Fusion ============= */
    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "Stage 6: Confidence fusion");

    stage_confidence_fusion(&ctx);

    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "Final result: OS=%s confidence=%.2f%%",
             ctx.os_result.best_os[0]
                 ? ctx.os_result.best_os : "Unknown",
             ctx.os_result.best_confidence);

done:
    if (result)
        *result = ctx.os_result;

    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "OS detection pipeline finished");

    return 0;
}

/* ============================================================
   Public API Wrappers (Logged)
   ============================================================ */
np_status_t np_os_detect_pipeline_auto(
    const char *target_ip,
    uint16_t port,
    const char *sigdb_path,
    np_os_result_t *result)
{
    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "Auto pipeline invoked (sigdb=%s)",
             sigdb_path ? sigdb_path : "builtin");

    np_os_sigdb_t loaded_db;
    const np_os_sigdb_t *db = NULL;

    memset(&loaded_db, 0, sizeof(loaded_db));

    /* 2. Fallback to builtin DB */
    if (!db)
    {
        if (np_sigdb_merge_builtin(&loaded_db) != 0)
        {
            pipe_log(NP_PIPE_LOG_ERR, LOG_STAGE,
                     "Failed to initialize builtin signature DB");
            return NP_STATUS_ERR;
        }
        db = &loaded_db;
    }

    /* 3. Run pipeline */
    np_status_t st =
        np_os_detect_pipeline_run(target_ip, port, db, result);

    /* 4. Cleanup */
    np_sigdb_free(&loaded_db);

    return st;
}

np_status_t np_os_detect_quick(
    const char *target_ip,
    uint16_t port,
    char *os_name_out,
    size_t os_name_sz,
    double *confidence_out)
{
    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "Quick OS detection invoked");

    np_os_result_t res;
    np_status_t st =
        np_os_detect_pipeline_auto(target_ip, port, NULL, &res);

    if (st == 0)
    {
        if (os_name_out && os_name_sz)
        {
            strncpy(os_name_out,
                    res.best_family,
                    os_name_sz - 1);
            os_name_out[os_name_sz - 1] = '\0';
        }

        if (confidence_out)
            *confidence_out = res.best_confidence;
    }

    return st;
}

void np_os_detect_result_free(np_os_result_t *r)
{
    (void)r;
}

void np_os_detect_result_print(FILE *out,
                               const np_os_result_t *r)
{
    if (!out || !r)
        return;

    fprintf(out, "\n--- NetPeek OS Detection Result ---\n");
    fprintf(out, "OS:         %s\n",
            r->best_os[0] ? r->best_os : "Unknown");
    fprintf(out, "Family:     %s\n",
            r->best_family[0] ? r->best_family : "Unknown");
    fprintf(out, "Confidence: %.2f%%\n",
            r->best_confidence);
    fprintf(out, "-----------------------------------\n");
}
