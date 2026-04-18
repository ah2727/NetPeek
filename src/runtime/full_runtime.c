#include "runtime/full_runtime.h"

#include "recon/submodules/scanner/scanner_internal.h"
#include "recon/submodules/scanner/service_version.h"
#include "recon/submodules/scanner/service_detect.h"
#include "recon/submodules/scanner/tls_probe.h"
#include "runtime/stats.h"
#include "core/error.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/tcp.h>

typedef enum
{
    NP_FULL_TASK_SCAN = 0,
    NP_FULL_TASK_VERSION_DETECT,
    NP_FULL_TASK_TLS,
    NP_FULL_TASK_OS,
    NP_FULL_TASK_COMPLETE
} np_full_task_type_t;

enum
{
    NP_FULL_BIT_SCAN = (1u << 0),
    NP_FULL_BIT_VERSION = (1u << 1),
    NP_FULL_BIT_TLS = (1u << 2),
    NP_FULL_BIT_OS = (1u << 3)
};

typedef struct
{
    np_full_task_type_t type;
    uint32_t target_idx;
} np_full_task_t;

typedef struct
{
    np_full_task_t *items;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t size;
} np_full_ring_t;

typedef struct
{
    _Atomic bool done;
    _Atomic bool scan_done;
    _Atomic uint32_t completed_mask;
    uint32_t required_mask;
} np_full_host_state_t;

typedef struct
{
    np_config_t *cfg;
    volatile sig_atomic_t *interrupted;

    bool running;
    bool syn_shared;

    uint32_t worker_count;
    pthread_t *workers;

    pthread_mutex_t queue_lock;
    pthread_cond_t queue_cond;
    np_full_ring_t queues[5];
    uint32_t queue_cursor;

    np_full_host_state_t *hosts;
    _Atomic uint32_t completed_hosts;
} np_full_runtime_t;

extern void np_start_receiver(np_config_t *cfg);
extern void np_stop_receiver(void);

static np_port_state_t full_default_noresp_state(np_scan_type_t scan_type)
{
    switch (scan_type)
    {
    case NP_SCAN_TCP_SYN:
    case NP_SCAN_TCP_ACK:
    case NP_SCAN_TCP_WINDOW:
        return NP_PORT_FILTERED;
    case NP_SCAN_TCP_MAIMON:
    case NP_SCAN_TCP_NULL:
    case NP_SCAN_TCP_FIN:
    case NP_SCAN_TCP_XMAS:
    case NP_SCAN_TCP_CUSTOM_FLAGS:
    case NP_SCAN_UDP:
        return NP_PORT_OPEN_FILTERED;
    default:
        return NP_PORT_FILTERED;
    }
}

static uint8_t full_scan_type_tcp_flags(const np_config_t *cfg)
{
    switch (cfg->scan_type)
    {
    case NP_SCAN_TCP_SYN: return TH_SYN;
    case NP_SCAN_TCP_ACK: return TH_ACK;
    case NP_SCAN_TCP_WINDOW: return TH_ACK;
    case NP_SCAN_TCP_MAIMON: return (TH_FIN | TH_ACK);
    case NP_SCAN_TCP_NULL: return 0;
    case NP_SCAN_TCP_FIN: return TH_FIN;
    case NP_SCAN_TCP_XMAS: return (TH_FIN | TH_PUSH | TH_URG);
    case NP_SCAN_TCP_CUSTOM_FLAGS: return cfg->tcp_custom_flags;
    default: return TH_SYN;
    }
}

bool np_full_mode_supported(np_scan_type_t scan_type)
{
    switch (scan_type)
    {
    case NP_SCAN_TCP_CONNECT:
    case NP_SCAN_TCP_SYN:
    case NP_SCAN_UDP:
    case NP_SCAN_TCP_ACK:
    case NP_SCAN_TCP_WINDOW:
    case NP_SCAN_TCP_MAIMON:
    case NP_SCAN_TCP_NULL:
    case NP_SCAN_TCP_FIN:
    case NP_SCAN_TCP_XMAS:
    case NP_SCAN_TCP_CUSTOM_FLAGS:
    case NP_SCAN_SCTP_INIT:
    case NP_SCAN_SCTP_COOKIE_ECHO:
    case NP_SCAN_IP_PROTOCOL:
        return true;
    default:
        return false;
    }
}

static bool ring_init(np_full_ring_t *ring, uint32_t capacity)
{
    ring->items = calloc(capacity, sizeof(*ring->items));
    if (!ring->items)
        return false;

    ring->capacity = capacity;
    ring->head = 0;
    ring->tail = 0;
    ring->size = 0;
    return true;
}

static void ring_destroy(np_full_ring_t *ring)
{
    free(ring->items);
    memset(ring, 0, sizeof(*ring));
}

static bool ring_push(np_full_ring_t *ring, const np_full_task_t *task)
{
    if (ring->size >= ring->capacity)
        return false;

    ring->items[ring->tail] = *task;
    ring->tail = (ring->tail + 1u) % ring->capacity;
    ring->size++;
    return true;
}

static bool ring_pop(np_full_ring_t *ring, np_full_task_t *task)
{
    if (ring->size == 0)
        return false;

    *task = ring->items[ring->head];
    ring->head = (ring->head + 1u) % ring->capacity;
    ring->size--;
    return true;
}

static uint32_t queue_total(np_full_runtime_t *rt)
{
    uint32_t total = 0;
    for (size_t i = 0; i < sizeof(rt->queues) / sizeof(rt->queues[0]); i++)
        total += rt->queues[i].size;
    return total;
}

static bool enqueue_task(np_full_runtime_t *rt, np_full_task_type_t type, uint32_t target_idx)
{
    np_full_task_t task = {.type = type, .target_idx = target_idx};

    pthread_mutex_lock(&rt->queue_lock);
    bool ok = ring_push(&rt->queues[(int)type], &task);
    if (ok)
        pthread_cond_signal(&rt->queue_cond);
    pthread_mutex_unlock(&rt->queue_lock);

    return ok;
}

static bool dequeue_task(np_full_runtime_t *rt, np_full_task_t *task)
{
    pthread_mutex_lock(&rt->queue_lock);

    while (rt->running && queue_total(rt) == 0)
        pthread_cond_wait(&rt->queue_cond, &rt->queue_lock);

    if (!rt->running && queue_total(rt) == 0)
    {
        pthread_mutex_unlock(&rt->queue_lock);
        return false;
    }

    bool ok = false;
    size_t qcount = sizeof(rt->queues) / sizeof(rt->queues[0]);
    for (size_t i = 0; i < qcount; i++)
    {
        size_t idx = (rt->queue_cursor + i) % qcount;
        if (ring_pop(&rt->queues[idx], task))
        {
            ok = true;
            rt->queue_cursor = (uint32_t)((idx + 1u) % qcount);
            break;
        }
    }

    pthread_mutex_unlock(&rt->queue_lock);
    return ok;
}

static uint32_t task_bit(np_full_task_type_t type)
{
    switch (type)
    {
    case NP_FULL_TASK_SCAN: return NP_FULL_BIT_SCAN;
    case NP_FULL_TASK_VERSION_DETECT: return NP_FULL_BIT_VERSION;
    case NP_FULL_TASK_TLS: return NP_FULL_BIT_TLS;
    case NP_FULL_TASK_OS: return NP_FULL_BIT_OS;
    default: return 0;
    }
}

static void task_finish(np_full_runtime_t *rt,
                        uint32_t target_idx,
                        np_full_task_type_t type)
{
    if (target_idx >= rt->cfg->target_count)
        return;

    np_full_host_state_t *host = &rt->hosts[target_idx];
    uint32_t bit = task_bit(type);

    if (type == NP_FULL_TASK_SCAN)
        atomic_store(&host->scan_done, true);

    uint32_t new_mask = atomic_load(&host->completed_mask);
    if (bit)
    {
        uint32_t old_mask = atomic_fetch_or(&host->completed_mask, bit);
        new_mask = old_mask | bit;

        if (!(old_mask & bit) &&
            (type == NP_FULL_TASK_VERSION_DETECT ||
             type == NP_FULL_TASK_TLS ||
             type == NP_FULL_TASK_OS))
        {
            np_stats_inc_work_completed(1);
        }
    }

    uint32_t required = host->required_mask;
    if (required == 0 || ((new_mask & required) == required))
        (void)enqueue_task(rt, NP_FULL_TASK_COMPLETE, target_idx);
}

static bool wait_for_scan_done(np_full_runtime_t *rt, uint32_t target_idx)
{
    if (target_idx >= rt->cfg->target_count)
        return false;

    while (!atomic_load(&rt->hosts[target_idx].scan_done))
    {
        if (rt->interrupted && *rt->interrupted)
            return false;
        usleep(1000);
    }

    return true;
}

static void mark_host_complete(np_full_runtime_t *rt, uint32_t target_idx)
{
    if (target_idx >= rt->cfg->target_count)
        return;

    bool already_done = atomic_exchange(&rt->hosts[target_idx].done, true);
    if (already_done)
        return;

    np_stats_inc_hosts_completed();
    (void)atomic_fetch_add(&rt->completed_hosts, 1u);
}

static bool target_should_skip(np_config_t *cfg, uint32_t target_idx)
{
    if (target_idx >= cfg->target_count)
        return true;

    if (cfg->host_discovery_done &&
        cfg->host_discovery_mode == NP_HOST_DISCOVERY_DEFAULT &&
        !cfg->targets[target_idx].host_up)
        return true;

    return false;
}

static void execute_scan(np_full_runtime_t *rt, uint32_t target_idx)
{
    if (target_should_skip(rt->cfg, target_idx))
    {
        task_finish(rt, target_idx, NP_FULL_TASK_SCAN);
        return;
    }

    np_config_t per_host;
    memcpy(&per_host, rt->cfg, sizeof(per_host));

    per_host.targets = &rt->cfg->targets[target_idx];
    per_host.target_count = 1;

    if (rt->worker_count > 0)
    {
        uint32_t per_host_threads = rt->cfg->threads ? rt->cfg->threads / rt->worker_count : 1;
        if (per_host_threads == 0)
            per_host_threads = 1;
        per_host.threads = per_host_threads;
    }

    (void)np_scanner_run_single_target_internal(&per_host, rt->interrupted, rt->syn_shared);
    task_finish(rt, target_idx, NP_FULL_TASK_SCAN);
}

static void execute_task(np_full_runtime_t *rt, const np_full_task_t *task)
{
    switch (task->type)
    {
    case NP_FULL_TASK_SCAN:
        execute_scan(rt, task->target_idx);
        break;
    case NP_FULL_TASK_VERSION_DETECT:
        if (!target_should_skip(rt->cfg, task->target_idx) &&
            wait_for_scan_done(rt, task->target_idx))
        {
            (void)np_service_version_run_target(rt->cfg, task->target_idx);
            (void)np_service_detect_run_target(rt->cfg, task->target_idx);
        }
        task_finish(rt, task->target_idx, NP_FULL_TASK_VERSION_DETECT);
        break;
    case NP_FULL_TASK_TLS:
        if (!target_should_skip(rt->cfg, task->target_idx) &&
            wait_for_scan_done(rt, task->target_idx))
            (void)np_tls_probe_run_target(rt->cfg, task->target_idx);
        task_finish(rt, task->target_idx, NP_FULL_TASK_TLS);
        break;
    case NP_FULL_TASK_OS:
        if (!target_should_skip(rt->cfg, task->target_idx))
            (void)np_scan_os_detect_run_target(rt->cfg, task->target_idx);
        task_finish(rt, task->target_idx, NP_FULL_TASK_OS);
        break;
    case NP_FULL_TASK_COMPLETE:
        mark_host_complete(rt, task->target_idx);
        break;
    default:
        break;
    }
}

static void *full_worker(void *arg)
{
    np_full_runtime_t *rt = arg;
    np_full_task_t task;

    while (dequeue_task(rt, &task))
    {
        if (rt->interrupted && *rt->interrupted)
            break;
        execute_task(rt, &task);
    }

    return NULL;
}

static void finalize_raw_syn(np_config_t *cfg)
{
    np_port_state_t noresp = full_default_noresp_state(cfg->scan_type);
    for (uint32_t t = 0; t < cfg->target_count; t++)
    {
        np_target_t *tgt = &cfg->targets[t];
        if (!tgt->results)
            continue;

        for (uint32_t p = 0; p < tgt->port_count; p++)
        {
            if (!tgt->results[p].completed)
            {
                tgt->results[p].state = noresp;
                strncpy(tgt->results[p].reason,
                        "no-response",
                        sizeof(tgt->results[p].reason) - 1);
            }
        }
    }
}

np_status_t np_full_runtime_run(np_config_t *cfg,
                                volatile sig_atomic_t *interrupted)
{
    if (!cfg)
        return NP_ERR_ARGS;

    if (!np_full_mode_supported(cfg->scan_type))
        return NP_ERR_ARGS;

    np_full_runtime_t rt;
    memset(&rt, 0, sizeof(rt));
    rt.cfg = cfg;
    rt.interrupted = interrupted;
    rt.running = true;

    uint32_t queue_capacity = cfg->full_queue_capacity;
    if (queue_capacity < 1024)
        queue_capacity = 1024;

    pthread_mutex_init(&rt.queue_lock, NULL);
    pthread_cond_init(&rt.queue_cond, NULL);

    for (size_t i = 0; i < sizeof(rt.queues) / sizeof(rt.queues[0]); i++)
    {
        if (!ring_init(&rt.queues[i], queue_capacity))
        {
            np_error(NP_ERR_RUNTIME, "[!] Full mode queue allocation failed\n");
            for (size_t j = 0; j < i; j++)
                ring_destroy(&rt.queues[j]);
            pthread_cond_destroy(&rt.queue_cond);
            pthread_mutex_destroy(&rt.queue_lock);
            return NP_ERR_MEMORY;
        }
    }

    rt.hosts = calloc(cfg->target_count, sizeof(*rt.hosts));
    if (!rt.hosts)
    {
        for (size_t i = 0; i < sizeof(rt.queues) / sizeof(rt.queues[0]); i++)
            ring_destroy(&rt.queues[i]);
        pthread_cond_destroy(&rt.queue_cond);
        pthread_mutex_destroy(&rt.queue_lock);
        return NP_ERR_MEMORY;
    }

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1)
        ncpu = 4;

    rt.worker_count = (uint32_t)ncpu;
    if (cfg->workers > 0)
        rt.worker_count = (uint32_t)cfg->workers;
    if (rt.worker_count < 1)
        rt.worker_count = 1;

    rt.workers = calloc(rt.worker_count, sizeof(*rt.workers));
    if (!rt.workers)
    {
        free(rt.hosts);
        for (size_t i = 0; i < sizeof(rt.queues) / sizeof(rt.queues[0]); i++)
            ring_destroy(&rt.queues[i]);
        pthread_cond_destroy(&rt.queue_cond);
        pthread_mutex_destroy(&rt.queue_lock);
        return NP_ERR_MEMORY;
    }

    if (cfg->scan_type == NP_SCAN_TCP_SYN)
    {
        np_syn_set_tcp_flags(full_scan_type_tcp_flags(cfg));
        if (np_syn_init() != NP_OK || np_icmp_init() != NP_OK)
        {
            free(rt.workers);
            free(rt.hosts);
            for (size_t i = 0; i < sizeof(rt.queues) / sizeof(rt.queues[0]); i++)
                ring_destroy(&rt.queues[i]);
            pthread_cond_destroy(&rt.queue_cond);
            pthread_mutex_destroy(&rt.queue_lock);
            return NP_ERR_SYSTEM;
        }
        np_start_receiver(cfg);
        usleep(20000);
        rt.syn_shared = true;
    }

    np_error(NP_ERR_RUNTIME,
             "[*] Full mode: %u worker(s), parallel tasks scan%s%s%s\n",
             rt.worker_count,
             cfg->service_version_detect ? "+version" : "",
             cfg->tls_info ? "+tls" : "",
             cfg->os_detect ? "+os" : "");

    uint64_t optional_work_total = 0;
    for (uint32_t i = 0; i < cfg->target_count; i++)
    {
        np_full_host_state_t *host = &rt.hosts[i];

        if (target_should_skip(cfg, i))
        {
            host->required_mask = 0;
            (void)enqueue_task(&rt, NP_FULL_TASK_COMPLETE, i);
            continue;
        }

        uint32_t required = NP_FULL_BIT_SCAN;
        if (cfg->service_version_detect)
        {
            required |= NP_FULL_BIT_VERSION;
            optional_work_total++;
        }
        if (cfg->tls_info)
        {
            required |= NP_FULL_BIT_TLS;
            optional_work_total++;
        }
        if (cfg->os_detect)
        {
            required |= NP_FULL_BIT_OS;
            optional_work_total++;
        }
        host->required_mask = required;

        (void)enqueue_task(&rt, NP_FULL_TASK_SCAN, i);
        if (cfg->service_version_detect)
            (void)enqueue_task(&rt, NP_FULL_TASK_VERSION_DETECT, i);
        if (cfg->tls_info)
            (void)enqueue_task(&rt, NP_FULL_TASK_TLS, i);
        if (cfg->os_detect)
            (void)enqueue_task(&rt, NP_FULL_TASK_OS, i);
    }

    np_stats_set_work_total((uint64_t)cfg->target_count + optional_work_total);

    for (uint32_t i = 0; i < rt.worker_count; i++)
    {
        int err = pthread_create(&rt.workers[i], NULL, full_worker, &rt);
        if (err != 0)
        {
            rt.worker_count = i;
            break;
        }
    }

    while ((!interrupted || !*interrupted) &&
           atomic_load(&rt.completed_hosts) < cfg->target_count)
    {
        usleep(5000);
    }

    rt.running = false;
    pthread_mutex_lock(&rt.queue_lock);
    pthread_cond_broadcast(&rt.queue_cond);
    pthread_mutex_unlock(&rt.queue_lock);

    for (uint32_t i = 0; i < rt.worker_count; i++)
        pthread_join(rt.workers[i], NULL);

    if (rt.syn_shared)
    {
        np_error(NP_ERR_RUNTIME, "[*] Waiting for final SYN replies...\n");
        sleep(2);
        np_stop_receiver();
        np_syn_close();
        np_icmp_close();
        finalize_raw_syn(cfg);
    }

    free(rt.workers);
    free(rt.hosts);
    for (size_t i = 0; i < sizeof(rt.queues) / sizeof(rt.queues[0]); i++)
        ring_destroy(&rt.queues[i]);

    pthread_cond_destroy(&rt.queue_cond);
    pthread_mutex_destroy(&rt.queue_lock);

    return NP_OK;
}
