#define _POSIX_C_SOURCE 200809L

#include "route/route.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "recon/submodules/scanner/scanner_internal.h"
#include "runtime/thread_pool.h"
#include "logger.h"

typedef struct
{
    np_route_result_t *result;
    uint32_t hop_idx;
    uint16_t port;
    uint32_t timeout_ms;
    pthread_mutex_t *hop_locks;
} hop_scan_task_t;

static bool connect_open_for_hop(const np_route_hop_t *hop,
                                 uint16_t port,
                                 uint32_t timeout_ms)
{
    np_target_t target;
    memset(&target, 0, sizeof(target));

    target.is_ipv6 = hop->is_ipv6;
    if (hop->is_ipv6)
    {
        target.addr6.sin6_family = AF_INET6;
        target.addr6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, hop->ip, &target.addr6.sin6_addr) != 1)
            return false;
    }
    else
    {
        target.addr4.sin_family = AF_INET;
        target.addr4.sin_port = htons(port);
        if (inet_pton(AF_INET, hop->ip, &target.addr4.sin_addr) != 1)
            return false;
    }

    int fd = -1;
    np_connect_rc_t rc = np_start_connect(&target, port, (int)timeout_ms, &fd);
    if (rc == NP_CONNECT_FAILED)
        return false;

    if (rc == NP_CONNECT_IMMEDIATE)
    {
        if (fd >= 0)
            close(fd);
        return true;
    }

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT;

    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr <= 0)
    {
        close(fd);
        return false;
    }

    int so_error = np_get_socket_error(fd);
    close(fd);
    return so_error == 0;
}

static void add_open_port(np_route_hop_t *hop, uint16_t port)
{
    uint16_t *next = realloc(hop->open_ports,
                             (hop->open_port_count + 1u) * sizeof(*hop->open_ports));
    if (!next)
        return;

    hop->open_ports = next;
    hop->open_ports[hop->open_port_count++] = port;
}

static void hop_scan_worker(void *arg)
{
    hop_scan_task_t *task = (hop_scan_task_t *)arg;
    if (!task)
        return;

    np_route_hop_t *hop = &task->result->hops[task->hop_idx];
    if (connect_open_for_hop(hop, task->port, task->timeout_ms))
    {
        pthread_mutex_lock(&task->hop_locks[task->hop_idx]);
        add_open_port(hop, task->port);
        pthread_mutex_unlock(&task->hop_locks[task->hop_idx]);
    }

    free(task);
}

static int cmp_u16(const void *a, const void *b)
{
    uint16_t va = *(const uint16_t *)a;
    uint16_t vb = *(const uint16_t *)b;
    return (va > vb) - (va < vb);
}

np_status_t np_route_scan_hops(np_route_result_t *result,
                               const np_route_options_t *opts)
{
    if (!result || !opts)
        return NP_ERR_ARGS;

    if (result->hop_count == 0)
        return NP_OK;

    uint32_t qsize = result->hop_count * 16u;
    if (qsize < 128u)
        qsize = 128u;

    uint32_t threads = opts->threads ? opts->threads : NP_DEFAULT_THREADS;
    np_pool_t *pool = np_pool_create(threads, qsize);
    if (!pool)
        return NP_ERR_MEMORY;

    pthread_mutex_t *hop_locks = calloc(result->hop_count, sizeof(*hop_locks));
    if (!hop_locks)
    {
        np_pool_destroy(pool, true);
        return NP_ERR_MEMORY;
    }

    for (uint32_t i = 0; i < result->hop_count; i++)
        pthread_mutex_init(&hop_locks[i], NULL);

    np_port_iter_t it;
    np_port_iter_init(&it);

    LOGI("[route] hop scan start hops=%u threads=%u timeout=%ums\n",
         result->hop_count,
         threads,
         opts->timeout_ms);

    uint32_t task_count = 0;

    uint16_t port = 0;
    while (np_port_iter_next(&opts->ports, &it, &port))
    {
        for (uint32_t i = 0; i < result->hop_count; i++)
        {
            np_route_hop_t *hop = &result->hops[i];
            if (hop->timeout || hop->ip[0] == '\0')
                continue;

            hop_scan_task_t *task = calloc(1, sizeof(*task));
            if (!task)
                continue;

            task->result = result;
            task->hop_idx = i;
            task->port = port;
            task->timeout_ms = opts->timeout_ms;
            task->hop_locks = hop_locks;

            if (np_pool_submit_bounded(pool, hop_scan_worker, task) != 0)
            {
                free(task);
                continue;
            }

            task_count++;
        }
    }

    LOGD("[route] hop scan queued tasks=%u\n", task_count);

    np_pool_wait(pool);
    np_pool_destroy(pool, true);

    for (uint32_t i = 0; i < result->hop_count; i++)
    {
        pthread_mutex_destroy(&hop_locks[i]);

        np_route_hop_t *hop = &result->hops[i];
        if (hop->open_port_count > 1)
            qsort(hop->open_ports, hop->open_port_count, sizeof(*hop->open_ports), cmp_u16);
    }

    uint32_t open_total = 0;
    for (uint32_t i = 0; i < result->hop_count; i++)
        open_total += result->hops[i].open_port_count;

    LOGI("[route] hop scan complete open_ports=%u\n", open_total);

    free(hop_locks);
    return NP_OK;
}
