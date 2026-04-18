#define _POSIX_C_SOURCE 200809L

#include "subenum/dns_resolver.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

typedef struct np_dns_task
{
    char fqdn[512];
    np_dns_record_type_t qtype;
    np_subenum_source_t src;
    uint16_t depth;
} np_dns_task_t;

struct np_dns_engine
{
    np_subenum_config_t cfg;
    np_result_store_t *store;
    np_dns_task_t *tasks;
    size_t task_count;
    size_t task_cap;
};

static double now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

static int ensure_tasks(np_dns_engine_t *engine, size_t needed)
{
    size_t cap;
    np_dns_task_t *tmp;

    if (engine->task_cap >= needed)
        return 1;

    cap = engine->task_cap ? engine->task_cap * 2 : 512;
    while (cap < needed)
        cap *= 2;

    tmp = realloc(engine->tasks, cap * sizeof(*tmp));
    if (!tmp)
        return 0;
    engine->tasks = tmp;
    engine->task_cap = cap;
    return 1;
}

np_dns_engine_t *np_dns_engine_create(const np_subenum_config_t *cfg,
                                      np_result_store_t *store)
{
    np_dns_engine_t *engine = calloc(1, sizeof(*engine));
    if (!engine)
        return NULL;

    if (cfg)
        engine->cfg = *cfg;
    engine->store = store;
    return engine;
}

int np_dns_engine_submit(np_dns_engine_t *engine,
                         const char *fqdn,
                         np_dns_record_type_t qtype,
                         np_subenum_source_t src,
                         uint16_t depth)
{
    np_dns_task_t *task;

    if (!engine || !fqdn || !*fqdn)
        return -1;

    if (!ensure_tasks(engine, engine->task_count + 1))
        return -1;

    task = &engine->tasks[engine->task_count++];
    memset(task, 0, sizeof(*task));
    strncpy(task->fqdn, fqdn, sizeof(task->fqdn) - 1);
    task->qtype = qtype;
    task->src = src;
    task->depth = depth;
    return 0;
}

int np_dns_engine_resolve_name(np_dns_engine_t *engine,
                               const char *fqdn,
                               np_resolved_addr_t *out,
                               size_t out_cap,
                               size_t *out_count,
                               double *out_rtt_ms)
{
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *cur;
    size_t count = 0;
    double start;
    double end;

    (void)engine;
    if (!fqdn)
        return -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    start = now_ms();
    if (getaddrinfo(fqdn, NULL, &hints, &res) != 0)
        return -1;
    end = now_ms();

    for (cur = res; cur; cur = cur->ai_next)
    {
        if (!out || count >= out_cap)
            break;

        if (cur->ai_family == AF_INET)
        {
            struct sockaddr_in *sa = (struct sockaddr_in *)cur->ai_addr;
            out[count].family = AF_INET;
            out[count].addr.v4 = sa->sin_addr;
            inet_ntop(AF_INET, &sa->sin_addr, out[count].addr_str, sizeof(out[count].addr_str));
            count++;
        }
        else if (cur->ai_family == AF_INET6)
        {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)cur->ai_addr;
            out[count].family = AF_INET6;
            out[count].addr.v6 = sa6->sin6_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, out[count].addr_str, sizeof(out[count].addr_str));
            count++;
        }
    }

    freeaddrinfo(res);
    if (out_count)
        *out_count = count;
    if (out_rtt_ms)
        *out_rtt_ms = end - start;

    return count > 0 ? 0 : -1;
}

int np_dns_engine_run(np_dns_engine_t *engine)
{
    size_t i;
    if (!engine || !engine->store)
        return -1;

    for (i = 0; i < engine->task_count; i++)
    {
        np_resolved_addr_t addrs[16];
        size_t count = 0;
        double rtt = 0.0;
        np_dns_task_t *task = &engine->tasks[i];

        if (task->qtype != NP_DNS_REC_A && task->qtype != NP_DNS_REC_AAAA)
            continue;

        if (np_dns_engine_resolve_name(engine, task->fqdn, addrs, 16, &count, &rtt) == 0)
        {
            np_result_store_insert(engine->store,
                                   task->fqdn,
                                   addrs,
                                   count,
                                   task->src,
                                   task->depth,
                                   rtt,
                                   NULL);
        }
    }

    engine->task_count = 0;
    return 0;
}

np_result_store_t *np_dns_engine_store(np_dns_engine_t *engine)
{
    return engine ? engine->store : NULL;
}

void np_dns_engine_destroy(np_dns_engine_t *engine)
{
    if (!engine)
        return;
    free(engine->tasks);
    free(engine);
}
