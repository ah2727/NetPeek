#include "thread_pool.h"
#include "core/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#define NP_DEFAULT_QUEUE_SIZE 1024
#define NP_MIN_THREADS 1
#define NP_MAX_THREADS 256

static inline bool queue_empty(const np_task_queue_t *q)
{
    return q->count == 0;
}

static inline bool queue_full(const np_task_queue_t *q)
{
    return q->count >= q->capacity;
}

/* ───────────────────────────────────────────── */
/* Worker thread                                 */
/* ───────────────────────────────────────────── */

static void *worker_thread(void *arg)
{
    np_pool_t *p = arg;

    for (;;) {
        pthread_mutex_lock(&p->mutex);

        while (queue_empty(&p->queue) && !p->shutdown)
            pthread_cond_wait(&p->not_empty, &p->mutex);

        if (p->shutdown && p->force_stop) {
            pthread_mutex_unlock(&p->mutex);
            break;
        }

        if (p->shutdown && queue_empty(&p->queue)) {
            pthread_mutex_unlock(&p->mutex);
            break;
        }

        np_task_t task = p->queue.tasks[p->queue.head];
        p->queue.head = (p->queue.head + 1) % p->queue.capacity;
        p->queue.count--;

        p->active_workers++;
        if (p->active_workers > p->peak_workers)
            p->peak_workers = p->active_workers;

        pthread_cond_signal(&p->not_full);
        pthread_mutex_unlock(&p->mutex);

        task.fn(task.arg);

        pthread_mutex_lock(&p->mutex);
        p->tasks_completed++;
        p->active_workers--;

        if (queue_empty(&p->queue) && p->active_workers == 0)
            pthread_cond_broadcast(&p->all_done);

        pthread_mutex_unlock(&p->mutex);
    }

    return NULL;
}

/* ───────────────────────────────────────────── */
/* Pool lifecycle                                */
/* ───────────────────────────────────────────── */

np_pool_t *np_pool_create(uint32_t threads, uint32_t qsize)
{
    if (threads < NP_MIN_THREADS) threads = NP_MIN_THREADS;
    if (threads > NP_MAX_THREADS) threads = NP_MAX_THREADS;
    if (qsize == 0) qsize = NP_DEFAULT_QUEUE_SIZE;

    np_pool_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    p->queue.tasks = calloc(qsize, sizeof(np_task_t));
    if (!p->queue.tasks) {
        free(p);
        return NULL;
    }

    p->queue.capacity = qsize;

    pthread_mutex_init(&p->mutex, NULL);
    pthread_cond_init(&p->not_empty, NULL);
    pthread_cond_init(&p->not_full, NULL);
    pthread_cond_init(&p->all_done, NULL);

    p->threads = calloc(threads, sizeof(pthread_t));
    p->thread_count = threads;

    for (uint32_t i = 0; i < threads; i++)
        pthread_create(&p->threads[i], NULL, worker_thread, p);

    return p;
}

void np_pool_destroy(np_pool_t *p, bool graceful)
{
    if (!p) return;

    pthread_mutex_lock(&p->mutex);
    p->shutdown = true;
    p->force_stop = !graceful;
    pthread_cond_broadcast(&p->not_empty);
    pthread_cond_broadcast(&p->not_full);
    pthread_mutex_unlock(&p->mutex);

    for (uint32_t i = 0; i < p->thread_count; i++)
        pthread_join(p->threads[i], NULL);

    pthread_mutex_destroy(&p->mutex);
    pthread_cond_destroy(&p->not_empty);
    pthread_cond_destroy(&p->not_full);
    pthread_cond_destroy(&p->all_done);

    free(p->queue.tasks);
    free(p->threads);
    free(p);
}

/* ───────────────────────────────────────────── */
/* Submission                                    */
/* ───────────────────────────────────────────── */

int np_pool_submit(np_pool_t *p, np_task_fn_t fn, void *arg)
{
    pthread_mutex_lock(&p->mutex);

    while (queue_full(&p->queue) && !p->shutdown)
        pthread_cond_wait(&p->not_full, &p->mutex);

    if (p->shutdown) {
        pthread_mutex_unlock(&p->mutex);
        return -1;
    }

    p->queue.tasks[p->queue.tail] = (np_task_t){ fn, arg };
    p->queue.tail = (p->queue.tail + 1) % p->queue.capacity;
    p->queue.count++;
    p->tasks_submitted++;

    pthread_cond_signal(&p->not_empty);
    pthread_mutex_unlock(&p->mutex);
    return 0;
}

/*
 * ✅ BOUNDED PRODUCER (THE FIX)
 */
int np_pool_submit_bounded(np_pool_t *p,
                           np_task_fn_t fn,
                           void *arg)
{
    for (;;) {
        if (np_pool_submit(p, fn, arg) == 0)
            return 0;

        if (p->shutdown)
            return -1;

        /* allow workers to drain */
        struct timespec ts = {0, 1000000}; /* 1ms */
        nanosleep(&ts, NULL);
    }
}

/* ───────────────────────────────────────────── */
/* Synchronization                               */
/* ───────────────────────────────────────────── */

void np_pool_wait(np_pool_t *p)
{
    pthread_mutex_lock(&p->mutex);
    while (!(queue_empty(&p->queue) && p->active_workers == 0))
        pthread_cond_wait(&p->all_done, &p->mutex);
    pthread_mutex_unlock(&p->mutex);
}

/* ───────────────────────────────────────────── */
/* Stats                                        */
/* ───────────────────────────────────────────── */

uint32_t np_pool_pending(const np_pool_t *p)
{
    pthread_mutex_lock((pthread_mutex_t *)&p->mutex);
    uint32_t n = p->queue.count;
    pthread_mutex_unlock((pthread_mutex_t *)&p->mutex);
    return n;
}

uint64_t np_pool_completed(const np_pool_t *p)
{
    pthread_mutex_lock((pthread_mutex_t *)&p->mutex);
    uint64_t n = p->tasks_completed;
    pthread_mutex_unlock((pthread_mutex_t *)&p->mutex);
    return n;
}

bool np_pool_idle(const np_pool_t *p)
{
    pthread_mutex_lock((pthread_mutex_t *)&p->mutex);
    bool idle = queue_empty(&p->queue) && p->active_workers == 0;
    pthread_mutex_unlock((pthread_mutex_t *)&p->mutex);
    return idle;
}

void np_pool_stats_print(const np_pool_t *p)
{
    pthread_mutex_lock((pthread_mutex_t *)&p->mutex);
    np_error(NP_ERR_RUNTIME, "[pool] submitted=%lu completed=%lu pending=%u peak=%u/%u\n",
        p->tasks_submitted,
        p->tasks_completed,
        p->queue.count,
        p->peak_workers,
        p->thread_count);
    pthread_mutex_unlock((pthread_mutex_t *)&p->mutex);
}
