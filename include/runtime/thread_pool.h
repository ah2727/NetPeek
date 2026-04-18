#ifndef NP_THREAD_POOL_H
#define NP_THREAD_POOL_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

/* ── Task function signature ─────────────────────────── */
typedef void (*np_task_fn_t)(void *arg);

/* ── Single task ─────────────────────────────────────── */
typedef struct
{
    np_task_fn_t fn;
    void *arg;
} np_task_t;

/* ── Task queue ──────────────────────────────────────── */
typedef struct
{
    np_task_t *tasks;
    uint32_t capacity;
    uint32_t count;
    uint32_t head;
    uint32_t tail;
} np_task_queue_t;

/* ── Thread pool ─────────────────────────────────────── */
typedef struct
{
    pthread_t *threads;
    uint32_t thread_count;

    np_task_queue_t queue;

    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    pthread_cond_t all_done;

    bool shutdown;
    bool force_stop;

    uint64_t tasks_submitted;
    uint64_t tasks_completed;
    uint64_t tasks_failed;

    uint32_t active_workers;
    uint32_t peak_workers;
} np_pool_t;

/* ── Lifecycle ───────────────────────────────────────── */
np_pool_t *np_pool_create(uint32_t threads, uint32_t queue_size);
void np_pool_destroy(np_pool_t *pool, bool graceful);

/* ── Submission ──────────────────────────────────────── */
int np_pool_submit(np_pool_t *pool, np_task_fn_t fn, void *arg);

/*
 * ✅ NEW: bounded producer helper
 *
 * Blocks intelligently until space exists, but never overflows
 * and never aborts early due to queue saturation.
 */
int np_pool_submit_bounded(np_pool_t *pool,
                           np_task_fn_t fn,
                           void *arg);

/* ── Synchronization ─────────────────────────────────── */
void np_pool_wait(np_pool_t *pool);

/* ── Stats ───────────────────────────────────────────── */
uint32_t np_pool_pending(const np_pool_t *pool);
uint64_t np_pool_completed(const np_pool_t *pool);
bool np_pool_idle(const np_pool_t *pool);
void np_pool_stats_print(const np_pool_t *pool);

/* ── Scan task ───────────────────────────────────────── */
typedef struct
{
    char target_ip[64];
    uint16_t port;
    const void *sigdb;
    bool verbose;

    void *result;
    int rc;
} np_scan_task_t;

void np_scan_worker(void *arg);

#endif /* NP_THREAD_POOL_H */
