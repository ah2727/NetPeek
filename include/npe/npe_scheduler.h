/*****************************************************************************
 * npe_scheduler.h — Execution scheduling and work queue
 *
 * The scheduler manages:
 *   - A thread pool of configurable size.
 *   - A thread-safe work queue.
 *   - Phase-ordered execution (prerule → hostrule → portrule → postrule).
 *   - Dependency resolution via topological sort.
 *   - Per-script timeout enforcement.
 *****************************************************************************/

#ifndef NPE_SCHEDULER_H
#define NPE_SCHEDULER_H

#include "npe_types.h"
#include "npe_script.h"
#include "npe_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Forward declarations ────────────────────────────────────────────────── */
typedef struct npe_registry  npe_registry_t;
typedef struct npe_vm_pool   npe_vm_pool_t;

/*============================================================================
 * Work Item — one unit of work in the queue
 *============================================================================*/

typedef enum npe_work_state {
    NPE_WORK_PENDING = 0,
    NPE_WORK_RUNNING,
    NPE_WORK_DONE,
    NPE_WORK_FAILED,
    NPE_WORK_TIMEOUT,
    NPE_WORK_CANCELLED,
} npe_work_state_t;

typedef struct npe_work_item {
    /* What to run */
    const npe_script_t     *script;
    npe_phase_t             phase;

    /* Against what */
    npe_host_t              host;          /* deep copy */
    npe_port_t              port;          /* deep copy */
    bool                    has_port;

    /* Script arguments */
    npe_args_t              args;

    /* State */
    npe_work_state_t        state;
    npe_result_t            result;

    /* Timing */
    uint32_t                timeout_ms;
    struct timespec         queued_at;
    struct timespec         started_at;
    struct timespec         finished_at;

    /* Internal linked list */
    struct npe_work_item   *next;
} npe_work_item_t;

/*============================================================================
 * Scheduler Configuration
 *============================================================================*/

typedef struct npe_scheduler_config {
    /* Thread pool */
    uint32_t            thread_count;      /* 0 → 8                        */
    uint32_t            queue_capacity;    /* 0 → 4096                     */

    /* Timing */
    uint32_t            default_timeout_ms;/* Per-script default           */

    /* Resource references (borrowed — must outlive the scheduler) */
    npe_engine_t       *engine;
    npe_registry_t     *registry;
    npe_vm_pool_t      *vm_pool;

    /* Callbacks */
    npe_result_fn       result_callback;
    void               *result_userdata;
    npe_progress_fn     progress_callback;
    void               *progress_userdata;

    /* Logging */
    npe_log_fn          log_fn;
    void               *log_userdata;
    npe_log_level_t     log_level;
} npe_scheduler_config_t;

/*============================================================================
 * Opaque Handle
 *============================================================================*/

typedef struct npe_scheduler npe_scheduler_t;

/*============================================================================
 * Lifecycle
 *============================================================================*/

/**
 * Create a new scheduler.
 */
npe_error_t npe_scheduler_create(const npe_scheduler_config_t *config,
                                 npe_scheduler_t             **out);

/**
 * Destroy the scheduler.  Waits for in-flight work to finish.
 */
void npe_scheduler_destroy(npe_scheduler_t **scheduler);

/*============================================================================
 * Queuing
 *============================================================================*/

/**
 * Queue a single work item.
 *
 * The scheduler takes ownership of the host/port copies inside the item.
 */
npe_error_t npe_scheduler_queue(npe_scheduler_t    *scheduler,
                                const npe_script_t *script,
                                npe_phase_t         phase,
                                const npe_host_t   *host,
                                const npe_port_t   *port,
                                const npe_args_t   *args);

/**
 * Queue all selected scripts for a given phase against one host.
 *
 * For NPE_PHASE_PORTRULE, a work item is created for every
 * (selected_script, port) pair where the script's port interest matches.
 */
npe_error_t npe_scheduler_queue_phase(npe_scheduler_t *scheduler,
                                      npe_phase_t      phase,
                                      const npe_host_t *host);

/**
 * Queue ALL phases for a host in the correct order.
 */
npe_error_t npe_scheduler_queue_host(npe_scheduler_t  *scheduler,
                                     const npe_host_t *host);

/*============================================================================
 * Execution
 *============================================================================*/

/**
 * Start processing the work queue.
 *
 * Launches worker threads (if not already running) and begins dispatching.
 * Returns immediately; use npe_scheduler_wait() to block.
 */
npe_error_t npe_scheduler_run(npe_scheduler_t *scheduler);

/**
 * Block until all queued work items have completed.
 *
 * @param timeout_ms  Maximum wait time.  0 → unlimited.
 * @return NPE_OK when all work is done; NPE_ERROR_TIMEOUT if the deadline
 *         was reached.
 */
npe_error_t npe_scheduler_wait(npe_scheduler_t *scheduler,
                               uint32_t         timeout_ms);

/**
 * Signal all workers to stop as soon as possible.
 *
 * Items already running finish; items still queued are marked CANCELLED.
 * Thread-safe (may be called from a signal handler).
 */
npe_error_t npe_scheduler_shutdown(npe_scheduler_t *scheduler);

/*============================================================================
 * Results
 *============================================================================*/

/**
 * Collect all results from completed work items.
 *
 * @param[out] results   Heap-allocated array.  Caller must free the array
 *                       (results themselves are copies — free with
 *                       npe_result_free_members then free()).
 * @param[out] count     Number of results.
 */
npe_error_t npe_scheduler_get_results(const npe_scheduler_t *scheduler,
                                      npe_result_t         **results,
                                      size_t                *count);

/*============================================================================
 * Statistics
 *============================================================================*/

typedef struct npe_scheduler_stats {
    size_t  total_queued;
    size_t  total_running;
    size_t  total_done;
    size_t  total_failed;
    size_t  total_timeout;
    size_t  total_cancelled;
    size_t  threads_active;
    size_t  queue_depth;
} npe_scheduler_stats_t;

npe_error_t npe_scheduler_get_stats(const npe_scheduler_t  *scheduler,
                                    npe_scheduler_stats_t  *stats);

#ifdef __cplusplus
}
#endif

#endif /* NPE_SCHEDULER_H */
