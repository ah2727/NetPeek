/*****************************************************************************
 * npe_scheduler.c — Work queue, thread pool, async dispatch
 * ───────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *
 * The scheduler manages the execution of script contexts across multiple
 * worker threads. It provides:
 *   - Work queue with priority-based ordering
 *   - Thread pool with configurable worker count
 *   - Async I/O event dispatch (epoll/kqueue)
 *   - Timeout handling
 *   - Graceful shutdown
 *****************************************************************************/

#include "npe/npe_scheduler.h"
#include "npe/npe_context.h"
#include "npe/npe_runtime.h"
#include "npe/npe_error.h"
#include "logger.h"

#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>
#include <lua.h>
#ifdef __linux__
#include <sys/epoll.h>
#include <sys/eventfd.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#define USE_KQUEUE 1
#else
#error "Unsupported platform: no epoll or kqueue available"
#endif

/*============================================================================
 * Internal Constants
 *============================================================================*/

#define SCHEDULER_MAX_WORKERS 64
#define SCHEDULER_QUEUE_CAPACITY 4096
#define SCHEDULER_POLL_MAX_EVENTS 128
#define SCHEDULER_POLL_TIMEOUT_MS 10

/*============================================================================
 * Work Item
 *============================================================================*/

typedef struct work_item
{
    npe_context_t *ctx;
    uint32_t priority;
    struct work_item *next;
} work_item_t;

/*============================================================================
 * Work Queue (priority-based)
 *============================================================================*/

typedef struct work_queue
{
    work_item_t *head;
    work_item_t *tail;
    size_t count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    size_t capacity;
    bool shutdown;
} work_queue_t;

/*============================================================================
 * I/O Event
 *============================================================================*/

typedef struct io_event
{
    npe_context_t *ctx;
    int fd;
    uint32_t events;
    struct timespec deadline;
    struct io_event *next;
} io_event_t;

/*============================================================================
 * Worker Thread
 *============================================================================*/

typedef struct worker_thread
{
    pthread_t tid;
    struct npe_scheduler *scheduler;
    npe_vm_t *vm;
    uint32_t id;
    bool running;
    uint64_t tasks_completed;
} worker_thread_t;

/*============================================================================
 * Platform I/O Abstraction
 *============================================================================*/

#define NPE_IO_READ 0x01
#define NPE_IO_WRITE 0x02

#ifdef USE_KQUEUE
typedef struct kevent poll_event_t;
#else
typedef struct epoll_event poll_event_t;
#endif

/*============================================================================
 * Scheduler Structure
 *============================================================================*/

struct npe_scheduler
{
    npe_scheduler_config_t config;
    npe_log_fn log_fn;
    void *log_userdata;
    npe_log_level_t log_level;

    work_queue_t queue;

    worker_thread_t *workers;
    size_t worker_count;

    npe_vm_pool_t *vm_pool;

    pthread_t io_thread;
    int poll_fd;
    int wakeup_fd;
#ifdef USE_KQUEUE
    int wakeup_pipe[2];
#endif
    io_event_t *io_events;
    pthread_mutex_t io_mutex;
    atomic_bool io_running;

    npe_scheduler_stats_t stats;
    pthread_mutex_t stats_mutex;
    atomic_size_t in_flight;
    bool running;
    bool abort_flag;
    pthread_mutex_t state_mutex;
};

/*============================================================================
 * Platform I/O — Helpers
 *============================================================================*/

static int platform_poll_create(void)
{
#ifdef USE_KQUEUE
    int fd = kqueue();
    LOGD("kqueue created: fd=%d", fd);
    return fd;
#else
    int fd = epoll_create1(0);
    LOGD("epoll created: fd=%d", fd);
    return fd;
#endif
}

static int platform_wakeup_create(npe_scheduler_t *sched)
{
#ifdef USE_KQUEUE
    if (pipe(sched->wakeup_pipe) < 0)
    {
        LOGE("pipe creation failed: %s", strerror(errno));
        return -1;
    }
    sched->wakeup_fd = sched->wakeup_pipe[0];
    LOGD("wakeup pipe created: read_fd=%d, write_fd=%d",
         sched->wakeup_pipe[0], sched->wakeup_pipe[1]);

    struct kevent kev;
    EV_SET(&kev, sched->wakeup_pipe[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(sched->poll_fd, &kev, 1, NULL, 0, NULL) < 0)
    {
        LOGE("kevent add wakeup failed: %s", strerror(errno));
        return -1;
    }
    return 0;
#else
    sched->wakeup_fd = eventfd(0, EFD_NONBLOCK);
    if (sched->wakeup_fd < 0)
    {
        LOGE("eventfd creation failed: %s", strerror(errno));
        return -1;
    }
    LOGD("eventfd created: fd=%d", sched->wakeup_fd);

    struct epoll_event evt;
    memset(&evt, 0, sizeof(evt));
    evt.events = EPOLLIN;
    evt.data.fd = sched->wakeup_fd;
    if (epoll_ctl(sched->poll_fd, EPOLL_CTL_ADD, sched->wakeup_fd, &evt) < 0)
    {
        LOGE("epoll_ctl add wakeup failed: %s", strerror(errno));
        return -1;
    }
    return 0;
#endif
}

static void platform_wakeup_signal(npe_scheduler_t *sched)
{
#ifdef USE_KQUEUE
    char c = 1;
    ssize_t n = write(sched->wakeup_pipe[1], &c, 1);
    if (n < 0)
        LOGD("wakeup signal write failed: %s", strerror(errno));
#else
    uint64_t val = 1;
    ssize_t n = write(sched->wakeup_fd, &val, sizeof(val));
    if (n < 0)
        LOGD("wakeup signal write failed: %s", strerror(errno));
#endif
}

static void platform_wakeup_drain(npe_scheduler_t *sched)
{
#ifdef USE_KQUEUE
    char buf[64];
    while (read(sched->wakeup_pipe[0], buf, sizeof(buf)) > 0)
    {
    }
#else
    uint64_t val;
    read(sched->wakeup_fd, &val, sizeof(val));
#endif
}

static void platform_wakeup_close(npe_scheduler_t *sched)
{
#ifdef USE_KQUEUE
    LOGD("closing wakeup pipe: read_fd=%d, write_fd=%d",
         sched->wakeup_pipe[0], sched->wakeup_pipe[1]);
    close(sched->wakeup_pipe[0]);
    close(sched->wakeup_pipe[1]);
#else
    LOGD("closing eventfd: fd=%d", sched->wakeup_fd);
    close(sched->wakeup_fd);
#endif
}

static int platform_io_add(npe_scheduler_t *sched, int fd, uint32_t events, void *ptr)
{
#ifdef USE_KQUEUE
    struct kevent changes[2];
    int nchanges = 0;
    if (events & NPE_IO_READ)
    {
        EV_SET(&changes[nchanges], fd, EVFILT_READ,
               EV_ADD | EV_ONESHOT, 0, 0, ptr);
        nchanges++;
    }
    if (events & NPE_IO_WRITE)
    {
        EV_SET(&changes[nchanges], fd, EVFILT_WRITE,
               EV_ADD | EV_ONESHOT, 0, 0, ptr);
        nchanges++;
    }
    int ret = kevent(sched->poll_fd, changes, nchanges, NULL, 0, NULL);
    if (ret < 0)
        LOGD("kevent add fd=%d events=0x%x failed: %s",
             fd, events, strerror(errno));
    else
        LOGD("kevent add fd=%d events=0x%x", fd, events);
    return ret;
#else
    struct epoll_event ep_evt;
    memset(&ep_evt, 0, sizeof(ep_evt));
    if (events & NPE_IO_READ)
        ep_evt.events |= EPOLLIN;
    if (events & NPE_IO_WRITE)
        ep_evt.events |= EPOLLOUT;
    ep_evt.data.ptr = ptr;
    int ret = epoll_ctl(sched->poll_fd, EPOLL_CTL_ADD, fd, &ep_evt);
    if (ret < 0)
        LOGD("epoll_ctl add fd=%d events=0x%x failed: %s",
             fd, events, strerror(errno));
    else
        LOGD("epoll_ctl add fd=%d events=0x%x", fd, events);
    return ret;
#endif
}

static void platform_io_remove(npe_scheduler_t *sched, int fd)
{
#ifdef USE_KQUEUE
    struct kevent changes[2];
    EV_SET(&changes[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    EV_SET(&changes[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    kevent(sched->poll_fd, changes, 2, NULL, 0, NULL);
    LOGD("kevent remove fd=%d", fd);
#else
    epoll_ctl(sched->poll_fd, EPOLL_CTL_DEL, fd, NULL);
    LOGD("epoll_ctl remove fd=%d", fd);
#endif
}

static int platform_io_wait(npe_scheduler_t *sched, poll_event_t *events,
                            int max_events, int timeout_ms)
{
#ifdef USE_KQUEUE
    struct timespec ts;
    ts.tv_sec = timeout_ms / 1000;
    ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
    return kevent(sched->poll_fd, NULL, 0, events, max_events, &ts);
#else
    return epoll_wait(sched->poll_fd, events, max_events, timeout_ms);
#endif
}

static void *platform_event_get_ptr(poll_event_t *evt)
{
#ifdef USE_KQUEUE
    return evt->udata;
#else
    return evt->data.ptr;
#endif
}

static bool platform_event_is_wakeup(npe_scheduler_t *sched, poll_event_t *evt)
{
#ifdef USE_KQUEUE
    return (int)evt->ident == sched->wakeup_pipe[0];
#else
    return evt->data.fd == sched->wakeup_fd;
#endif
}

/*============================================================================
 * Work Queue — Implementation
 *============================================================================*/

static npe_error_t queue_init(work_queue_t *q, size_t capacity)
{
    LOGD("initializing work queue: capacity=%zu", capacity);
    memset(q, 0, sizeof(*q));
    q->capacity = capacity > 0 ? capacity : SCHEDULER_QUEUE_CAPACITY;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
    LOGI("work queue initialized: capacity=%zu", q->capacity);
    return NPE_OK;
}

static void queue_destroy(work_queue_t *q)
{
    LOGD("destroying work queue");
    pthread_mutex_lock(&q->mutex);

    work_item_t *item = q->head;
    size_t freed = 0;
    while (item)
    {
        work_item_t *next = item->next;
        free(item);
        freed++;
        item = next;
    }

    if (freed > 0)
        LOGW("freed %zu pending work items during queue destruction", freed);

    q->head = q->tail = NULL;
    q->count = 0;

    pthread_mutex_unlock(&q->mutex);

    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
    LOGI("work queue destroyed");
}

static npe_error_t queue_push(work_queue_t *q, npe_context_t *ctx, uint32_t priority)
{
    pthread_mutex_lock(&q->mutex);

    while (q->count >= q->capacity && !q->shutdown)
    {
        LOGD("work queue full (count=%zu, capacity=%zu), waiting",
             q->count, q->capacity);
        pthread_cond_wait(&q->not_full, &q->mutex);
    }

    if (q->shutdown)
    {
        LOGD("queue_push rejected: queue is shutdown");
        pthread_mutex_unlock(&q->mutex);
        return NPE_ERROR_GENERIC;
    }

    work_item_t *item = calloc(1, sizeof(work_item_t));
    if (!item)
    {
        LOGE("failed to allocate work item");
        pthread_mutex_unlock(&q->mutex);
        return NPE_ERROR_MEMORY;
    }

    item->ctx = ctx;
    item->priority = priority;
    item->next = NULL;

    if (!q->head || priority > q->head->priority)
    {
        item->next = q->head;
        q->head = item;
        if (!q->tail)
            q->tail = item;
        LOGD("work item queued at head: priority=%u, count=%zu",
             priority, q->count + 1);
    }
    else
    {
        work_item_t *prev = q->head;
        work_item_t *curr = q->head->next;

        while (curr && curr->priority >= priority)
        {
            prev = curr;
            curr = curr->next;
        }

        item->next = curr;
        prev->next = item;
        if (!curr)
            q->tail = item;
        LOGD("work item queued: priority=%u, count=%zu",
             priority, q->count + 1);
    }

    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);

    return NPE_OK;
}

static npe_context_t *queue_pop(work_queue_t *q, uint32_t timeout_ms)
{
    pthread_mutex_lock(&q->mutex);

    struct timespec abs_timeout;
    if (timeout_ms > 0)
    {
        clock_gettime(CLOCK_REALTIME, &abs_timeout);
        abs_timeout.tv_sec += timeout_ms / 1000;
        abs_timeout.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (abs_timeout.tv_nsec >= 1000000000)
        {
            abs_timeout.tv_sec++;
            abs_timeout.tv_nsec -= 1000000000;
        }
    }

    while (q->count == 0 && !q->shutdown)
    {
        if (timeout_ms == 0)
        {
            pthread_cond_wait(&q->not_empty, &q->mutex);
        }
        else
        {
            int err = pthread_cond_timedwait(&q->not_empty, &q->mutex,
                                             &abs_timeout);
            if (err == ETIMEDOUT)
            {
                pthread_mutex_unlock(&q->mutex);
                return NULL;
            }
        }
    }

    if (q->shutdown && q->count == 0)
    {
        LOGD("queue_pop: shutdown with empty queue");
        pthread_mutex_unlock(&q->mutex);
        return NULL;
    }

    work_item_t *item = q->head;
    if (!item)
    {
        pthread_mutex_unlock(&q->mutex);
        return NULL;
    }

    q->head = item->next;
    if (!q->head)
        q->tail = NULL;
    q->count--;

    LOGD("work item dequeued: priority=%u, remaining=%zu",
         item->priority, q->count);

    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);

    npe_context_t *ctx = item->ctx;
    free(item);

    return ctx;
}

/*============================================================================
 * I/O Event Management
 *============================================================================*/

static npe_error_t io_event_add(npe_scheduler_t *sched, npe_context_t *ctx,
                                int fd, uint32_t events, uint32_t timeout_ms)
{
    LOGD("adding I/O event: fd=%d, events=0x%x, timeout=%ums",
         fd, events, timeout_ms);

    pthread_mutex_lock(&sched->io_mutex);

    io_event_t *evt = calloc(1, sizeof(io_event_t));
    if (!evt)
    {
        LOGE("failed to allocate I/O event");
        pthread_mutex_unlock(&sched->io_mutex);
        return NPE_ERROR_MEMORY;
    }

    evt->ctx = ctx;
    evt->fd = fd;
    evt->events = events;

    clock_gettime(CLOCK_MONOTONIC, &evt->deadline);
    evt->deadline.tv_sec += timeout_ms / 1000;
    evt->deadline.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (evt->deadline.tv_nsec >= 1000000000)
    {
        evt->deadline.tv_sec++;
        evt->deadline.tv_nsec -= 1000000000;
    }

    evt->next = sched->io_events;
    sched->io_events = evt;

    if (fd >= 0 && platform_io_add(sched, fd, events, evt) < 0)
    {
        LOGW("platform_io_add failed for fd %d: %s", fd, strerror(errno));
    }

    pthread_mutex_unlock(&sched->io_mutex);

    platform_wakeup_signal(sched);
    LOGI("I/O event added: fd=%d, events=0x%x", fd, events);

    return NPE_OK;
}

static void io_event_remove(npe_scheduler_t *sched, io_event_t *evt)
{
    int fd = evt->fd;
    LOGD("removing I/O event: fd=%d", fd);

    if (fd >= 0)
        platform_io_remove(sched, fd);

    pthread_mutex_lock(&sched->io_mutex);

    if (sched->io_events == evt)
    {
        sched->io_events = evt->next;
    }
    else
    {
        io_event_t *prev = sched->io_events;
        while (prev && prev->next != evt)
            prev = prev->next;
        if (prev)
            prev->next = evt->next;
    }

    pthread_mutex_unlock(&sched->io_mutex);

    free(evt);
    LOGD("I/O event removed: fd=%d", fd);
}

/*============================================================================
 * I/O Thread — event loop
 *============================================================================*/

static void *io_thread_main(void *arg)
{
    npe_scheduler_t *sched = (npe_scheduler_t *)arg;
    poll_event_t events[SCHEDULER_POLL_MAX_EVENTS];

    LOGI("I/O thread started");

    while (atomic_load(&sched->io_running))
    {
        LOGI("I/O thread: loop iteration, io_running=%d", atomic_load(&sched->io_running));
        if (!atomic_load(&sched->io_running))
        {
            LOGI("I/O thread: early exit check triggered");
            break;
        }

        int nfds = platform_io_wait(sched, events, SCHEDULER_POLL_MAX_EVENTS,
                                    SCHEDULER_POLL_TIMEOUT_MS);
        LOGI("I/O thread: platform_io_wait returned nfds=%d, io_running=%d",
             nfds, atomic_load(&sched->io_running));

        /* ── EXIT CHECK RIGHT AFTER WAKEUP ── */
        if (!atomic_load(&sched->io_running))
        {
            LOGI("I/O thread: io_running=0 after poll, breaking out");
            break;
        }

        if (nfds < 0)
        {
            if (errno == EINTR)
            {
                LOGI("I/O wait interrupted");
                continue;
            }
            LOGE("poll wait failed: %s", strerror(errno));
            break;
        }

        if (nfds > 0)
            LOGI("I/O thread: %d events ready", nfds);

        for (int i = 0; i < nfds; i++)
        {
            if (platform_event_is_wakeup(sched, &events[i]))
            {
                LOGI("I/O thread wakeup signal received");
                platform_wakeup_drain(sched);
                continue;
            }

            io_event_t *evt = (io_event_t *)platform_event_get_ptr(&events[i]);
            if (!evt)
                continue;

            LOGI("I/O event ready: fd=%d", evt->fd);

            npe_error_t err = npe_vm_resume(evt->ctx->vm, NPE_OK);
            if (err != NPE_OK)
                LOGW("npe_vm_resume failed: %s", npe_error_string(err));

            npe_context_t *ctx = evt->ctx;
            io_event_remove(sched, evt);
            queue_push(&sched->queue, ctx,
                       ctx->script ? ctx->script->priority : 0);
        }

        LOGI("I/O thread: event processing done, starting timeout sweep");

        /* ── Timeout sweep ─────────────────────────────────────────── */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        LOGI("I/O thread: acquiring io_mutex for timeout sweep");
        pthread_mutex_lock(&sched->io_mutex);
        LOGI("I/O thread: io_mutex acquired");

        io_event_t *evt = sched->io_events;
        io_event_t *prev = NULL;
        int timeouts = 0;

        npe_context_t *timeout_list[SCHEDULER_POLL_MAX_EVENTS];
        uint32_t timeout_prio[SCHEDULER_POLL_MAX_EVENTS];
        int timeout_count = 0;

        while (evt)
        {
            io_event_t *next = evt->next;

            if (now.tv_sec > evt->deadline.tv_sec ||
                (now.tv_sec == evt->deadline.tv_sec &&
                 now.tv_nsec >= evt->deadline.tv_nsec))
            {
                LOGW("I/O timeout: fd=%d", evt->fd);

                npe_vm_resume(evt->ctx->vm, NPE_ERROR_TIMEOUT);
                npe_context_set_state(evt->ctx, NPE_CTX_STATE_TIMEOUT);
                npe_context_set_flag(evt->ctx, NPE_CTX_FLAG_TIMED_OUT);

                if (timeout_count < SCHEDULER_POLL_MAX_EVENTS)
                {
                    timeout_list[timeout_count] = evt->ctx;
                    timeout_prio[timeout_count] = evt->ctx->script
                                                      ? evt->ctx->script->priority
                                                      : 0;
                    timeout_count++;
                }

                if (prev)
                    prev->next = next;
                else
                    sched->io_events = next;

                if (evt->fd >= 0)
                    platform_io_remove(sched, evt->fd);
                free(evt);
                timeouts++;
            }
            else
            {
                prev = evt;
            }

            evt = next;
        }

        LOGI("I/O thread: releasing io_mutex");
        pthread_mutex_unlock(&sched->io_mutex);

        for (int i = 0; i < timeout_count; i++)
        {
            queue_push(&sched->queue, timeout_list[i], timeout_prio[i]);
        }

        if (timeouts > 0)
            LOGI("I/O thread: %d timeouts processed", timeouts);

        LOGI("I/O thread: loop iteration complete");
    }

    LOGI("I/O thread exiting NOW");
    fflush(stderr);
    fflush(stdout);
    return NULL;
}

/*============================================================================
 * Worker Thread — executes contexts
 *============================================================================*/

static void *worker_thread_main(void *arg)
{
    worker_thread_t *worker = (worker_thread_t *)arg;
    npe_scheduler_t *sched = worker->scheduler;

    LOGI("worker thread %u started", worker->id);

    while (worker->running)
    {
        npe_context_t *ctx = queue_pop(&sched->queue, 500);

        if (!ctx)
        {
            pthread_mutex_lock(&sched->state_mutex);
            if (sched->abort_flag || !sched->running)
            {
                LOGD("worker %u: shutdown detected", worker->id);
                pthread_mutex_unlock(&sched->state_mutex);
                break;
            }
            pthread_mutex_unlock(&sched->state_mutex);
            continue;
        }

        /*────────────────────────────────────────────────────────────────
         * PATCH: Increment in_flight exactly once per pop.
         * Re-queued contexts do NOT increment again — they were
         * already counted from the first pop.  Timed-out/error
         * contexts arriving from the I/O thread already have their
         * original increment still live.
         *
         * We track whether this pop is for a FRESH context (needs
         * increment) vs a re-queued one (already counted).
         *────────────────────────────────────────────────────────────────*/
        bool fresh_pop = (ctx->state == NPE_CTX_STATE_INIT ||
                          ctx->state == NPE_CTX_STATE_RULE);
        if (fresh_pop)
            atomic_fetch_add(&sched->in_flight, 1);

        LOGI("worker %u: processing context id=%lu for host %s "
             "(script=%s, state=%d)",
             worker->id, ctx->id, ctx->host.ip,
             ctx->script ? ctx->script->meta.name : "NULL", ctx->state);

        /*────────────────────────────────────────────────────────────────
         * BUG FIX #9: Handle timed-out / error contexts that were
         * re-queued from the I/O thread.  They just need cleanup.
         *────────────────────────────────────────────────────────────────*/
        if (ctx->state == NPE_CTX_STATE_TIMEOUT ||
            ctx->state == NPE_CTX_STATE_ERROR)
        {
            LOGI("worker %u: cleaning up context id=%lu (state=%d)",
                 worker->id, ctx->id, ctx->state);

            /* Release VM if it's still attached from the yield */
            if (ctx->vm)
            {
                npe_vm_t *old_vm = ctx->vm;
                ctx->vm = NULL;
                npe_vm_pool_release(sched->vm_pool, &old_vm);
            }

            npe_context_destroy(&ctx);

            atomic_fetch_sub(&sched->in_flight, 1);
            worker->tasks_completed++;

            pthread_mutex_lock(&sched->stats_mutex);
            sched->stats.total_done++;
            pthread_mutex_unlock(&sched->stats_mutex);
            continue;
        }

        npe_vm_t *vm = NULL;
        npe_error_t err = npe_vm_pool_acquire(sched->vm_pool, &vm);
        if (err != NPE_OK)
        {
            LOGE("worker %u: failed to acquire VM: %s",
                 worker->id, npe_error_string(err));
            npe_context_set_state(ctx, NPE_CTX_STATE_ERROR);
            npe_context_destroy(&ctx);
            atomic_fetch_sub(&sched->in_flight, 1);
            continue;
        }

        ctx->vm = vm;
        npe_vm_set_context(vm, ctx);

        /*────────────────────────────────────────────────────────────────
         * CRITICAL: Load the script into the VM before executing.
         *────────────────────────────────────────────────────────────────*/
        if (!ctx->script || !ctx->script->source.path)
        {
            LOGE("worker %u: context has no script or script source path",
                 worker->id);
            npe_context_set_state(ctx, NPE_CTX_STATE_ERROR);
            npe_vm_pool_release(sched->vm_pool, &vm);
            ctx->vm = NULL;
            npe_context_destroy(&ctx);
            atomic_fetch_sub(&sched->in_flight, 1);
            continue;
        }

        err = npe_vm_load_script(vm, ctx->script);
        if (err != NPE_OK)
        {
            LOGE("worker %u: failed to load script '%s' from '%s': %s",
                 worker->id, ctx->script->meta.name,
                 ctx->script->source.path, npe_error_string(err));
            npe_context_set_state(ctx, NPE_CTX_STATE_ERROR);
            npe_vm_pool_release(sched->vm_pool, &vm);
            ctx->vm = NULL;
            npe_context_destroy(&ctx);
            atomic_fetch_sub(&sched->in_flight, 1);
            continue;
        }

        LOGD("worker %u: script '%s' loaded into VM",
             worker->id, ctx->script->meta.name);

        /*────────────────────────────────────────────────────────────────
         * PATCH: Removed ctx_consumed (was dead code — written but
         * never read).  Only ctx_requeued is needed for the final
         * in_flight / VM release logic.
         *────────────────────────────────────────────────────────────────*/
        bool ctx_requeued = false;

        switch (ctx->state)
        {
        case NPE_CTX_STATE_INIT:
        case NPE_CTX_STATE_RULE:
        {
            bool match = false;

            /*────────────────────────────────────────────────────────────
             * BUG FIX: Determine the correct phase from context.
             * Previously hardcoded to NPE_PHASE_PORTRULE, which
             * fails when has_port is false (port==NULL).
             *────────────────────────────────────────────────────────────*/
            npe_phase_t phase;
            const char *phase_name;
            if (ctx->has_port)
            {
                phase = NPE_PHASE_PORTRULE;
                phase_name = "portrule";
            }
            else
            {
                phase = NPE_PHASE_HOSTRULE;
                phase_name = "hostrule";
            }

            LOGI("worker %u: calling %s for script '%s' on host %s",
                 worker->id, phase_name, ctx->script->meta.name,
                 ctx->host.ip);

            err = npe_vm_call_rule(vm, phase, &ctx->host,
                                   ctx->has_port ? &ctx->port : NULL, &match);

            /*────────────────────────────────────────────────────────────
             * BUG FIX: If hostrule didn't match and we haven't tried
             * portrule yet, try portrule with a nil port so the Lua
             * script can decide (e.g. banner-grab on default ports).
             *────────────────────────────────────────────────────────────*/
            if (err == NPE_OK && !match && phase == NPE_PHASE_HOSTRULE)
            {
                LOGD("worker %u: hostrule didn't match, trying portrule for '%s'",
                     worker->id, ctx->script->meta.name);
                phase = NPE_PHASE_PORTRULE;
                phase_name = "portrule";

                err = npe_vm_call_rule(vm, phase, &ctx->host, NULL, &match);
            }

            if (err == NPE_OK && match)
            {
                LOGI("worker %u: rule matched for '%s' on %s, transitioning to action",
                     worker->id, ctx->script->meta.name, ctx->host.ip);
                npe_context_set_state(ctx, NPE_CTX_STATE_ACTION);

                /*────────────────────────────────────────────────────────
                 * BUG FIX: Release the VM BEFORE re-queuing the context.
                 *────────────────────────────────────────────────────────*/
                npe_vm_pool_release(sched->vm_pool, &vm);
                ctx->vm = NULL;
                vm = NULL; /* prevent double-release below */

                /*────────────────────────────────────────────────────────
                 * PATCH (in_flight balance): Decrement BEFORE re-queue.
                 * The next pop of this context will re-increment via
                 * the fresh_pop logic (state == ACTION is not fresh,
                 * so we handle it below — see note).
                 *────────────────────────────────────────────────────────*/
                queue_push(&sched->queue, ctx, ctx->script->priority);
                ctx_requeued = true;
            }
            else if (err == NPE_OK)
            {
                LOGI("worker %u: rule did NOT match for '%s' on %s",
                     worker->id, ctx->script->meta.name, ctx->host.ip);
                npe_context_set_state(ctx, NPE_CTX_STATE_DONE);
                npe_context_destroy(&ctx);
            }
            else
            {
                LOGE("worker %u: rule error for '%s' on %s: %s",
                     worker->id, ctx->script->meta.name, ctx->host.ip,
                     npe_error_string(err));
                npe_context_set_state(ctx, NPE_CTX_STATE_ERROR);
                npe_context_destroy(&ctx);
            }
            break;
        }

        case NPE_CTX_STATE_ACTION:
        {
            LOGI("worker %u: calling action for '%s' on %s",
                 worker->id, ctx->script->meta.name, ctx->host.ip);

            npe_result_t result;
            memset(&result, 0, sizeof(result));

            err = npe_vm_call_action(vm, &ctx->host,
                                     ctx->has_port ? &ctx->port : NULL,
                                     &result);

            if (err == NPE_OK)
            {
                LOGI("worker %u: action completed for '%s' on %s (output_type=%d)",
                     worker->id, ctx->script->meta.name, ctx->host.ip,
                     result.output.type);

                if (result.output.type == NPE_VAL_STRING && result.output.v.s)
                    LOGI("worker %u: result: %s", worker->id, result.output.v.s);

                ctx->result = result;
                npe_context_set_state(ctx, NPE_CTX_STATE_DONE);
                npe_context_set_flag(ctx, NPE_CTX_FLAG_FINISHED);

                if (sched->config.result_callback)
                {
                    LOGD("worker %u: invoking result callback", worker->id);
                    sched->config.result_callback(ctx->script, &result,
                                                  sched->config.result_userdata);
                }

                npe_context_destroy(&ctx);
            }

            else if (npe_vm_is_yielded(vm))
            {
                npe_yield_info_t yinfo;
                npe_vm_yield_info(vm, &yinfo);

                LOGI("worker %u: script '%s' yielded (reason=%d, fd=%d, timeout=%ums)",
                     worker->id, ctx->script->meta.name,
                     yinfo.reason, yinfo.fd, yinfo.timeout_ms);

                uint32_t io_events = 0;

                if (yinfo.reason == NPE_REASON_YIELD_NONE)
                {
                    if (yinfo.type == NPE_YIELD_READ)
                        yinfo.reason = NPE_REASON_YIELD_SOCKET_READ;
                    else if (yinfo.type == NPE_YIELD_WRITE)
                        yinfo.reason = NPE_REASON_YIELD_SOCKET_WRITE;
                    else if (yinfo.type == NPE_YIELD_CONNECT)
                        yinfo.reason = NPE_REASON_YIELD_SOCKET_CONNECT;
                    else if (yinfo.type == NPE_YIELD_SLEEP)
                        yinfo.reason = NPE_REASON_YIELD_SLEEP;
                }

                if (yinfo.reason == NPE_REASON_YIELD_SOCKET_READ)
                    io_events = NPE_IO_READ;
                else if (yinfo.reason == NPE_REASON_YIELD_SOCKET_WRITE)
                    io_events = NPE_IO_WRITE;
                else if (yinfo.reason == NPE_REASON_YIELD_SOCKET_CONNECT)
                    io_events = NPE_IO_WRITE;
                else if (yinfo.reason == NPE_REASON_YIELD_SLEEP)
                    io_events = 0;

                if (io_events || yinfo.reason == NPE_REASON_YIELD_SLEEP)
                {
                    /*────────────────────────────────────────────────────
                     * Yielded for I/O: the I/O thread owns the context
                     * now. Do NOT release the VM — the script coroutine
                     * state lives inside it. Do NOT decrement in_flight
                     * until the I/O completes and context is re-processed.
                     *────────────────────────────────────────────────────*/
                    io_event_add(sched, ctx,
                                 yinfo.reason == NPE_REASON_YIELD_SLEEP ? -1 : yinfo.fd,
                                 io_events,
                                 yinfo.timeout_ms);
                    vm = NULL; /* prevent release below — VM stays with ctx */
                    ctx_requeued = true;
                }
                else
                {
                    LOGD("worker %u: re-queuing yielded context (no I/O)",
                         worker->id);
                    /*────────────────────────────────────────────────────
                     * PATCH: Non-I/O yield — VM stays with ctx for
                     * resume, but in_flight stays counted (ctx_requeued
                     * prevents decrement below).
                     *────────────────────────────────────────────────────*/
                    queue_push(&sched->queue, ctx, ctx->script->priority);
                    vm = NULL; /* VM stays with ctx for resume */
                    ctx_requeued = true;
                }
            }
            else
            {
                LOGE("worker %u: action error for '%s' on %s: %s",
                     worker->id, ctx->script->meta.name, ctx->host.ip,
                     npe_error_string(err));
                npe_context_set_state(ctx, NPE_CTX_STATE_ERROR);

                if (result.output.type == NPE_VAL_STRING && result.output.v.s)
                {
                    free(result.output.v.s);
                    result.output.v.s = NULL;
                }
                npe_context_destroy(&ctx);
            }
            break;
        }

        default:
            LOGE("worker %u: unexpected context state %d for '%s'",
                 worker->id, ctx->state,
                 ctx->script ? ctx->script->meta.name : "NULL");
            npe_context_destroy(&ctx);
            break;
        }

        /*────────────────────────────────────────────────────────────────
         * BUG FIX: Only release VM if it wasn't already released or
         * transferred to a re-queued/yielded context.
         *────────────────────────────────────────────────────────────────*/
        if (vm)
        {
            npe_vm_pool_release(sched->vm_pool, &vm);
            vm = NULL;
        }

        /*────────────────────────────────────────────────────────────────
         * PATCH (in_flight accounting):
         *
         * in_flight was incremented at the top ONLY for fresh pops
         * (INIT/RULE). For re-queued ACTION contexts, in_flight was
         * already live from the original INIT/RULE pop.
         *
         * Decrement when context is truly finished (destroyed).
         * If re-queued (rule→action transition, yield), do NOT
         * decrement — the count stays live until final completion.
         *────────────────────────────────────────────────────────────────*/
        if (!ctx_requeued)
        {
            atomic_fetch_sub(&sched->in_flight, 1);
            worker->tasks_completed++;

            pthread_mutex_lock(&sched->stats_mutex);
            sched->stats.total_done++;
            pthread_mutex_unlock(&sched->stats_mutex);
        }
    }

    LOGI("worker thread %u exiting (%llu tasks completed)",
         worker->id, (unsigned long long)worker->tasks_completed);
    return NULL;
}

/*============================================================================
 * npe_scheduler_create
 *============================================================================*/

npe_error_t npe_scheduler_create(const npe_scheduler_config_t *config, npe_scheduler_t **out)
{
    if (!out)
    {
        LOGE("npe_scheduler_create: null output pointer");
        return NPE_ERROR_INVALID_ARG;
    }
    *out = NULL;

    LOGI("creating scheduler");

    npe_scheduler_t *sched = calloc(1, sizeof(npe_scheduler_t));
    if (!sched)
    {
        LOGE("failed to allocate scheduler");
        return NPE_ERROR_MEMORY;
    }

    if (config)
    {
        sched->config = *config;
        LOGD("scheduler config: threads=%zu, queue_capacity=%zu, timeout=%ums",
             config->thread_count, config->queue_capacity, config->default_timeout_ms);
    }
    else
    {
        sched->config.thread_count = 4;
        sched->config.queue_capacity = 1024;
        sched->config.default_timeout_ms = NPE_DEFAULT_TIMEOUT_MS;
        LOGD("using default scheduler config: threads=4, queue_capacity=1024");
    }

    sched->log_fn = sched->config.log_fn;
    sched->log_userdata = sched->config.log_userdata;
    sched->log_level = sched->config.log_level;
    sched->vm_pool = sched->config.vm_pool;

    npe_error_t err = queue_init(&sched->queue, sched->config.queue_capacity);
    if (err != NPE_OK)
    {
        LOGE("queue initialization failed: %s", npe_error_string(err));
        free(sched);
        return err;
    }

    sched->poll_fd = platform_poll_create();
    if (sched->poll_fd < 0)
    {
        LOGE("poll creation failed: %s", strerror(errno));
        queue_destroy(&sched->queue);
        free(sched);
        return NPE_ERROR_IO;
    }

    if (platform_wakeup_create(sched) < 0)
    {
        LOGE("wakeup mechanism creation failed");
        close(sched->poll_fd);
        queue_destroy(&sched->queue);
        free(sched);
        return NPE_ERROR_IO;
    }

    pthread_mutex_init(&sched->io_mutex, NULL);
    pthread_mutex_init(&sched->stats_mutex, NULL);
    pthread_mutex_init(&sched->state_mutex, NULL);
    LOGI("scheduler created successfully");

    *out = sched;
    return NPE_OK;
}

/*============================================================================
 * npe_scheduler_destroy
 *============================================================================*/

void npe_scheduler_destroy(npe_scheduler_t **sched)
{
    if (!sched || !*sched)
        return;

    npe_scheduler_t *s = *sched;

    LOGI("destroying scheduler");

    if (s->running)
    {
        LOGW("scheduler still running during destroy, shutting down");
        npe_scheduler_shutdown(s);
    }

    platform_wakeup_close(s);
    close(s->poll_fd);

    queue_destroy(&s->queue);

    pthread_mutex_destroy(&s->io_mutex);
    pthread_mutex_destroy(&s->stats_mutex);
    pthread_mutex_destroy(&s->state_mutex);

    free(s->workers);

    LOGI("scheduler destroyed");

    free(s);
    *sched = NULL;
}

/*============================================================================
 * npe_scheduler_run
 *============================================================================*/

npe_error_t npe_scheduler_run(npe_scheduler_t *sched)
{
    if (!sched)
    {
        LOGE("npe_scheduler_run: null scheduler");
        return NPE_ERROR_INVALID_ARG;
    }

    pthread_mutex_lock(&sched->state_mutex);
    if (sched->running)
    {
        pthread_mutex_unlock(&sched->state_mutex);
        LOGW("scheduler already running");
        return NPE_ERROR_GENERIC;
    }
    atomic_store(&sched->io_running, true);
    sched->running = true;
    sched->abort_flag = false;
    pthread_mutex_unlock(&sched->state_mutex);

    LOGI("starting scheduler");

    if (pthread_create(&sched->io_thread, NULL, io_thread_main, sched) != 0)
    {
        LOGE("failed to create I/O thread: %s", strerror(errno));
        pthread_mutex_lock(&sched->state_mutex);
        sched->running = false;
        atomic_store(&sched->io_running, false);
        pthread_mutex_unlock(&sched->state_mutex);
        return NPE_ERROR_GENERIC;
    }

    size_t nworkers = sched->config.thread_count;
    if (nworkers == 0)
        nworkers = 4;
    if (nworkers > SCHEDULER_MAX_WORKERS)
    {
        LOGW("thread count %zu exceeds max %d, capping", nworkers, SCHEDULER_MAX_WORKERS);
        nworkers = SCHEDULER_MAX_WORKERS;
    }

    sched->workers = calloc(nworkers, sizeof(worker_thread_t));
    if (!sched->workers)
    {
        LOGE("failed to allocate worker array");
        sched->io_running = false;
        pthread_join(sched->io_thread, NULL);
        pthread_mutex_lock(&sched->state_mutex);
        sched->running = false;
        pthread_mutex_unlock(&sched->state_mutex);
        return NPE_ERROR_MEMORY;
    }

    sched->worker_count = nworkers;

    for (size_t i = 0; i < nworkers; i++)
    {
        worker_thread_t *w = &sched->workers[i];
        w->id = (uint32_t)i;
        w->scheduler = sched;
        w->running = true;

        if (pthread_create(&w->tid, NULL, worker_thread_main, w) != 0)
        {
            LOGE("failed to create worker thread %zu: %s", i, strerror(errno));
            w->running = false;
        }
    }

    LOGI("scheduler started with %zu workers", nworkers);

    return NPE_OK;
}

/*============================================================================
 * npe_scheduler_shutdown
 *============================================================================*/

npe_error_t npe_scheduler_shutdown(npe_scheduler_t *sched)
{
    if (!sched)
    {
        LOGE("npe_scheduler_shutdown: null scheduler");
        return NPE_ERROR_INVALID_ARG;
    }
    if (!sched->running)
    {
        LOGD("scheduler not running, nothing to shutdown");
        return NPE_OK;
    }
    LOGI("shutting down scheduler");

    pthread_mutex_lock(&sched->state_mutex);
    sched->running = false;
    sched->queue.shutdown = true;
    pthread_mutex_unlock(&sched->state_mutex);

    /* ── Stop and join workers FIRST ── */
    for (size_t i = 0; i < sched->worker_count; i++)
        sched->workers[i].running = false;

    pthread_cond_broadcast(&sched->queue.not_empty);
    pthread_cond_broadcast(&sched->queue.not_full);

    LOGD("waiting for %zu worker threads to exit", sched->worker_count);
    for (size_t i = 0; i < sched->worker_count; i++)
    {
        worker_thread_t *w = &sched->workers[i];
        pthread_join(w->tid, NULL);
        LOGD("worker %u joined", w->id);
    }

    /* ── Then stop I/O thread ── */
    atomic_store(&sched->io_running, false);
    platform_wakeup_signal(sched);
    usleep(1000);
    platform_wakeup_signal(sched);
    LOGI("waiting for I/O thread to exit, io_running=%d", atomic_load(&sched->io_running));
    pthread_join(sched->io_thread, NULL);
    LOGI("I/O thread joined");

    return NPE_OK;
}

/*============================================================================
 * npe_scheduler_queue
 *============================================================================*/

npe_error_t npe_scheduler_queue(npe_scheduler_t *sched, const npe_script_t *script,
                                npe_phase_t phase, const npe_host_t *host,
                                const npe_port_t *port, const npe_args_t *args)
{
    if (!sched || !script || !host)
    {
        LOGE("npe_scheduler_queue: invalid arguments");
        return NPE_ERROR_INVALID_ARG;
    }
    if (!sched->running)
    {
        LOGW("cannot queue work: scheduler not running");
        return NPE_ERROR_GENERIC;
    }

    LOGD("queuing script: phase=%d, priority=%u", phase, script->priority);

    npe_engine_t *engine = sched->config.engine;
    if (!engine)
    {
        LOGE("npe_scheduler_queue: scheduler missing engine reference");
        return NPE_ERROR_SYSTEM;
    }

    npe_context_t *ctx = NULL;
    npe_error_t err = npe_context_create(engine, script, host, port, &ctx);
    if (err != NPE_OK)
    {
        LOGE("failed to create context: %s", npe_error_string(err));
        return err;
    }

    if (args)
    {
        ctx->args = *args;
        LOGD("context created with args");
    }

    uint32_t priority = script->priority;

    err = queue_push(&sched->queue, ctx, priority);
    if (err != NPE_OK)
    {
        LOGE("failed to queue context: %s", npe_error_string(err));
        npe_context_destroy(&ctx);
        return err;
    }

    pthread_mutex_lock(&sched->stats_mutex);
    sched->stats.total_queued++;
    sched->stats.queue_depth = sched->queue.count;
    pthread_mutex_unlock(&sched->stats_mutex);

    LOGI("script queued: priority=%u, queue_depth=%zu", priority, sched->queue.count);

    return NPE_OK;
}

/*============================================================================
 * npe_scheduler_queue_phase
 *============================================================================*/

npe_error_t npe_scheduler_queue_phase(npe_scheduler_t *sched, npe_phase_t phase, const npe_host_t *host)
{
    if (!sched || !host)
    {
        LOGE("npe_scheduler_queue_phase: invalid arguments");
        return NPE_ERROR_INVALID_ARG;
    }
    LOGD("queuing phase %d for host", phase);

    (void)phase;
    return NPE_OK;
}

/*============================================================================
 * npe_scheduler_queue_host
 *============================================================================*/

npe_error_t npe_scheduler_queue_host(npe_scheduler_t *sched, const npe_host_t *host)
{
    if (!sched || !host)
    {
        LOGE("npe_scheduler_queue_host: invalid arguments");
        return NPE_ERROR_INVALID_ARG;
    }

    LOGI("queuing all phases for host");

    npe_error_t err;

    err = npe_scheduler_queue_phase(sched, NPE_PHASE_PRERULE, host);
    if (err != NPE_OK)
    {
        LOGE("failed to queue PRERULE phase: %s", npe_error_string(err));
        return err;
    }

    err = npe_scheduler_queue_phase(sched, NPE_PHASE_HOSTRULE, host);
    if (err != NPE_OK)
    {
        LOGE("failed to queue HOSTRULE phase: %s", npe_error_string(err));
        return err;
    }

    err = npe_scheduler_queue_phase(sched, NPE_PHASE_PORTRULE, host);
    if (err != NPE_OK)
    {
        LOGE("failed to queue PORTRULE phase: %s", npe_error_string(err));
        return err;
    }

    err = npe_scheduler_queue_phase(sched, NPE_PHASE_POSTRULE, host);
    if (err != NPE_OK)
    {
        LOGE("failed to queue POSTRULE phase: %s", npe_error_string(err));
        return err;
    }

    LOGI("all phases queued for host");

    return NPE_OK;
}

/*============================================================================
 * npe_scheduler_wait
 *============================================================================*/

npe_error_t npe_scheduler_wait(npe_scheduler_t *sched, uint32_t timeout_ms)
{
    if (!sched)
    {
        LOGE("npe_scheduler_wait: null scheduler");
        return NPE_ERROR_INVALID_ARG;
    }
    LOGD("waiting for queue to drain (timeout=%ums)", timeout_ms);

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (sched->running)
    {
        pthread_mutex_lock(&sched->stats_mutex);
        size_t queued = sched->queue.count;
        pthread_mutex_unlock(&sched->stats_mutex);

        if (queued == 0 && atomic_load(&sched->in_flight) == 0)
        {
            usleep(50000);
            pthread_mutex_lock(&sched->stats_mutex);
            queued = sched->queue.count;
            pthread_mutex_unlock(&sched->stats_mutex);
            if (queued == 0 && atomic_load(&sched->in_flight) == 0)
            {
                LOGI("queue drained successfully");
                return NPE_OK;
            }
        }

        if (queued == 0)
        {
            usleep(50000);
            pthread_mutex_lock(&sched->stats_mutex);
            queued = sched->queue.count;
            pthread_mutex_unlock(&sched->stats_mutex);
            if (queued == 0 && atomic_load(&sched->in_flight) == 0)
            {
                LOGI("queue drained successfully");
                return NPE_OK;
            }
        }

        if (timeout_ms > 0)
        {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            uint64_t elapsed = (uint64_t)(now.tv_sec - start.tv_sec) * 1000 +
                               (uint64_t)(now.tv_nsec - start.tv_nsec) / 1000000;
            if (elapsed >= timeout_ms)
            {
                LOGW("wait timeout after %llums (queue_depth=%zu)", (unsigned long long)elapsed, queued);
                return NPE_ERROR_TIMEOUT;
            }
        }

        usleep(10000);
    }

    LOGD("wait interrupted: scheduler stopped");
    return NPE_OK;
}

/*============================================================================
 * npe_scheduler_get_results
 *============================================================================*/

npe_error_t npe_scheduler_get_results(const npe_scheduler_t *sched, npe_result_t **results, size_t *count)
{
    if (!sched || !results || !count)
    {
        LOGE("npe_scheduler_get_results: invalid arguments");
        return NPE_ERROR_INVALID_ARG;
    }

    LOGD("getting results (not implemented)");

    *results = NULL;
    *count = 0;
    return NPE_OK;
}

/*============================================================================
 * npe_scheduler_get_stats
 *============================================================================*/

npe_error_t npe_scheduler_get_stats(const npe_scheduler_t *sched, npe_scheduler_stats_t *stats)
{
    if (!sched || !stats)
    {
        LOGE("npe_scheduler_get_stats: invalid arguments");
        return NPE_ERROR_INVALID_ARG;
    }

    pthread_mutex_lock((pthread_mutex_t *)&sched->stats_mutex);
    *stats = sched->stats;
    stats->queue_depth = sched->queue.count;
    stats->threads_active = sched->worker_count;
    pthread_mutex_unlock((pthread_mutex_t *)&sched->stats_mutex);

    LOGD("stats: queued=%llu, done=%llu, queue_depth=%zu, threads=%zu",
         (unsigned long long)stats->total_queued,
         (unsigned long long)stats->total_done,
         stats->queue_depth,
         stats->threads_active);

    return NPE_OK;
}
