#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "event_loop.h"

/* ---------------------------
 * Common lifecycle helpers
 * --------------------------- */

void event_loop_reset(event_loop_t *loop)
{
    if (!loop)
        return;
    loop->backend_fd = -1;
}

static int event_loop_is_initialized(event_loop_t *loop)
{
    return loop && loop->backend_fd >= 0;
}

#if defined(__linux__)

#include <sys/epoll.h>

int event_loop_init(event_loop_t *loop)
{
    if (!loop)
        return -1;

    if (event_loop_is_initialized(loop))
        return 0;

    loop->backend_fd = epoll_create1(EPOLL_CLOEXEC);
    return (loop->backend_fd < 0) ? -1 : 0;
}

int event_loop_add(event_loop_t *loop, int fd)
{
    if (!event_loop_is_initialized(loop))
        return -1;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));

    /* UDP scan only needs read/error readiness; write is not required. */
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLET;
    ev.data.fd = fd;

    if (epoll_ctl(loop->backend_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        if (errno == EEXIST)
            return epoll_ctl(loop->backend_fd, EPOLL_CTL_MOD, fd, &ev);
        return -1;
    }
    return 0;
}

int event_loop_remove(event_loop_t *loop, int fd)
{
    if (!event_loop_is_initialized(loop))
        return -1;

    return epoll_ctl(loop->backend_fd, EPOLL_CTL_DEL, fd, NULL);
}

int event_loop_wait(event_loop_t *loop, event_loop_event_t *out, int max_events)
{
    if (!event_loop_is_initialized(loop))
        return -1;

    struct epoll_event events[128];

    if (max_events > 128)
        max_events = 128;

    int n = epoll_wait(loop->backend_fd, events, max_events, 10); // 10ms instead of 100ms
    if (n < 0)
        return (errno == EINTR) ? 0 : -1;

    for (int i = 0; i < n; i++)
    {
        out[i].fd = events[i].data.fd;
        out[i].readable = (events[i].events & EPOLLIN) != 0;
        out[i].writable = (events[i].events & EPOLLOUT) != 0;
        out[i].error = (events[i].events & (EPOLLERR | EPOLLHUP)) != 0;
    }

    return n;
}

void event_loop_destroy(event_loop_t *loop)
{
    if (!event_loop_is_initialized(loop))
        return;

    close(loop->backend_fd);
    loop->backend_fd = -1;
}

#elif defined(__APPLE__) || defined(__FreeBSD__)

#include <sys/event.h>
#include <sys/time.h>

int event_loop_init(event_loop_t *loop)
{
    if (!loop)
        return -1;

    if (event_loop_is_initialized(loop))
        return 0;

    loop->backend_fd = kqueue();
    return (loop->backend_fd < 0) ? -1 : 0;
}

int event_loop_add(event_loop_t *loop, int fd)
{
    if (!event_loop_is_initialized(loop))
        return -1;

    struct kevent ev;

    /* UDP sockets only require read/error readiness on kqueue. */
    EV_SET(&ev, fd, EVFILT_READ,
           EV_ADD | EV_CLEAR | EV_ENABLE, 0, 0, NULL);

    return kevent(loop->backend_fd, &ev, 1, NULL, 0, NULL);
}

int event_loop_remove(event_loop_t *loop, int fd)
{
    if (!event_loop_is_initialized(loop))
        return -1;

    struct kevent ev;

    EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    (void)kevent(loop->backend_fd, &ev, 1, NULL, 0, NULL);
    return 0;
}

int event_loop_wait(event_loop_t *loop, event_loop_event_t *out, int max_events)
{
    if (!event_loop_is_initialized(loop))
        return -1;

    struct kevent events[128];
    struct timespec timeout = {0, 10 * 1000 * 1000}; // 10ms instead of 100ms

    if (max_events > 128)
        max_events = 128;

    int n = kevent(loop->backend_fd, NULL, 0,
                   events, max_events, &timeout);
    if (n < 0)
        return (errno == EINTR) ? 0 : -1;

    int count = 0;

    for (int i = 0; i < n; i++)
    {
        int fd = (int)events[i].ident;
        int slot = -1;

        for (int j = 0; j < count; j++)
        {
            if (out[j].fd == fd)
            {
                slot = j;
                break;
            }
        }

        if (slot < 0)
        {
            slot = count++;
            out[slot].fd = fd;
            out[slot].readable = 0;
            out[slot].writable = 0;
            out[slot].error = 0;
        }

        if (events[i].filter == EVFILT_READ)
            out[slot].readable = 1;

        if (events[i].filter == EVFILT_WRITE)
            out[slot].writable = 1;

        if (events[i].flags & (EV_ERROR | EV_EOF))
            out[slot].error = 1;
    }

    return count;
}

void event_loop_destroy(event_loop_t *loop)
{
    if (!event_loop_is_initialized(loop))
        return;

    close(loop->backend_fd);
    loop->backend_fd = -1;
}

#else
#error "Unsupported platform"
#endif
