#include "runtime/io_engine.h"

#if defined(__linux__)

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/socket.h>

typedef struct np_io_engine_priv_hdr
{
    const char *name;
} np_io_engine_priv_hdr_t;

typedef struct np_epoll_entry
{
    int fd;
    np_io_op_t op;
    void *user_data;
} np_epoll_entry_t;

typedef struct np_epoll_priv
{
    np_io_engine_priv_hdr_t hdr;
    int epfd;
    int max_events;
    np_epoll_entry_t *entries;
    int entries_count;
    int entries_cap;
    np_io_event_t *ready;
    int ready_head;
    int ready_tail;
    int ready_count;
    int ready_cap;
} np_epoll_priv_t;

static int enqueue_ready(np_epoll_priv_t *priv, const np_io_event_t *event)
{
    if (priv->ready_count == priv->ready_cap)
        return -1;

    priv->ready[priv->ready_tail] = *event;
    priv->ready_tail = (priv->ready_tail + 1) % priv->ready_cap;
    priv->ready_count++;
    return 0;
}

static int drain_ready(np_epoll_priv_t *priv, np_io_event_t *out, int max_events)
{
    int produced = 0;
    while (produced < max_events && priv->ready_count > 0)
    {
        out[produced++] = priv->ready[priv->ready_head];
        priv->ready_head = (priv->ready_head + 1) % priv->ready_cap;
        priv->ready_count--;
    }
    return produced;
}

static int find_entry(np_epoll_priv_t *priv, int fd)
{
    for (int i = 0; i < priv->entries_count; i++)
    {
        if (priv->entries[i].fd == fd)
            return i;
    }
    return -1;
}

static int remove_entry(np_epoll_priv_t *priv, int fd)
{
    int idx = find_entry(priv, fd);
    if (idx < 0)
        return -1;

    if (idx != priv->entries_count - 1)
        priv->entries[idx] = priv->entries[priv->entries_count - 1];

    priv->entries_count--;
    return 0;
}

static int add_entry(np_epoll_priv_t *priv, int fd, np_io_op_t op, void *user_data)
{
    if (find_entry(priv, fd) >= 0)
        return 0;

    if (priv->entries_count == priv->entries_cap)
    {
        int new_cap = priv->entries_cap ? priv->entries_cap * 2 : 64;
        np_epoll_entry_t *next = realloc(priv->entries, (size_t)new_cap * sizeof(*next));
        if (!next)
            return -1;
        priv->entries = next;
        priv->entries_cap = new_cap;
    }

    priv->entries[priv->entries_count++] = (np_epoll_entry_t){
        .fd = fd,
        .op = op,
        .user_data = user_data};
    return 0;
}

static int epoll_submit_connect(np_io_engine_t *self, int fd,
                                const struct sockaddr *addr, socklen_t len,
                                void *user_data)
{
    np_epoll_priv_t *priv = (np_epoll_priv_t *)self->priv;
    if (!priv || fd < 0 || !addr)
        return -1;

    int rc = connect(fd, addr, len);
    if (rc == 0)
    {
        np_io_event_t event = {
            .fd = fd,
            .op = NP_IO_OP_CONNECT,
            .result = 0,
            .error = 0,
            .user_data = user_data};
        return enqueue_ready(priv, &event);
    }

    if (errno != EINPROGRESS)
        return -1;

    struct epoll_event evt;
    memset(&evt, 0, sizeof(evt));
    evt.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
    evt.data.fd = fd;

    if (epoll_ctl(priv->epfd, EPOLL_CTL_ADD, fd, &evt) < 0)
    {
        if (errno != EEXIST)
            return -1;

        if (epoll_ctl(priv->epfd, EPOLL_CTL_MOD, fd, &evt) < 0)
            return -1;
    }

    if (add_entry(priv, fd, NP_IO_OP_CONNECT, user_data) < 0)
    {
        (void)epoll_ctl(priv->epfd, EPOLL_CTL_DEL, fd, NULL);
        return -1;
    }

    return 0;
}

static int epoll_submit_sendto(np_io_engine_t *self, int fd,
                               const void *buf, size_t len,
                               const struct sockaddr *addr, socklen_t alen,
                               void *user_data)
{
    (void)user_data;
    if (!self || fd < 0 || !buf)
        return -1;
    return (int)sendto(fd, buf, len, 0, addr, alen);
}

static int epoll_submit_recvfrom(np_io_engine_t *self, int fd,
                                 void *buf, size_t len, void *user_data)
{
    (void)user_data;
    if (!self || fd < 0 || !buf)
        return -1;
    return (int)recvfrom(fd, buf, len, 0, NULL, NULL);
}

static int epoll_poll(np_io_engine_t *self, np_io_event_t *out,
                      int max_events, int timeout_ms)
{
    np_epoll_priv_t *priv = (np_epoll_priv_t *)self->priv;
    if (!priv || !out || max_events <= 0)
        return -1;

    if (max_events > priv->max_events)
        max_events = priv->max_events;

    int produced = drain_ready(priv, out, max_events);
    if (produced > 0)
        return produced;

    struct epoll_event events[256];
    if (max_events > (int)(sizeof(events) / sizeof(events[0])))
        max_events = (int)(sizeof(events) / sizeof(events[0]));

    int n = epoll_wait(priv->epfd, events, max_events, timeout_ms);
    if (n < 0)
    {
        if (errno == EINTR)
            return 0;
        return -1;
    }

    produced = 0;
    for (int i = 0; i < n && produced < max_events; i++)
    {
        int fd = events[i].data.fd;
        int idx = find_entry(priv, fd);
        if (idx < 0)
            continue;

        int err = 0;
        socklen_t err_len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0)
            err = errno;

        out[produced].fd = fd;
        out[produced].op = priv->entries[idx].op;
        out[produced].user_data = priv->entries[idx].user_data;
        out[produced].error = err;
        out[produced].result = (err == 0) ? 0 : -1;
        produced++;

        (void)epoll_ctl(priv->epfd, EPOLL_CTL_DEL, fd, NULL);
        (void)remove_entry(priv, fd);
    }

    return produced;
}

static void epoll_destroy(np_io_engine_t *self)
{
    if (!self || !self->priv)
        return;

    np_epoll_priv_t *priv = (np_epoll_priv_t *)self->priv;
    if (priv->epfd >= 0)
        close(priv->epfd);
    free(priv->entries);
    free(priv->ready);
    free(priv);
    self->priv = NULL;
}

int np_io_engine_try_epoll(np_io_engine_t *engine, int max_events)
{
    if (!engine)
        return -1;

    np_epoll_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv)
        return -1;

    priv->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (priv->epfd < 0)
    {
        free(priv);
        return -1;
    }

    priv->hdr.name = "epoll";
    priv->max_events = (max_events > 0 && max_events <= 256) ? max_events : 256;
    priv->ready_cap = priv->max_events * 4;
    priv->ready = calloc((size_t)priv->ready_cap, sizeof(*priv->ready));
    if (!priv->ready)
    {
        close(priv->epfd);
        free(priv);
        return -1;
    }

    engine->init = NULL;
    engine->submit_connect = epoll_submit_connect;
    engine->submit_sendto = epoll_submit_sendto;
    engine->submit_recvfrom = epoll_submit_recvfrom;
    engine->poll = epoll_poll;
    engine->destroy = epoll_destroy;
    engine->priv = priv;
    return 0;
}

#else

int np_io_engine_try_epoll(np_io_engine_t *engine, int max_events)
{
    (void)engine;
    (void)max_events;
    return -1;
}

#endif
