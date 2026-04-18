#include "runtime/io_engine.h"

#if defined(__linux__) && defined(NP_HAVE_LIBURING)

#include <errno.h>
#include <liburing.h>
#include <stdlib.h>
#include <string.h>

typedef struct np_io_engine_priv_hdr
{
    const char *name;
} np_io_engine_priv_hdr_t;

typedef struct np_uring_op_ctx
{
    int fd;
    np_io_op_t op;
    void *user_data;
} np_uring_op_ctx_t;

typedef struct np_uring_priv
{
    np_io_engine_priv_hdr_t hdr;
    struct io_uring ring;
    unsigned int queued_since_submit;
    int max_events;
} np_uring_priv_t;

static int uring_submit_connect(np_io_engine_t *self, int fd,
                                const struct sockaddr *addr, socklen_t len,
                                void *user_data)
{
    np_uring_priv_t *priv = (np_uring_priv_t *)self->priv;
    if (!priv || fd < 0 || !addr)
        return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&priv->ring);
    if (!sqe)
    {
        if (io_uring_submit(&priv->ring) < 0)
            return -1;

        sqe = io_uring_get_sqe(&priv->ring);
        if (!sqe)
            return -1;
    }

    np_uring_op_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->fd = fd;
    ctx->op = NP_IO_OP_CONNECT;
    ctx->user_data = user_data;

    io_uring_prep_connect(sqe, fd, addr, len);
    io_uring_sqe_set_data(sqe, ctx);
    priv->queued_since_submit++;

    if (priv->queued_since_submit >= 256)
    {
        if (io_uring_submit(&priv->ring) < 0)
            return -1;
        priv->queued_since_submit = 0;
    }

    return 0;
}

static int uring_submit_sendto(np_io_engine_t *self, int fd,
                               const void *buf, size_t len,
                               const struct sockaddr *addr, socklen_t alen,
                               void *user_data)
{
    np_uring_priv_t *priv = (np_uring_priv_t *)self->priv;
    if (!priv || fd < 0 || !buf)
        return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&priv->ring);
    if (!sqe)
    {
        if (io_uring_submit(&priv->ring) < 0)
            return -1;
        sqe = io_uring_get_sqe(&priv->ring);
        if (!sqe)
            return -1;
    }

    np_uring_op_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->fd = fd;
    ctx->op = NP_IO_OP_SENDTO;
    ctx->user_data = user_data;

    io_uring_prep_sendto(sqe, fd, buf, len, 0, addr, alen);
    io_uring_sqe_set_data(sqe, ctx);
    priv->queued_since_submit++;

    if (priv->queued_since_submit >= 256)
    {
        if (io_uring_submit(&priv->ring) < 0)
            return -1;
        priv->queued_since_submit = 0;
    }

    return 0;
}

static int uring_submit_recvfrom(np_io_engine_t *self, int fd,
                                 void *buf, size_t len, void *user_data)
{
    np_uring_priv_t *priv = (np_uring_priv_t *)self->priv;
    if (!priv || fd < 0 || !buf)
        return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&priv->ring);
    if (!sqe)
    {
        if (io_uring_submit(&priv->ring) < 0)
            return -1;
        sqe = io_uring_get_sqe(&priv->ring);
        if (!sqe)
            return -1;
    }

    np_uring_op_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->fd = fd;
    ctx->op = NP_IO_OP_RECVFROM;
    ctx->user_data = user_data;

    io_uring_prep_recv(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, ctx);
    priv->queued_since_submit++;

    if (priv->queued_since_submit >= 256)
    {
        if (io_uring_submit(&priv->ring) < 0)
            return -1;
        priv->queued_since_submit = 0;
    }

    return 0;
}

static int uring_poll(np_io_engine_t *self, np_io_event_t *out,
                      int max_events, int timeout_ms)
{
    np_uring_priv_t *priv = (np_uring_priv_t *)self->priv;
    if (!priv || !out || max_events <= 0)
        return -1;

    if (priv->queued_since_submit > 0)
    {
        if (io_uring_submit(&priv->ring) < 0)
            return -1;
        priv->queued_since_submit = 0;
    }

    if (max_events > priv->max_events)
        max_events = priv->max_events;

    struct __kernel_timespec timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_nsec = (timeout_ms % 1000) * 1000000L;

    int produced = 0;
    while (produced < max_events)
    {
        struct io_uring_cqe *cqe = NULL;
        int rc;

        if (produced == 0)
            rc = io_uring_wait_cqe_timeout(&priv->ring, &cqe, &timeout);
        else
            rc = io_uring_peek_cqe(&priv->ring, &cqe);

        if (rc < 0)
        {
            if (rc == -ETIME || rc == -EAGAIN || rc == -EINTR)
                break;
            return -1;
        }

        np_uring_op_ctx_t *ctx = io_uring_cqe_get_data(cqe);
        int res = cqe->res;

        out[produced].fd = ctx ? ctx->fd : -1;
        out[produced].op = ctx ? ctx->op : NP_IO_OP_CONNECT;
        out[produced].user_data = ctx ? ctx->user_data : NULL;
        out[produced].error = (res < 0) ? -res : 0;
        out[produced].result = (res < 0) ? -1 : res;
        produced++;

        free(ctx);
        io_uring_cqe_seen(&priv->ring, cqe);
    }

    return produced;
}

static void uring_destroy(np_io_engine_t *self)
{
    if (!self || !self->priv)
        return;

    np_uring_priv_t *priv = (np_uring_priv_t *)self->priv;
    io_uring_queue_exit(&priv->ring);
    free(priv);
    self->priv = NULL;
}

int np_io_engine_try_uring(np_io_engine_t *engine, int max_events)
{
    if (!engine)
        return -1;

    np_uring_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv)
        return -1;

    unsigned int depth = (max_events > 0 && max_events <= 1024) ? (unsigned int)max_events : 512u;
    if (depth < 256)
        depth = 256;

    int rc = io_uring_queue_init((unsigned int)depth, &priv->ring, 0);
    if (rc < 0)
    {
        free(priv);
        return -1;
    }

    priv->hdr.name = "io_uring";
    priv->max_events = (int)depth;

    engine->init = NULL;
    engine->submit_connect = uring_submit_connect;
    engine->submit_sendto = uring_submit_sendto;
    engine->submit_recvfrom = uring_submit_recvfrom;
    engine->poll = uring_poll;
    engine->destroy = uring_destroy;
    engine->priv = priv;
    return 0;
}

#else

int np_io_engine_try_uring(np_io_engine_t *engine, int max_events)
{
    (void)engine;
    (void)max_events;
    return -1;
}

#endif
