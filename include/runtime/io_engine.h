#ifndef NP_IO_ENGINE_H
#define NP_IO_ENGINE_H

#include <stddef.h>
#include <sys/socket.h>

typedef enum np_io_op
{
    NP_IO_OP_CONNECT = 1,
    NP_IO_OP_SENDTO,
    NP_IO_OP_RECVFROM
} np_io_op_t;

typedef struct np_io_event
{
    int fd;
    np_io_op_t op;
    int result;
    int error;
    void *user_data;
} np_io_event_t;

typedef struct np_io_engine
{
    int (*init)(struct np_io_engine *self, int max_events);
    int (*submit_connect)(struct np_io_engine *self, int fd,
                          const struct sockaddr *addr, socklen_t len,
                          void *user_data);
    int (*submit_sendto)(struct np_io_engine *self, int fd,
                         const void *buf, size_t len,
                         const struct sockaddr *addr, socklen_t alen,
                         void *user_data);
    int (*submit_recvfrom)(struct np_io_engine *self, int fd,
                           void *buf, size_t len, void *user_data);
    int (*poll)(struct np_io_engine *self, np_io_event_t *out,
                int max_events, int timeout_ms);
    void (*destroy)(struct np_io_engine *self);
    void *priv;
} np_io_engine_t;

int np_io_engine_create(np_io_engine_t *engine, int max_events);
const char *np_io_engine_name(const np_io_engine_t *engine);

int np_io_engine_try_uring(np_io_engine_t *engine, int max_events);
int np_io_engine_try_epoll(np_io_engine_t *engine, int max_events);
int np_io_engine_try_kqueue(np_io_engine_t *engine, int max_events);

#endif
