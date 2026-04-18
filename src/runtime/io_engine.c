#include "runtime/io_engine.h"

#include <string.h>

typedef struct np_io_engine_priv_hdr
{
    const char *name;
} np_io_engine_priv_hdr_t;

int np_io_engine_create(np_io_engine_t *engine, int max_events)
{
    if (!engine)
        return -1;

    memset(engine, 0, sizeof(*engine));

    if (np_io_engine_try_uring(engine, max_events) == 0)
        return 0;

    if (np_io_engine_try_epoll(engine, max_events) == 0)
        return 0;

    if (np_io_engine_try_kqueue(engine, max_events) == 0)
        return 0;

    return -1;
}

const char *np_io_engine_name(const np_io_engine_t *engine)
{
    if (!engine || !engine->priv)
        return "none";

    const np_io_engine_priv_hdr_t *hdr = (const np_io_engine_priv_hdr_t *)engine->priv;
    return hdr->name ? hdr->name : "unknown";
}
