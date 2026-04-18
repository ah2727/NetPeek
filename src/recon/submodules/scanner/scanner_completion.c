#include "scanner_internal.h"

void np_completion_init(np_completion_t *c, uint32_t count)
{
    pthread_mutex_init(&c->lock, NULL);
    pthread_cond_init(&c->cond, NULL);
    c->pending = count;
}

void np_completion_signal(np_completion_t *c)
{
    pthread_mutex_lock(&c->lock);

    if (c->pending > 0)
        c->pending--;

    if (c->pending == 0)
        pthread_cond_broadcast(&c->cond);

    pthread_mutex_unlock(&c->lock);
}

void np_completion_wait(np_completion_t *c)
{
    pthread_mutex_lock(&c->lock);

    while (c->pending > 0)
        pthread_cond_wait(&c->cond, &c->lock);

    pthread_mutex_unlock(&c->lock);
}

void np_completion_destroy(np_completion_t *c)
{
    pthread_mutex_destroy(&c->lock);
    pthread_cond_destroy(&c->cond);
}
