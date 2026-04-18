#include "scanner_internal.h"

#include <stdlib.h>

np_status_t np_wq_init(np_work_queue_t *q, uint32_t capacity)
{
    q->items = calloc(capacity, sizeof(np_work_item_t));
    if (!q->items)
        return NP_ERR_MEMORY;

    q->capacity = capacity;
    q->head = 0;
    q->tail = 0;
    q->size = 0;
    pthread_mutex_init(&q->lock, NULL);
    return NP_OK;
}

void np_wq_destroy(np_work_queue_t *q)
{
    if (!q)
        return;

    free(q->items);
    q->items = NULL;
    q->capacity = 0;
    q->head = 0;
    q->tail = 0;
    q->size = 0;
    pthread_mutex_destroy(&q->lock);
}

bool np_wq_pop(np_work_queue_t *q, np_work_item_t *out)
{
    bool got = false;

    pthread_mutex_lock(&q->lock);

    if (q->size > 0) {
        *out = q->items[q->head];
        q->head = (q->head + 1) % q->capacity;
        q->size--;
        got = true;
    }

    pthread_mutex_unlock(&q->lock);
    return got;
}

bool np_wq_push(np_work_queue_t *q, const np_work_item_t *item)
{
    bool ok = false;

    pthread_mutex_lock(&q->lock);

    if (q->size < q->capacity) {
        q->items[q->tail] = *item;
        q->tail = (q->tail + 1) % q->capacity;
        q->size++;
        ok = true;
    }

    pthread_mutex_unlock(&q->lock);
    return ok;
}

uint32_t np_wq_popped_count(np_work_queue_t *q)
{
    uint32_t n;

    pthread_mutex_lock(&q->lock);
    n = q->capacity - q->size;
    pthread_mutex_unlock(&q->lock);

    return n;
}
