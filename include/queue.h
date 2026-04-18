#pragma once
#include <stdatomic.h>
#include <stdint.h>

typedef struct {
    uint32_t target;
    uint16_t port;
} work_item_t;

typedef struct {
    work_item_t *items;
    uint32_t capacity;

    atomic_uint head;
    atomic_uint tail;

} work_queue_t;

int queue_init(work_queue_t *q, uint32_t capacity);
int queue_push(work_queue_t *q, work_item_t item);
int queue_pop(work_queue_t *q, work_item_t *item);
void queue_destroy(work_queue_t *q);