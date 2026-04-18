#include "core/arena.h"

#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct np_arena_block
{
    struct np_arena_block *next;
    size_t used;
    size_t size;
    unsigned char data[];
} np_arena_block_t;

struct np_arena
{
    size_t block_size;
    np_arena_block_t *head;
    np_arena_block_t *tail;
};

static size_t align_up(size_t value)
{
    const size_t alignment = alignof(max_align_t);
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static np_arena_block_t *new_block(size_t size)
{
    np_arena_block_t *block = calloc(1, sizeof(*block) + size);
    if (!block)
        return NULL;
    block->size = size;
    return block;
}

np_arena_t *np_arena_create(size_t block_size)
{
    np_arena_t *arena = calloc(1, sizeof(*arena));
    if (!arena)
        return NULL;

    arena->block_size = block_size ? block_size : NP_ARENA_DEFAULT_BLOCK_SIZE;
    return arena;
}

void *np_arena_alloc(np_arena_t *arena, size_t size)
{
    if (!arena || size == 0)
        return NULL;

    size = align_up(size);

    np_arena_block_t *block = arena->tail;
    if (!block || (block->used + size > block->size))
    {
        size_t block_size = arena->block_size;
        if (size > block_size)
            block_size = size;

        np_arena_block_t *newb = new_block(block_size);
        if (!newb)
            return NULL;

        if (!arena->head)
            arena->head = newb;
        else
            arena->tail->next = newb;

        arena->tail = newb;
        block = newb;
    }

    void *ptr = block->data + block->used;
    block->used += size;
    return ptr;
}

void np_arena_reset(np_arena_t *arena)
{
    if (!arena)
        return;

    for (np_arena_block_t *block = arena->head; block; block = block->next)
        block->used = 0;

    arena->tail = arena->head;
}

void np_arena_destroy(np_arena_t *arena)
{
    if (!arena)
        return;

    np_arena_block_t *block = arena->head;
    while (block)
    {
        np_arena_block_t *next = block->next;
        free(block);
        block = next;
    }

    free(arena);
}
