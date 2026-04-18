#ifndef NP_CORE_ARENA_H
#define NP_CORE_ARENA_H

#include <stddef.h>

#define NP_ARENA_DEFAULT_BLOCK_SIZE (64u * 1024u)

typedef struct np_arena np_arena_t;

np_arena_t *np_arena_create(size_t block_size);
void *np_arena_alloc(np_arena_t *arena, size_t size);
void np_arena_reset(np_arena_t *arena);
void np_arena_destroy(np_arena_t *arena);

#endif
