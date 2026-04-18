#include "test.h"
#include "core/arena.h"
#include <stdint.h>
#include <string.h>

NP_TEST(arena_create_default) { np_arena_t *a = np_arena_create(0); ASSERT_TRUE(a != NULL); np_arena_destroy(a); }
NP_TEST(arena_alloc_basic) { np_arena_t *a = np_arena_create(0); void *p = np_arena_alloc(a, 32); ASSERT_TRUE(p != NULL); np_arena_destroy(a); }
NP_TEST(arena_alloc_many) {
    np_arena_t *a = np_arena_create(64);
    for (int i=0;i<100;i++) ASSERT_TRUE(np_arena_alloc(a, 24) != NULL);
    np_arena_destroy(a);
}
NP_TEST(arena_alloc_large_block) {
    np_arena_t *a = np_arena_create(64);
    void *p = np_arena_alloc(a, 4096);
    ASSERT_TRUE(p != NULL);
    np_arena_destroy(a);
}
NP_TEST(arena_reset_reuse) {
    np_arena_t *a = np_arena_create(128);
    uint8_t *p = np_arena_alloc(a, 64);
    ASSERT_TRUE(p != NULL);
    memset(p, 0xAA, 64);
    np_arena_reset(a);
    ASSERT_TRUE(np_arena_alloc(a, 64) != NULL);
    np_arena_destroy(a);
}
NP_TEST(arena_zero_alloc_null) {
    np_arena_t *a = np_arena_create(128);
    ASSERT_TRUE(np_arena_alloc(a, 0) == NULL);
    np_arena_destroy(a);
}
NP_TEST(arena_null_safe) {
    np_arena_reset(NULL);
    np_arena_destroy(NULL);
    ASSERT_TRUE(1);
}

void register_arena_tests(void)
{
    NP_REGISTER(arena_create_default);
    NP_REGISTER(arena_alloc_basic);
    NP_REGISTER(arena_alloc_many);
    NP_REGISTER(arena_alloc_large_block);
    NP_REGISTER(arena_reset_reuse);
    NP_REGISTER(arena_zero_alloc_null);
    NP_REGISTER(arena_null_safe);
}
