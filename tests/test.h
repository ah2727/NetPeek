#ifndef NP_TEST_H
#define NP_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NP_MAX_TESTS 256

typedef void (*np_test_fn)(void);

typedef struct
{
    const char *name;
    np_test_fn fn;
} np_test_case_t;

extern np_test_case_t g_np_tests[NP_MAX_TESTS];
extern int g_np_test_count;
extern int g_np_assert_failures;

static inline void np_register_test(const char *name, np_test_fn fn)
{
    if (g_np_test_count >= NP_MAX_TESTS)
    {
        fprintf(stderr, "too many tests\n");
        exit(2);
    }
    g_np_tests[g_np_test_count++] = (np_test_case_t){name, fn};
}

#define NP_TEST(name) static void name(void)
#define NP_REGISTER(name) np_register_test(#name, name)

#define ASSERT_TRUE(expr) do { if (!(expr)) { \
    fprintf(stderr, "ASSERT_TRUE failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    g_np_assert_failures++; return; } } while (0)

#define ASSERT_EQ_INT(a,b) do { long _a=(long)(a), _b=(long)(b); if (_a!=_b) { \
    fprintf(stderr, "ASSERT_EQ_INT failed at %s:%d: %ld != %ld\n", __FILE__, __LINE__, _a, _b); \
    g_np_assert_failures++; return; } } while (0)

#define ASSERT_EQ_STR(a,b) do { const char *_a=(a), *_b=(b); if ((!_a && _b) || (_a && !_b) || (_a && _b && strcmp(_a,_b)!=0)) { \
    fprintf(stderr, "ASSERT_EQ_STR failed at %s:%d\n", __FILE__, __LINE__); \
    g_np_assert_failures++; return; } } while (0)

#endif
