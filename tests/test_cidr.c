#include "test.h"
#include "target.h"
#include <stdlib.h>

NP_TEST(cidr_detect_true) { ASSERT_TRUE(np_target_is_cidr("10.0.0.0/24")); }
NP_TEST(cidr_detect_false) { ASSERT_TRUE(!np_target_is_cidr("example.com")); }
NP_TEST(cidr_expand_32) {
    np_target_t *targets = NULL; uint32_t count = 0;
    ASSERT_EQ_INT(NP_OK, np_target_expand_cidr("192.168.1.10/32", &targets, &count));
    ASSERT_EQ_INT(1, count); ASSERT_EQ_STR("192.168.1.10", targets[0].hostname); free(targets);
}
NP_TEST(cidr_expand_30_count) {
    np_target_t *targets = NULL; uint32_t count = 0;
    ASSERT_EQ_INT(NP_OK, np_target_expand_cidr("10.0.0.0/30", &targets, &count));
    ASSERT_EQ_INT(4, count); free(targets);
}
NP_TEST(cidr_invalid_prefix) {
    np_target_t *targets = NULL; uint32_t count = 0;
    ASSERT_EQ_INT(NP_ERR_ARGS, np_target_expand_cidr("10.0.0.0/33", &targets, &count));
}
NP_TEST(cidr_invalid_ip) {
    np_target_t *targets = NULL; uint32_t count = 0;
    ASSERT_EQ_INT(NP_ERR_ARGS, np_target_expand_cidr("999.0.0.1/24", &targets, &count));
}
NP_TEST(cidr_bad_format) {
    np_target_t *targets = NULL; uint32_t count = 0;
    ASSERT_EQ_INT(NP_ERR_ARGS, np_target_expand_cidr("10.0.0.1", &targets, &count));
}

void register_cidr_tests(void)
{
    NP_REGISTER(cidr_detect_true);
    NP_REGISTER(cidr_detect_false);
    NP_REGISTER(cidr_expand_32);
    NP_REGISTER(cidr_expand_30_count);
    NP_REGISTER(cidr_invalid_prefix);
    NP_REGISTER(cidr_invalid_ip);
    NP_REGISTER(cidr_bad_format);
}
