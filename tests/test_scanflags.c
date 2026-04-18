#include "test.h"
#include "args.h"
#include "netpeek.h"
#include <getopt.h>

static np_config_t *cfg_new(void) { return np_config_create(); }
static np_status_t parse_args(int argc, char **argv, np_config_t *cfg) { optind = 1; return np_args_parse(argc, argv, cfg); }

NP_TEST(scanflags_hex) {
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--scanflags", "0x12", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(0x12, cfg->tcp_custom_flags);
    np_config_destroy(cfg);
}
NP_TEST(scanflags_decimal) {
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--scanflags", "18", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(18, cfg->tcp_custom_flags);
    np_config_destroy(cfg);
}
NP_TEST(scanflags_tokens_syn_ack) {
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--scanflags", "syn,ack", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(0x12, cfg->tcp_custom_flags);
    np_config_destroy(cfg);
}
NP_TEST(scanflags_case_insensitive) {
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--scanflags", "SYN,ACK", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(0x12, cfg->tcp_custom_flags);
    np_config_destroy(cfg);
}
NP_TEST(scanflags_invalid_token) {
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--scanflags", "foo", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_ERR_ARGS, parse_args(5, argv, cfg));
    np_config_destroy(cfg);
}
NP_TEST(scanflags_invalid_big) {
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--scanflags", "999", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_ERR_ARGS, parse_args(5, argv, cfg));
    np_config_destroy(cfg);
}
NP_TEST(scanflags_invalid_hex) {
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--scanflags", "0xGG", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_ERR_ARGS, parse_args(5, argv, cfg));
    np_config_destroy(cfg);
}

NP_TEST(osscan_guess_flag)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--osscan-guess", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(4, argv, cfg));
    ASSERT_TRUE(cfg->osscan_guess);
    np_config_destroy(cfg);
}

NP_TEST(osscan_limit_flag)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--osscan-limit", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(4, argv, cfg));
    ASSERT_TRUE(cfg->osscan_limit);
    np_config_destroy(cfg);
}

NP_TEST(full_mode_enables_version_and_os_detect)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--full-mode", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(4, argv, cfg));
    ASSERT_EQ_INT(NP_ENGINE_FULL, cfg->engine_mode);
    ASSERT_TRUE(cfg->service_version_detect);
    ASSERT_TRUE(cfg->os_detect);
    np_config_destroy(cfg);
}

void register_scanflags_tests(void)
{
    NP_REGISTER(scanflags_hex);
    NP_REGISTER(scanflags_decimal);
    NP_REGISTER(scanflags_tokens_syn_ack);
    NP_REGISTER(scanflags_case_insensitive);
    NP_REGISTER(scanflags_invalid_token);
    NP_REGISTER(scanflags_invalid_big);
    NP_REGISTER(scanflags_invalid_hex);
    NP_REGISTER(osscan_guess_flag);
    NP_REGISTER(osscan_limit_flag);
    NP_REGISTER(full_mode_enables_version_and_os_detect);
}
