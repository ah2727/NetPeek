#include "test.h"
#include "args.h"
#include "netpeek.h"
#include <getopt.h>

static np_config_t *cfg_new(void) { return np_config_create(); }

static np_status_t parse_t(int t, np_config_t *cfg)
{
    char temp[8]; snprintf(temp, sizeof(temp), "%d", t);
    char *argv[] = {"scan", "--timing-template", temp, "-t", "127.0.0.1"};
    optind = 1;
    return np_args_parse(5, argv, cfg);
}

NP_TEST(timing_template_0) {
    np_config_t *cfg=cfg_new();
    ASSERT_EQ_INT(NP_OK, parse_t(0,cfg));
    ASSERT_EQ_INT(0, cfg->timing_template);
    ASSERT_EQ_INT(300000000u, cfg->scan_delay_us);
    ASSERT_EQ_INT(1, cfg->min_hostgroup);
    ASSERT_EQ_INT(1, cfg->max_hostgroup);
    ASSERT_EQ_INT(1, cfg->min_parallelism);
    ASSERT_EQ_INT(1, cfg->max_parallelism);
    np_config_destroy(cfg);
}
NP_TEST(timing_template_1) { np_config_t *cfg=cfg_new(); ASSERT_EQ_INT(NP_OK, parse_t(1,cfg)); ASSERT_EQ_INT(1, cfg->timing_template); np_config_destroy(cfg); }
NP_TEST(timing_template_2) { np_config_t *cfg=cfg_new(); ASSERT_EQ_INT(NP_OK, parse_t(2,cfg)); ASSERT_EQ_INT(2, cfg->timing_template); np_config_destroy(cfg); }
NP_TEST(timing_template_3) { np_config_t *cfg=cfg_new(); ASSERT_EQ_INT(NP_OK, parse_t(3,cfg)); ASSERT_EQ_INT(3, cfg->timing_template); np_config_destroy(cfg); }
NP_TEST(timing_template_4) { np_config_t *cfg=cfg_new(); ASSERT_EQ_INT(NP_OK, parse_t(4,cfg)); ASSERT_EQ_INT(4, cfg->timing_template); np_config_destroy(cfg); }
NP_TEST(timing_template_5) { np_config_t *cfg=cfg_new(); ASSERT_EQ_INT(NP_OK, parse_t(5,cfg)); ASSERT_EQ_INT(5, cfg->timing_template); np_config_destroy(cfg); }
NP_TEST(timing_template_invalid) {
    np_config_t *cfg=cfg_new();
    char *argv[] = {"scan", "--timing-template", "7", "-t", "127.0.0.1"};
    optind = 1;
    ASSERT_EQ_INT(NP_ERR_ARGS, np_args_parse(5, argv, cfg));
    np_config_destroy(cfg);
}


NP_TEST(fast_mode_sets_t4_and_udp_defaults)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--fast", "-t", "127.0.0.1"};
    optind = 1;

    ASSERT_EQ_INT(NP_OK, np_args_parse(4, argv, cfg));
    ASSERT_EQ_INT(NP_TIMING_TEMPLATE_4, cfg->timing_template);
    ASSERT_EQ_INT(25000u, cfg->udp_min_probe_interval_us);
    ASSERT_EQ_INT(5000u, cfg->max_rtt_timeout_ms);
    ASSERT_EQ_INT(256u, cfg->udp_batch_size);
    ASSERT_TRUE(cfg->drop_filtered_states);
    ASSERT_TRUE(cfg->udp_linux_advanced);

    np_config_destroy(cfg);
}
void register_timing_tests(void)
{
    NP_REGISTER(timing_template_0);
    NP_REGISTER(timing_template_1);
    NP_REGISTER(timing_template_2);
    NP_REGISTER(timing_template_3);
    NP_REGISTER(timing_template_4);
    NP_REGISTER(timing_template_5);
    NP_REGISTER(timing_template_invalid);
    NP_REGISTER(fast_mode_sets_t4_and_udp_defaults);
}
