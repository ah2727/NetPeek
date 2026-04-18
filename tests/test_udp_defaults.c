#include "test.h"
#include "args.h"
#include "netpeek.h"
#include "ports.h"

#include <getopt.h>

static np_config_t *cfg_new(void) { return np_config_create(); }

NP_TEST(udp_without_ports_defaults_to_top_1000)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--udp", "-t", "127.0.0.1"};

    optind = 1;
    ASSERT_EQ_INT(NP_OK, np_args_parse(4, argv, cfg));

    ASSERT_EQ_INT((int)np_top_ports_count, (int)cfg->ports.count);
    ASSERT_EQ_INT((int)np_top_ports_top_1000[0], (int)cfg->ports.ranges[0].start);
    ASSERT_EQ_INT((int)np_top_ports_top_1000[0], (int)cfg->ports.ranges[0].end);
    ASSERT_EQ_INT((int)np_top_ports_top_1000[1], (int)cfg->ports.ranges[1].start);
    ASSERT_EQ_INT((int)np_top_ports_top_1000[2], (int)cfg->ports.ranges[2].start);

    np_config_destroy(cfg);
}

NP_TEST(tcp_without_ports_keeps_top_ports_default)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "-t", "127.0.0.1"};

    optind = 1;
    ASSERT_EQ_INT(NP_OK, np_args_parse(3, argv, cfg));

    ASSERT_EQ_INT((int)np_top_ports_count, (int)cfg->ports.count);
    ASSERT_EQ_INT((int)np_top_ports_top_1000[0], (int)cfg->ports.ranges[0].start);
    ASSERT_EQ_INT((int)np_top_ports_top_1000[0], (int)cfg->ports.ranges[0].end);

    np_config_destroy(cfg);
}

void register_udp_default_tests(void)
{
    NP_REGISTER(udp_without_ports_defaults_to_top_1000);
    NP_REGISTER(tcp_without_ports_keeps_top_ports_default);
}
