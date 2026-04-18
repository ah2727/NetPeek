#include "test.h"
#include "args.h"
#include "netpeek.h"

#include <getopt.h>

static np_status_t parse_args(int argc, char **argv, np_config_t *cfg)
{
    optind = 1;
    return np_args_parse(argc, argv, cfg);
}

NP_TEST(evasion_mtu_and_frag_order)
{
    np_config_t *cfg = np_config_create();
    char *argv[] = {
        "scan", "--mtu", "32", "--frag-order", "random", "-t", "127.0.0.1"
    };
    ASSERT_EQ_INT(NP_OK, parse_args(7, argv, cfg));
    ASSERT_TRUE(cfg->evasion.fragment_packets);
    ASSERT_EQ_INT(32, cfg->evasion.fragment_mtu);
    ASSERT_EQ_INT(NP_FRAG_ORDER_RANDOM, cfg->evasion.fragment_order);
    np_config_destroy(cfg);
}

NP_TEST(evasion_decoys_with_me)
{
    np_config_t *cfg = np_config_create();
    char *argv[] = {
        "scan", "--decoys", "8.8.8.8,ME,1.1.1.1", "-t", "127.0.0.1"
    };
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(2, cfg->evasion.decoy_count);
    ASSERT_TRUE(cfg->evasion.decoy_has_me);
    np_config_destroy(cfg);
}

NP_TEST(evasion_decoys_rnd)
{
    np_config_t *cfg = np_config_create();
    char *argv[] = {
        "scan", "--decoys", "RND:10", "-t", "127.0.0.1"
    };
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(10, cfg->evasion.decoy_count);
    np_config_destroy(cfg);
}

NP_TEST(evasion_source_port_ttl_jitter)
{
    np_config_t *cfg = np_config_create();
    char *argv[] = {
        "scan", "-g", "53", "--ttl", "88", "--scan-jitter", "500ms", "-t", "127.0.0.1"
    };
    ASSERT_EQ_INT(NP_OK, parse_args(9, argv, cfg));
    ASSERT_TRUE(cfg->evasion.source_port_set);
    ASSERT_EQ_INT(53, cfg->evasion.source_port);
    ASSERT_TRUE(cfg->evasion.ttl_set);
    ASSERT_EQ_INT(88, cfg->evasion.ttl_value);
    ASSERT_EQ_INT(500000, cfg->evasion.scan_jitter_us);
    np_config_destroy(cfg);
}

NP_TEST(evasion_randomize_hosts_and_rst)
{
    np_config_t *cfg = np_config_create();
    char *argv[] = {
        "scan", "--randomize-hosts", "--defeat-rst-ratelimit", "-t", "127.0.0.1"
    };
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_TRUE(cfg->randomize_hosts);
    ASSERT_TRUE(cfg->evasion.randomize_hosts);
    ASSERT_TRUE(cfg->evasion.defeat_rst_ratelimit);
    np_config_destroy(cfg);
}

void register_evasion_args_tests(void)
{
    NP_REGISTER(evasion_mtu_and_frag_order);
    NP_REGISTER(evasion_decoys_with_me);
    NP_REGISTER(evasion_decoys_rnd);
    NP_REGISTER(evasion_source_port_ttl_jitter);
    NP_REGISTER(evasion_randomize_hosts_and_rst);
}

