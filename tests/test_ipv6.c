#include "test.h"
#include "target.h"
#include "args.h"
#include "netpeek.h"

#include <stdlib.h>
#include <getopt.h>

static np_status_t parse_args(int argc, char **argv, np_config_t *cfg)
{
    optind = 1;
    return np_args_parse(argc, argv, cfg);
}

NP_TEST(cidr_expand_ipv6_128)
{
    np_target_t *targets = NULL;
    uint32_t count = 0;
    ASSERT_EQ_INT(NP_OK, np_target_expand_cidr("2001:db8::1/128", &targets, &count));
    ASSERT_EQ_INT(1, count);
    ASSERT_EQ_STR("2001:db8::1", targets[0].hostname);
    free(targets);
}

NP_TEST(args_parse_bracket_ipv6)
{
    np_config_t *cfg = np_config_create();
    char *argv[] = {"scan", "-t", "[2001:db8::1]", "-p", "80"};
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(1, cfg->target_count);
    ASSERT_EQ_STR("2001:db8::1", cfg->targets[0].hostname);
    np_config_destroy(cfg);
}

void register_ipv6_tests(void)
{
    NP_REGISTER(cidr_expand_ipv6_128);
    NP_REGISTER(args_parse_bracket_ipv6);
}
