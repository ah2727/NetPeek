#include "test.h"
#include "args.h"
#include "netpeek.h"

#include <getopt.h>

static np_config_t *cfg_new(void) { return np_config_create(); }
static np_status_t parse_args(int argc, char **argv, np_config_t *cfg)
{
    optind = 1;
    return np_args_parse(argc, argv, cfg);
}

NP_TEST(output_xml_flag_sets_format_and_file)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--xml", "out.xml", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(NP_OUTPUT_XML, cfg->output_fmt);
    ASSERT_EQ_STR("out.xml", cfg->output_file);
    np_config_destroy(cfg);
}

NP_TEST(output_html_flag_sets_format_and_file)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--html", "out.html", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(NP_OUTPUT_HTML, cfg->output_fmt);
    ASSERT_EQ_STR("out.html", cfg->output_file);
    np_config_destroy(cfg);
}

NP_TEST(output_file_extension_xml_detected)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "-o", "report.xml", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(NP_OUTPUT_XML, cfg->output_fmt);
    np_config_destroy(cfg);
}

NP_TEST(output_file_extension_html_detected)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "-o", "report.html", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(5, argv, cfg));
    ASSERT_EQ_INT(NP_OUTPUT_HTML, cfg->output_fmt);
    np_config_destroy(cfg);
}

NP_TEST(show_closed_disabled_by_default)
{
    np_config_t *cfg = cfg_new();
    ASSERT_TRUE(!cfg->show_closed);
    np_config_destroy(cfg);
}

NP_TEST(show_closed_flag_keeps_closed_visible)
{
    np_config_t *cfg = cfg_new();
    char *argv[] = {"scan", "--show-closed", "-t", "127.0.0.1"};
    ASSERT_EQ_INT(NP_OK, parse_args(4, argv, cfg));
    ASSERT_TRUE(cfg->show_closed);
    np_config_destroy(cfg);
}

void register_output_args_tests(void)
{
    NP_REGISTER(output_xml_flag_sets_format_and_file);
    NP_REGISTER(output_html_flag_sets_format_and_file);
    NP_REGISTER(output_file_extension_xml_detected);
    NP_REGISTER(output_file_extension_html_detected);
    NP_REGISTER(show_closed_disabled_by_default);
    NP_REGISTER(show_closed_flag_keeps_closed_visible);
}
