#include "test.h"

#include "netpeek.h"
#include "recon/context.h"
#include "recon/output_sections.h"

NP_TEST(recon_visibility_version_follows_flag)
{
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    cfg->service_version_detect = false;
    ASSERT_TRUE(!np_recon_should_show_version(ctx));

    cfg->service_version_detect = true;
    ASSERT_TRUE(np_recon_should_show_version(ctx));

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

NP_TEST(recon_visibility_os_only_analyze_or_os_detect)
{
    np_config_t *cfg = np_config_create();
    ASSERT_TRUE(cfg != NULL);

    np_recon_context_t *ctx = np_recon_create(cfg);
    ASSERT_TRUE(ctx != NULL);

    cfg->recon_subcommand = NULL;
    ASSERT_TRUE(!np_recon_should_show_os(ctx));

    cfg->recon_subcommand = "discover";
    ASSERT_TRUE(!np_recon_should_show_os(ctx));

    cfg->recon_subcommand = "analyze";
    ASSERT_TRUE(np_recon_should_show_os(ctx));

    cfg->recon_subcommand = "os-detect";
    ASSERT_TRUE(np_recon_should_show_os(ctx));

    np_recon_destroy(ctx);
    np_config_destroy(cfg);
}

void register_recon_output_visibility_tests(void)
{
    NP_REGISTER(recon_visibility_version_follows_flag);
    NP_REGISTER(recon_visibility_os_only_analyze_or_os_detect);
}
