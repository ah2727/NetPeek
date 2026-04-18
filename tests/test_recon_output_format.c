#include "test.h"

#include "recon/output.h"

static np_status_t dummy_emit(np_recon_context_t *ctx, const np_output_config_t *cfg)
{
    (void)ctx;
    (void)cfg;
    return NP_OK;
}

NP_TEST(recon_extension_json_maps_to_json)
{
    ASSERT_EQ_STR("json", np_format_from_extension("result.json"));
}

NP_TEST(recon_extension_case_insensitive)
{
    ASSERT_EQ_STR("md", np_format_from_extension("report.MD"));
}

NP_TEST(recon_extension_unknown_falls_back_text)
{
    ASSERT_EQ_STR("text", np_format_from_extension("report.unknown"));
}

NP_TEST(recon_extension_csv_maps_to_csv)
{
    ASSERT_EQ_STR("csv", np_format_from_extension("report.csv"));
}

NP_TEST(recon_output_find_is_case_insensitive)
{
    static const np_output_module_t mod = {
        .name = "unit.case",
        .format = "unitcase",
        .extensions = "unit",
        .emit = dummy_emit,
    };

    ASSERT_EQ_INT(NP_OK, np_output_register(&mod));
    ASSERT_TRUE(np_output_find("UNITCASE") != NULL);
}

void register_recon_output_format_tests(void)
{
    NP_REGISTER(recon_extension_json_maps_to_json);
    NP_REGISTER(recon_extension_case_insensitive);
    NP_REGISTER(recon_extension_unknown_falls_back_text);
    NP_REGISTER(recon_extension_csv_maps_to_csv);
    NP_REGISTER(recon_output_find_is_case_insensitive);
}
