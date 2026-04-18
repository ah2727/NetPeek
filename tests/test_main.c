#include "test.h"

np_test_case_t g_np_tests[NP_MAX_TESTS];
int g_np_test_count = 0;
int g_np_assert_failures = 0;

void register_cidr_tests(void);
void register_ports_tests(void);
void register_scanflags_tests(void);
void register_output_args_tests(void);
void register_timing_tests(void);
void register_evasion_args_tests(void);
void register_arena_tests(void);
void register_checksum_tests(void);
void register_ipv6_tests(void);
void register_subenum_dns_packet_tests(void);
void register_subenum_result_store_tests(void);
void register_subenum_wordlist_tests(void);
void register_privilege_policy_tests(void);
void register_recon_core_tests(void);
void register_recon_output_format_tests(void);
void register_recon_output_visibility_tests(void);
void register_recon_scheduler_tests(void);
void register_npe_registry_cache_tests(void);
void register_udp_default_tests(void);
void register_port_table_tests(void);

int main(void)
{
    register_cidr_tests();
    register_ports_tests();
    register_scanflags_tests();
    register_output_args_tests();
    register_timing_tests();
    register_evasion_args_tests();
    register_arena_tests();
    register_checksum_tests();
    register_ipv6_tests();
    register_subenum_dns_packet_tests();
    register_subenum_result_store_tests();
    register_subenum_wordlist_tests();
    register_privilege_policy_tests();
    register_recon_core_tests();
    register_recon_output_format_tests();
    register_recon_output_visibility_tests();
    register_recon_scheduler_tests();
    register_npe_registry_cache_tests();
    register_udp_default_tests();
    register_port_table_tests();

    int failed = 0;
    for (int i = 0; i < g_np_test_count; i++)
    {
        int before = g_np_assert_failures;
        g_np_tests[i].fn();
        if (g_np_assert_failures == before)
            printf("[PASS] %s\n", g_np_tests[i].name);
        else
        {
            printf("[FAIL] %s\n", g_np_tests[i].name);
            failed++;
        }
    }

    printf("\nTotal: %d  Failed: %d\n", g_np_test_count, failed);
    return failed ? 1 : 0;
}
