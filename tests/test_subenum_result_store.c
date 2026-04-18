#include "test.h"
#include "subenum/result_store.h"

#include <arpa/inet.h>
#include <string.h>

NP_TEST(subenum_store_insert_lookup)
{
    np_result_store_t *store = np_result_store_create(128);
    np_resolved_addr_t a;
    np_subdomain_entry_t *entry;

    ASSERT_TRUE(store != NULL);
    memset(&a, 0, sizeof(a));
    a.family = AF_INET;
    strcpy(a.addr_str, "1.2.3.4");

    ASSERT_TRUE(np_result_store_insert(store, "api.example.com", &a, 1, NP_SUBSRC_BRUTE, 0, 1.5, NULL));
    ASSERT_TRUE(!np_result_store_insert(store, "api.example.com", &a, 1, NP_SUBSRC_CT, 0, 1.0, NULL));
    ASSERT_EQ_INT(1, np_result_store_count(store));

    entry = np_result_store_lookup(store, "api.example.com");
    ASSERT_TRUE(entry != NULL);
    ASSERT_TRUE((entry->sources & NP_SUBSRC_BRUTE) != 0);
    ASSERT_TRUE((entry->sources & NP_SUBSRC_CT) != 0);

    np_result_store_destroy(store);
}

void register_subenum_result_store_tests(void)
{
    NP_REGISTER(subenum_store_insert_lookup);
}
