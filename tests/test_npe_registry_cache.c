#include "test.h"
#include "npe/npe_registry.h"

#include <stdio.h>
#include <unistd.h>

NP_TEST(npe_registry_cache_roundtrip_escaped_string)
{
    npe_registry_t *reg = NULL;
    ASSERT_EQ_INT(NPE_OK, npe_registry_create(&reg));

    npe_value_t value;
    value.type = NPE_VAL_STRING;
    value.v.s = "line1\nline2\tvalue\\trail";

    ASSERT_EQ_INT(NPE_OK, npe_registry_shared_set(reg, "k\tey", &value, "writer\nname"));

    char path[] = "/tmp/netpeek-regcache-XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0);
    close(fd);

    ASSERT_EQ_INT(NPE_OK, npe_registry_save_cache(reg, path));
    npe_registry_destroy(reg);

    ASSERT_EQ_INT(NPE_OK, npe_registry_create(&reg));
    ASSERT_EQ_INT(NPE_OK, npe_registry_load_cache(reg, path));

    npe_shared_entry_t out;
    ASSERT_EQ_INT(NPE_OK, npe_registry_shared_get(reg, "k\tey", &out));
    ASSERT_EQ_INT(NPE_VAL_STRING, out.value.type);
    ASSERT_EQ_STR("line1\nline2\tvalue\\trail", out.value.v.s);

    unlink(path);
    npe_registry_destroy(reg);
}

void register_npe_registry_cache_tests(void)
{
    NP_REGISTER(npe_registry_cache_roundtrip_escaped_string);
}
