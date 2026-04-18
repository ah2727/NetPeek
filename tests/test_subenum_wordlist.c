#include "test.h"
#include "subenum/wordlist.h"

NP_TEST(subenum_builtin_wordlist)
{
    np_wordlist_t *wl = np_wordlist_load_builtin();
    ASSERT_TRUE(wl != NULL);
    ASSERT_TRUE(wl->count > 5);
    np_wordlist_free(wl);
}

void register_subenum_wordlist_tests(void)
{
    NP_REGISTER(subenum_builtin_wordlist);
}
