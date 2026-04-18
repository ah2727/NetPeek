#define _POSIX_C_SOURCE 200809L

#include "subenum/brute.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "subenum/wordlist.h"

int np_brute_run(np_dns_engine_t *engine,
                 const char *domain,
                 const np_subenum_config_t *cfg,
                 uint16_t depth)
{
    np_wordlist_t *wl = NULL;
    size_t i;

    if (!engine || !domain || !cfg)
        return -1;

    if (cfg->wordlist_path && cfg->wordlist_path[0])
        wl = np_wordlist_load_file(cfg->wordlist_path);
    if (!wl || cfg->use_builtin_wordlist)
    {
        if (wl)
            np_wordlist_free(wl);
        wl = np_wordlist_load_builtin();
    }
    if (!wl)
        return -1;

    for (i = 0; i < wl->count; i++)
    {
        char fqdn[640];
        snprintf(fqdn, sizeof(fqdn), "%s.%s", wl->words[i], domain);
        np_dns_engine_submit(engine, fqdn, NP_DNS_REC_A, NP_SUBSRC_BRUTE, depth);
    }

    np_wordlist_free(wl);
    return 0;
}
