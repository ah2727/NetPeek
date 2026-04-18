#define _POSIX_C_SOURCE 200809L

#include "cli.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "subenum/subenum.h"

static int add_domain(np_subenum_config_t *cfg, const char *domain)
{
    char **tmp;
    if (!cfg || !domain || !*domain)
        return -1;

    tmp = realloc(cfg->domains, (cfg->domain_count + 1) * sizeof(*tmp));
    if (!tmp)
        return -1;
    cfg->domains = tmp;

    cfg->domains[cfg->domain_count] = strdup(domain);
    if (!cfg->domains[cfg->domain_count])
        return -1;
    cfg->domain_count++;
    return 0;
}

int cmd_dns(int argc, char **argv)
{
    np_subenum_config_t cfg;
    int opt;

    static struct option long_opts[] = {
        {"sub", no_argument, 0, 1000},
        {"wordlist", required_argument, 0, 1001},
        {"dns-servers", required_argument, 0, 1002},
        {"types", required_argument, 0, 1003},
        {"zone-transfer", no_argument, 0, 1004},
        {"reverse", required_argument, 0, 1005},
        {"json", no_argument, 0, 1006},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    np_subenum_config_init(&cfg);
    optind = 1;

    while ((opt = getopt_long(argc, argv, "T:h", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'T':
            cfg.thread_count = atoi(optarg);
            break;
        case 'h':
            fprintf(stderr, "Usage: netpeek dns <domain> [--sub] [--wordlist FILE] [--json]\n");
            np_subenum_config_free(&cfg);
            return 0;
        case 1000:
            cfg.techniques |= NP_SUBSRC_BRUTE;
            break;
        case 1001:
            free(cfg.wordlist_path);
            cfg.wordlist_path = strdup(optarg);
            break;
        case 1002:
            break;
        case 1003:
            break;
        case 1004:
            cfg.techniques |= NP_SUBSRC_AXFR;
            break;
        case 1005:
            cfg.techniques |= NP_SUBSRC_REVERSE;
            break;
        case 1006:
            cfg.output_json = true;
            break;
        default:
            fprintf(stderr, "Usage: netpeek dns <domain> [--sub] [--wordlist FILE] [--json]\n");
            np_subenum_config_free(&cfg);
            return 1;
        }
    }

    if (optind >= argc)
    {
        fprintf(stderr, "Usage: netpeek dns <domain> [--sub] [--wordlist FILE] [--json]\n");
        np_subenum_config_free(&cfg);
        return 1;
    }

    if (add_domain(&cfg, argv[optind]) != 0)
    {
        np_subenum_config_free(&cfg);
        return 1;
    }

    opt = np_subenum_execute(&cfg);
    np_subenum_config_free(&cfg);
    return opt;
}
