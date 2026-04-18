#define _POSIX_C_SOURCE 200809L

#include "cli.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "proxy.h"
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

static void subenum_usage(void)
{
    fprintf(stderr,
            "Usage: netpeek subenum -d <domain> [options]\n"
            "       netpeek subenum <domain> [options]\n\n"
            "Options:\n"
            "  -d, --domain <domain>       Target domain (repeatable)\n"
            "  -w, --wordlist <file>       Wordlist for brute-force\n"
            "      --builtin-wordlist      Use compiled-in default wordlist\n"
            "  -T, --threads <n>           Worker count (default 32)\n"
            "      --timeout <ms>          DNS timeout in milliseconds\n"
            "      --dns-servers <list>    Custom resolvers (reserved)\n"
            "      --system-dns            Use OS resolver\n"
            "  -r, --recursive             Recursive enumeration (reserved)\n"
            "      --max-depth <n>         Max recursion depth\n"
            "      --brute                 Enable brute-force\n"
            "      --axfr                  Attempt AXFR\n"
            "      --ct                    CT-derived seeds\n"
            "      --ct-provider <name>    CT provider: crtsh|certspotter|all\n"
            "      --ct-token <token>      Cert Spotter API token\n"
            "      --proxy <url>           HTTP/SOCKS proxy URL\n"
            "      --reverse               Reverse DNS sweep\n"
            "      --permute               Permutation pass\n"
            "      --wildcard-detect       Wildcard filtering\n"
            "      --resolve               Resolve found subdomains\n"
            "      --filter-alive          Only keep resolving hosts\n"
            "      --json | --csv | --grep Output format\n"
            "  -o, --output <file>         Write output to file\n"
            "  -v, --verbose               Verbose mode\n"
            "  -h, --help                  Show help\n");
}

int cmd_subenum(int argc, char **argv)
{
    np_subenum_config_t cfg;
    int ch;

    static struct option long_opts[] = {
        {"domain", required_argument, NULL, 'd'},
        {"wordlist", required_argument, NULL, 'w'},
        {"builtin-wordlist", no_argument, NULL, 1000},
        {"threads", required_argument, NULL, 'T'},
        {"timeout", required_argument, NULL, 1001},
        {"dns-servers", required_argument, NULL, 1002},
        {"system-dns", no_argument, NULL, 1003},
        {"recursive", no_argument, NULL, 'r'},
        {"max-depth", required_argument, NULL, 1004},
        {"brute", no_argument, NULL, 1005},
        {"axfr", no_argument, NULL, 1006},
        {"ct", no_argument, NULL, 1007},
        {"ct-provider", required_argument, NULL, 1016},
        {"ct-token", required_argument, NULL, 1017},
        {"proxy", required_argument, NULL, 1018},
        {"reverse", no_argument, NULL, 1008},
        {"permute", no_argument, NULL, 1009},
        {"wildcard-detect", no_argument, NULL, 1010},
        {"resolve", no_argument, NULL, 1011},
        {"filter-alive", no_argument, NULL, 1012},
        {"json", no_argument, NULL, 1013},
        {"csv", no_argument, NULL, 1014},
        {"grep", no_argument, NULL, 1015},
        {"output", required_argument, NULL, 'o'},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    np_subenum_config_init(&cfg);
    optind = 1;

    while ((ch = getopt_long(argc, argv, "d:w:T:ro:vh", long_opts, NULL)) != -1)
    {
        switch (ch)
        {
        case 'd':
            if (add_domain(&cfg, optarg) != 0)
                goto fail;
            break;
        case 'w':
            free(cfg.wordlist_path);
            cfg.wordlist_path = strdup(optarg);
            if (!cfg.wordlist_path)
                goto fail;
            break;
        case 'T':
            cfg.thread_count = atoi(optarg);
            break;
        case 'r':
            cfg.recursive = true;
            break;
        case 'o':
            free(cfg.output_file);
            cfg.output_file = strdup(optarg);
            if (!cfg.output_file)
                goto fail;
            break;
        case 'v':
            cfg.verbose = true;
            break;
        case 'h':
            subenum_usage();
            np_subenum_config_free(&cfg);
            return 0;
        case 1000:
            cfg.use_builtin_wordlist = true;
            break;
        case 1001:
            cfg.timeout_ms = atoi(optarg);
            break;
        case 1002:
            break;
        case 1003:
            cfg.use_system_dns = true;
            break;
        case 1004:
            cfg.max_depth = atoi(optarg);
            break;
        case 1005:
            cfg.techniques |= NP_SUBSRC_BRUTE;
            break;
        case 1006:
            cfg.techniques |= NP_SUBSRC_AXFR;
            break;
        case 1007:
            cfg.techniques |= NP_SUBSRC_CT;
            break;
        case 1008:
            cfg.techniques |= NP_SUBSRC_REVERSE;
            break;
        case 1016:
            if (strcasecmp(optarg, "all") == 0)
                cfg.ct_providers = NP_CTPROV_CRTSH | NP_CTPROV_CERTSPOTTER;
            else if (strcasecmp(optarg, "crtsh") == 0)
                cfg.ct_providers = NP_CTPROV_CRTSH;
            else if (strcasecmp(optarg, "certspotter") == 0)
                cfg.ct_providers = NP_CTPROV_CERTSPOTTER;
            else
            {
                fprintf(stderr, "subenum: invalid --ct-provider '%s'\n", optarg);
                np_subenum_config_free(&cfg);
                return 1;
            }
            break;
        case 1017:
            free(cfg.ct_certspotter_token);
            cfg.ct_certspotter_token = strdup(optarg);
            if (!cfg.ct_certspotter_token)
                goto fail;
            break;
        case 1018:
        {
            np_proxy_t parsed;
            if (np_proxy_parse(optarg, &parsed) != NP_OK)
            {
                fprintf(stderr, "subenum: invalid --proxy URL '%s'\n", optarg);
                np_subenum_config_free(&cfg);
                return 1;
            }
            free(cfg.http_proxy);
            cfg.http_proxy = strdup(optarg);
            if (!cfg.http_proxy)
                goto fail;
            break;
        }
        case 1009:
            cfg.techniques |= NP_SUBSRC_PERMUTE;
            break;
        case 1010:
            cfg.wildcard_detect = true;
            break;
        case 1011:
            cfg.resolve_all = true;
            break;
        case 1012:
            cfg.filter_alive = true;
            break;
        case 1013:
            cfg.output_json = true;
            cfg.output_csv = false;
            cfg.output_grep = false;
            break;
        case 1014:
            cfg.output_json = false;
            cfg.output_csv = true;
            cfg.output_grep = false;
            break;
        case 1015:
            cfg.output_json = false;
            cfg.output_csv = false;
            cfg.output_grep = true;
            break;
        default:
            subenum_usage();
            np_subenum_config_free(&cfg);
            return 1;
        }
    }

    if (cfg.domain_count == 0 && optind < argc)
    {
        if (add_domain(&cfg, argv[optind]) != 0)
            goto fail;
    }

    if (cfg.domain_count == 0)
    {
        subenum_usage();
        np_subenum_config_free(&cfg);
        return 1;
    }

    if (!cfg.ct_certspotter_token)
    {
        const char *env_token = getenv("NP_CT_CERTSPOTTER_TOKEN");
        if (env_token && env_token[0])
        {
            cfg.ct_certspotter_token = strdup(env_token);
            if (!cfg.ct_certspotter_token)
                goto fail;
        }
    }

    ch = np_subenum_execute(&cfg);
    np_subenum_config_free(&cfg);
    return ch;

fail:
    np_subenum_config_free(&cfg);
    fprintf(stderr, "subenum: out of memory\n");
    return 1;
}
