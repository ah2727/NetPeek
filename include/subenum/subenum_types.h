#ifndef NP_SUBENUM_TYPES_H
#define NP_SUBENUM_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

typedef enum
{
    NP_SUBSRC_BRUTE     = (1u << 0),
    NP_SUBSRC_AXFR      = (1u << 1),
    NP_SUBSRC_CT        = (1u << 2),
    NP_SUBSRC_REVERSE   = (1u << 3),
    NP_SUBSRC_PERMUTE   = (1u << 4),
    NP_SUBSRC_RECURSIVE = (1u << 5)
} np_subenum_source_t;

typedef enum
{
    NP_CTPROV_CRTSH = (1u << 0),
    NP_CTPROV_CERTSPOTTER = (1u << 1)
} np_ct_provider_t;

typedef enum
{
    NP_DNS_REC_A = 1,
    NP_DNS_REC_NS = 2,
    NP_DNS_REC_CNAME = 5,
    NP_DNS_REC_SOA = 6,
    NP_DNS_REC_PTR = 12,
    NP_DNS_REC_MX = 15,
    NP_DNS_REC_TXT = 16,
    NP_DNS_REC_AAAA = 28,
    NP_DNS_REC_SRV = 33,
    NP_DNS_REC_AXFR = 252
} np_dns_record_type_t;

typedef struct
{
    int family;
    union
    {
        struct in_addr v4;
        struct in6_addr v6;
    } addr;
    char addr_str[INET6_ADDRSTRLEN];
} np_resolved_addr_t;

typedef struct np_subdomain_entry
{
    char fqdn[512];
    np_resolved_addr_t *addrs;
    size_t addr_count;
    char cname[512];
    uint32_t sources;
    uint16_t depth;
    double rtt_ms;
    struct np_subdomain_entry *next;
} np_subdomain_entry_t;

typedef struct
{
    char **domains;
    size_t domain_count;

    uint32_t techniques;
    bool recursive;
    int max_depth;

    char **resolvers;
    size_t resolver_count;
    bool use_system_dns;
    int timeout_ms;
    char *http_proxy;

    uint32_t ct_providers;
    char *ct_certspotter_token;

    int thread_count;

    char *wordlist_path;
    bool use_builtin_wordlist;

    bool wildcard_detect;

    bool resolve_all;
    bool filter_alive;
    bool output_json;
    bool output_csv;
    bool output_grep;
    char *output_file;
    bool verbose;
} np_subenum_config_t;

typedef struct
{
    bool detected;
    np_resolved_addr_t addrs[16];
    size_t addr_count;
    char cname[512];
    bool cname_wildcard;
} np_wildcard_info_t;

#endif
