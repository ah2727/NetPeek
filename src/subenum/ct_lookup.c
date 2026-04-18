#define _POSIX_C_SOURCE 200809L

#include "subenum/ct_lookup.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "npe_lib/npe_lib_http.h"

static int has_domain_suffix(const char *fqdn, const char *domain)
{
    if (!fqdn || !domain)
        return 0;

    size_t f_len = strlen(fqdn);
    size_t d_len = strlen(domain);
    if (d_len == 0 || f_len < d_len)
        return 0;

    const char *tail = fqdn + (f_len - d_len);
    if (strcasecmp(tail, domain) != 0)
        return 0;

    if (f_len == d_len)
        return 1;

    return tail[-1] == '.';
}

static void normalize_fqdn(char *s)
{
    if (!s)
        return;

    while (*s && isspace((unsigned char)*s))
        memmove(s, s + 1, strlen(s));

    while (s[0] == '*' && s[1] == '.')
        memmove(s, s + 2, strlen(s + 2) + 1);

    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '.' || isspace((unsigned char)s[len - 1])))
        s[--len] = '\0';

    for (size_t i = 0; s[i] != '\0'; i++)
        s[i] = (char)tolower((unsigned char)s[i]);
}

static const char *json_extract_string(const char *p,
                                       const char *end,
                                       char *out,
                                       size_t out_cap)
{
    if (!p || !end || !out || out_cap == 0 || p >= end || *p != '"')
        return NULL;

    p++;
    size_t wr = 0;

    while (p < end && *p)
    {
        char c = *p++;
        if (c == '"')
            break;

        if (c == '\\' && p < end)
        {
            char esc = *p++;
            switch (esc)
            {
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case '\\': c = '\\'; break;
            case '"': c = '"'; break;
            case '/': c = '/'; break;
            default: c = esc; break;
            }
        }

        if (wr + 1 < out_cap)
            out[wr++] = c;
    }

    out[wr] = '\0';
    return p;
}

static void submit_ct_name(np_dns_engine_t *engine,
                           const char *domain,
                           const char *candidate,
                           uint16_t depth)
{
    if (!engine || !domain || !candidate)
        return;

    char tmp[640];
    snprintf(tmp, sizeof(tmp), "%s", candidate);
    normalize_fqdn(tmp);

    if (tmp[0] == '\0')
        return;

    if (!has_domain_suffix(tmp, domain))
        return;

    (void)np_dns_engine_submit(engine, tmp, NP_DNS_REC_A, NP_SUBSRC_CT, depth);
}

static int http_fetch_body(const char *url,
                           const np_subenum_config_t *cfg,
                           npe_http_response_t *resp)
{
    if (!url || !resp)
        return -1;

    npe_http_request_opts_t opts;
    npe_http_opts_init(&opts);
    opts.timeout_ms = (cfg && cfg->timeout_ms > 0) ? (uint32_t)cfg->timeout_ms : 5000;
    opts.follow_redirects = true;
    opts.verify_ssl = true;
    if (cfg && cfg->http_proxy && cfg->http_proxy[0])
        opts.proxy = cfg->http_proxy;

    int rc = npe_http_get(url, &opts, resp);
    if (rc != 0 || resp->status_code < 200 || resp->status_code >= 300 || !resp->body)
        return -1;

    return 0;
}

static int parse_crtsh_body(const char *body,
                            const char *domain,
                            np_dns_engine_t *engine,
                            uint16_t depth)
{
    const char *p = body;
    const char *end = body + strlen(body);
    static const char *keys[] = {"\"name_value\":\"", "\"common_name\":\""};
    int submitted = 0;

    while (p < end)
    {
        const char *found = NULL;
        size_t key_len = 0;

        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        {
            const char *candidate = strstr(p, keys[i]);
            if (!candidate)
                continue;

            if (!found || candidate < found)
            {
                found = candidate;
                key_len = strlen(keys[i]);
            }
        }

        if (!found)
            break;

        const char *value_start = found + key_len - 1;
        char extracted[1024];
        const char *next = json_extract_string(value_start, end, extracted, sizeof(extracted));
        if (!next)
            break;

        char *save = NULL;
        char *line = strtok_r(extracted, "\n", &save);
        while (line)
        {
            submit_ct_name(engine, domain, line, depth);
            submitted++;
            line = strtok_r(NULL, "\n", &save);
        }

        p = next;
    }

    return submitted;
}

static int parse_certspotter_body(const char *body,
                                  const char *domain,
                                  np_dns_engine_t *engine,
                                  uint16_t depth)
{
    const char *p = body;
    const char *end = body + strlen(body);
    int submitted = 0;

    while (p < end)
    {
        const char *key = strstr(p, "\"dns_names\"");
        if (!key)
            break;

        const char *arr = strchr(key, '[');
        if (!arr)
            break;
        arr++;

        while (arr < end)
        {
            while (arr < end && isspace((unsigned char)*arr))
                arr++;

            if (arr >= end || *arr == ']')
            {
                if (arr < end)
                    arr++;
                break;
            }

            if (*arr != '"')
            {
                arr++;
                continue;
            }

            char name[1024];
            const char *next = json_extract_string(arr, end, name, sizeof(name));
            if (!next)
                break;

            submit_ct_name(engine, domain, name, depth);
            submitted++;
            arr = next;

            while (arr < end && isspace((unsigned char)*arr))
                arr++;
            if (arr < end && *arr == ',')
                arr++;
        }

        p = arr;
    }

    return submitted;
}

static int np_ct_lookup_crtsh(const char *domain,
                              const np_subenum_config_t *cfg,
                              np_dns_engine_t *engine,
                              uint16_t depth)
{
    char enc_domain[512];
    if (npe_http_url_encode(domain, enc_domain, sizeof(enc_domain)) < 0)
        return -1;

    char url[1024];
    snprintf(url, sizeof(url), "https://crt.sh/?q=%%25.%s&output=json", enc_domain);

    npe_http_response_t resp;
    npe_http_response_init(&resp);
    int rc = http_fetch_body(url, cfg, &resp);
    if (rc == 0)
        rc = parse_crtsh_body(resp.body, domain, engine, depth) >= 0 ? 0 : -1;

    npe_lib_http_response_free(&resp);
    return rc;
}

static int np_ct_lookup_certspotter(const char *domain,
                                    const np_subenum_config_t *cfg,
                                    np_dns_engine_t *engine,
                                    uint16_t depth)
{
    char enc_domain[512];
    if (npe_http_url_encode(domain, enc_domain, sizeof(enc_domain)) < 0)
        return -1;

    char url[1200];
    snprintf(url,
             sizeof(url),
             "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names",
             enc_domain);

    npe_http_request_opts_t opts;
    npe_http_opts_init(&opts);
    opts.timeout_ms = (cfg && cfg->timeout_ms > 0) ? (uint32_t)cfg->timeout_ms : 5000;
    opts.follow_redirects = true;
    opts.verify_ssl = true;
    if (cfg && cfg->http_proxy && cfg->http_proxy[0])
        opts.proxy = cfg->http_proxy;

    npe_http_header_t auth_hdr;
    memset(&auth_hdr, 0, sizeof(auth_hdr));
    if (cfg && cfg->ct_certspotter_token && cfg->ct_certspotter_token[0])
    {
        snprintf(auth_hdr.name, sizeof(auth_hdr.name), "%s", "Authorization");
        snprintf(auth_hdr.value, sizeof(auth_hdr.value), "Bearer %s", cfg->ct_certspotter_token);
        opts.custom_headers = &auth_hdr;
        opts.custom_header_count = 1;
    }

    npe_http_response_t resp;
    npe_http_response_init(&resp);
    int rc = npe_http_get(url, &opts, &resp);
    if (rc != 0 || resp.status_code < 200 || resp.status_code >= 300 || !resp.body)
    {
        npe_lib_http_response_free(&resp);
        return -1;
    }

    rc = parse_certspotter_body(resp.body, domain, engine, depth) >= 0 ? 0 : -1;
    npe_lib_http_response_free(&resp);
    return rc;
}

int np_ct_lookup(const char *domain,
                 const np_subenum_config_t *cfg,
                 np_dns_engine_t *engine,
                 uint16_t depth)
{
    return np_ct_lookup_multi(domain, cfg, engine, depth);
}

int np_ct_lookup_multi(const char *domain,
                       const np_subenum_config_t *cfg,
                       np_dns_engine_t *engine,
                       uint16_t depth)
{
    if (!domain || !engine)
        return -1;

    uint32_t providers = NP_CTPROV_CRTSH | NP_CTPROV_CERTSPOTTER;
    if (cfg && cfg->ct_providers != 0)
        providers = cfg->ct_providers;

    int ok = 0;
    if ((providers & NP_CTPROV_CRTSH) != 0)
    {
        if (np_ct_lookup_crtsh(domain, cfg, engine, depth) == 0)
            ok++;
    }

    if ((providers & NP_CTPROV_CERTSPOTTER) != 0)
    {
        if (np_ct_lookup_certspotter(domain, cfg, engine, depth) == 0)
            ok++;
    }

    return ok > 0 ? 0 : -1;
}
