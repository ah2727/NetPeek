#define _POSIX_C_SOURCE 200809L

#include "recon/submodules/scanner/dns_enum.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    char host[256];
    char a[INET_ADDRSTRLEN];
    char aaaa[INET6_ADDRSTRLEN];
} np_dns_result_t;

static void copy_capped(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0)
        return;
    if (!src)
    {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

static void resolve_host(const char *host, np_dns_result_t *out)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(host, NULL, &hints, &res) != 0)
        return;

    for (struct addrinfo *p = res; p; p = p->ai_next)
    {
        if (p->ai_family == AF_INET && out->a[0] == '\0')
        {
            struct sockaddr_in *s4 = (struct sockaddr_in *)p->ai_addr;
            (void)inet_ntop(AF_INET, &s4->sin_addr, out->a, sizeof(out->a));
        }
        else if (p->ai_family == AF_INET6 && out->aaaa[0] == '\0')
        {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)p->ai_addr;
            (void)inet_ntop(AF_INET6, &s6->sin6_addr, out->aaaa, sizeof(out->aaaa));
        }
    }

    freeaddrinfo(res);
}

int np_dns_enum_run(const char *domain, const np_dns_enum_opts_t *opts)
{
    if (!domain || !*domain)
        return 1;

    np_dns_result_t *rows = NULL;
    size_t rows_count = 0;
    size_t rows_cap = 0;

    np_dns_result_t base;
    memset(&base, 0, sizeof(base));
    copy_capped(base.host, sizeof(base.host), domain);
    resolve_host(domain, &base);

    rows_cap = 128;
    rows = calloc(rows_cap, sizeof(*rows));
    if (!rows)
        return 1;
    rows[rows_count++] = base;

    if (opts && opts->subdomains)
    {
        const char *wl = (opts->wordlist && opts->wordlist[0])
                             ? opts->wordlist
                             : "data/subdomains-top1k.txt";

        FILE *fp = fopen(wl, "r");
        if (fp)
        {
            char line[256];
            while (fgets(line, sizeof(line), fp))
            {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                if (line[0] == '\0' || line[0] == '#')
                    continue;

                char fqdn[512];
                snprintf(fqdn, sizeof(fqdn), "%s.%s", line, domain);

                np_dns_result_t row;
                memset(&row, 0, sizeof(row));
                copy_capped(row.host, sizeof(row.host), fqdn);
                resolve_host(fqdn, &row);

                if (row.a[0] == '\0' && row.aaaa[0] == '\0')
                    continue;

                if (rows_count >= rows_cap)
                {
                    rows_cap *= 2;
                    np_dns_result_t *tmp = realloc(rows, rows_cap * sizeof(*rows));
                    if (!tmp)
                        break;
                    rows = tmp;
                }

                rows[rows_count++] = row;
            }
            fclose(fp);
        }
    }

    if (opts && opts->json)
    {
        printf("{\n  \"domain\": \"%s\",\n  \"records\": [\n", domain);
        for (size_t i = 0; i < rows_count; i++)
        {
            printf("    {\"host\":\"%s\",\"A\":\"%s\",\"AAAA\":\"%s\"}%s\n",
                   rows[i].host,
                   rows[i].a,
                   rows[i].aaaa,
                   (i + 1 < rows_count) ? "," : "");
        }
        printf("  ]\n}\n");
    }
    else
    {
        printf("DNS enumeration for %s\n", domain);
        for (size_t i = 0; i < rows_count; i++)
        {
            printf("%-40s A=%-16s AAAA=%s\n",
                   rows[i].host,
                   rows[i].a[0] ? rows[i].a : "-",
                   rows[i].aaaa[0] ? rows[i].aaaa : "-");
        }
    }

    free(rows);
    return 0;
}
