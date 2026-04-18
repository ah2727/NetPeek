#define _POSIX_C_SOURCE 200809L

#include "subenum/wildcard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void random_label(char *out, size_t cap)
{
    static const char *hex = "0123456789abcdef";
    size_t i;
    if (cap < 17)
        return;
    for (i = 0; i < 16; i++)
        out[i] = hex[rand() % 16];
    out[16] = '\0';
}

int np_wildcard_detect(np_dns_engine_t *engine,
                       const char *domain,
                       np_wildcard_info_t *info)
{
    int samples = 5;
    int hits = 0;
    int i;
    np_resolved_addr_t first[16];
    size_t first_count = 0;
    double rtt;

    if (!engine || !domain || !info)
        return -1;

    memset(info, 0, sizeof(*info));
    srand((unsigned int)time(NULL));

    for (i = 0; i < samples; i++)
    {
        char label[32];
        char fqdn[600];
        np_resolved_addr_t addrs[16];
        size_t count = 0;

        random_label(label, sizeof(label));
        snprintf(fqdn, sizeof(fqdn), "%s.%s", label, domain);

        if (np_dns_engine_resolve_name(engine, fqdn, addrs, 16, &count, &rtt) == 0 && count > 0)
        {
            if (first_count == 0)
            {
                memcpy(first, addrs, count * sizeof(*addrs));
                first_count = count;
                hits++;
            }
            else if (count == first_count)
            {
                size_t j;
                int equal = 1;
                for (j = 0; j < count; j++)
                {
                    if (strcmp(first[j].addr_str, addrs[j].addr_str) != 0)
                    {
                        equal = 0;
                        break;
                    }
                }
                if (equal)
                    hits++;
            }
        }
    }

    if (hits >= samples - 1 && first_count > 0)
    {
        size_t n = first_count > 16 ? 16 : first_count;
        info->detected = true;
        memcpy(info->addrs, first, n * sizeof(*first));
        info->addr_count = n;
    }

    return 0;
}

bool np_wildcard_is_false_positive(const np_wildcard_info_t *info,
                                   const np_subdomain_entry_t *entry)
{
    size_t i;
    size_t j;
    if (!info || !entry || !info->detected)
        return false;
    if (entry->addr_count == 0)
        return false;

    for (i = 0; i < entry->addr_count; i++)
    {
        int found = 0;
        for (j = 0; j < info->addr_count; j++)
        {
            if (strcmp(entry->addrs[i].addr_str, info->addrs[j].addr_str) == 0)
            {
                found = 1;
                break;
            }
        }
        if (!found)
            return false;
    }

    return true;
}
