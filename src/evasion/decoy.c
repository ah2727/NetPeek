#include "evasion/decoy.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static bool parse_me_token(const char *token)
{
    if (!token)
        return false;
    return strcasecmp(token, "ME") == 0;
}

bool np_decoy_is_reserved_ipv4(uint32_t addr_be)
{
    uint32_t ip = ntohl(addr_be);
    uint8_t a = (uint8_t)(ip >> 24);
    uint8_t b = (uint8_t)((ip >> 16) & 0xff);

    if (a == 0 || a == 10 || a == 127)
        return true;
    if (a == 100 && (b >= 64 && b <= 127))
        return true;
    if (a == 169 && b == 254)
        return true;
    if (a == 172 && (b >= 16 && b <= 31))
        return true;
    if (a == 192 && b == 168)
        return true;
    if (a == 192 && b == 0)
        return true;
    if (a == 198 && (b == 18 || b == 19))
        return true;
    if (a == 198 && b == 51)
        return true;
    if (a == 203 && b == 0)
        return true;
    if (a >= 224)
        return true;

    return false;
}

static bool random_public_ipv4(uint32_t *out)
{
    if (!out)
        return false;

    for (int tries = 0; tries < 2048; tries++)
    {
        uint32_t cand = ((uint32_t)(rand() & 0xff) << 24) |
                        ((uint32_t)(rand() & 0xff) << 16) |
                        ((uint32_t)(rand() & 0xff) << 8) |
                        ((uint32_t)(rand() & 0xff));
        if ((cand >> 24) == 0)
            continue;

        uint32_t be = htonl(cand);
        if (np_decoy_is_reserved_ipv4(be))
            continue;

        *out = be;
        return true;
    }

    return false;
}

bool np_decoy_parse_spec(np_evasion_t *ev, const char *spec)
{
    if (!ev || !spec || spec[0] == '\0')
        return false;

    ev->decoy_count = 0;
    ev->decoy_has_me = false;
    ev->decoy_me_index = -1;
    memset(ev->decoy_ipv4, 0, sizeof(ev->decoy_ipv4));
    memset(ev->decoy_ips, 0, sizeof(ev->decoy_ips));

    if (strncasecmp(spec, "RND:", 4) == 0)
    {
        char *endptr = NULL;
        long requested = strtol(spec + 4, &endptr, 10);
        if (!endptr || *endptr != '\0' || requested <= 0 || requested > NP_MAX_DECOYS)
            return false;

        for (long i = 0; i < requested; i++)
        {
            uint32_t addr = 0;
            if (!random_public_ipv4(&addr))
                return false;
            ev->decoy_ipv4[ev->decoy_count] = addr;
            struct in_addr tmp = {.s_addr = addr};
            if (!inet_ntop(AF_INET, &tmp, ev->decoy_ips[ev->decoy_count], INET_ADDRSTRLEN))
                return false;
            ev->decoy_count++;
        }
        return true;
    }

    char tmp[2048];
    strncpy(tmp, spec, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    int token_index = 0;
    for (char *tok = strtok(tmp, ","); tok; tok = strtok(NULL, ","), token_index++)
    {
        while (isspace((unsigned char)*tok))
            tok++;
        if (*tok == '\0')
            continue;

        if (parse_me_token(tok))
        {
            ev->decoy_has_me = true;
            ev->decoy_me_index = (int8_t)token_index;
            continue;
        }

        if (ev->decoy_count >= NP_MAX_DECOYS)
            return false;

        struct in_addr addr;
        if (inet_pton(AF_INET, tok, &addr) != 1)
            return false;
        if (np_decoy_is_reserved_ipv4(addr.s_addr))
            return false;

        ev->decoy_ipv4[ev->decoy_count] = addr.s_addr;
        strncpy(ev->decoy_ips[ev->decoy_count], tok, INET_ADDRSTRLEN - 1);
        ev->decoy_ips[ev->decoy_count][INET_ADDRSTRLEN - 1] = '\0';
        ev->decoy_count++;
    }

    return ev->decoy_count > 0 || ev->decoy_has_me;
}

size_t np_decoy_build_send_list(const np_evasion_t *ev,
                                uint32_t real_src_be,
                                uint32_t *out,
                                size_t cap)
{
    if (!out || cap == 0)
        return 0;

    if (!ev || ev->decoy_count == 0)
    {
        out[0] = real_src_be;
        return 1;
    }

    size_t total = (size_t)ev->decoy_count + 1;
    if (total > cap)
        total = cap;

    int me_pos = 0;
    if (ev->decoy_has_me && ev->decoy_me_index >= 0 && ev->decoy_me_index < (int8_t)total)
        me_pos = ev->decoy_me_index;
    else
        me_pos = rand() % (int)total;

    size_t di = 0;
    for (size_t i = 0; i < total; i++)
    {
        if ((int)i == me_pos)
        {
            out[i] = real_src_be;
            continue;
        }

        if (di < ev->decoy_count)
            out[i] = ev->decoy_ipv4[di++];
        else
            out[i] = real_src_be;
    }

    return total;
}
