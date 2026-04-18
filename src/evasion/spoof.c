#include "evasion/spoof.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

uint16_t np_spoof_pick_source_port(const np_evasion_t *ev, uint16_t fallback)
{
    if (!ev)
        return fallback;
    if (ev->source_port_set)
        return ev->source_port;
    return fallback;
}

uint8_t np_spoof_pick_ttl(const np_evasion_t *ev, uint8_t fallback)
{
    if (!ev)
        return fallback;
    return ev->ttl_set ? ev->ttl_value : fallback;
}

static int parse_hex_byte(const char *s)
{
    if (!s || !isxdigit((unsigned char)s[0]) || !isxdigit((unsigned char)s[1]))
        return -1;

    char tmp[3] = {s[0], s[1], '\0'};
    return (int)strtol(tmp, NULL, 16);
}

bool np_spoof_parse_mac(np_evasion_t *ev, const char *arg)
{
    if (!ev || !arg || arg[0] == '\0')
        return false;

    if (strcmp(arg, "0") == 0)
    {
        ev->spoof_mac_mode = NP_SPOOF_MAC_RANDOM;
        ev->spoof_mac_set = true;
        return true;
    }

    uint8_t bytes[6] = {0};
    int count = 0;
    const char *cursor = arg;

    while (*cursor && count < 6)
    {
        int v = parse_hex_byte(cursor);
        if (v < 0)
            break;

        bytes[count++] = (uint8_t)v;
        cursor += 2;
        if (*cursor == ':' || *cursor == '-')
            cursor++;
        else if (*cursor != '\0')
            return false;
    }

    if (*cursor != '\0')
        return false;

    if (count == 6)
    {
        memcpy(ev->spoof_mac, bytes, sizeof(bytes));
        ev->spoof_mac_mode = NP_SPOOF_MAC_EXPLICIT;
        ev->spoof_mac_set = true;
        return true;
    }

    if (count == 3)
    {
        memcpy(ev->spoof_mac_vendor, bytes, 3);
        ev->spoof_mac_mode = NP_SPOOF_MAC_VENDOR;
        ev->spoof_mac_set = true;
        return true;
    }

    return false;
}

bool np_spoof_resolve_mac(const np_evasion_t *ev, uint8_t out[6])
{
    if (!ev || !out)
        return false;

    switch (ev->spoof_mac_mode)
    {
    case NP_SPOOF_MAC_EXPLICIT:
        memcpy(out, ev->spoof_mac, 6);
        return true;
    case NP_SPOOF_MAC_VENDOR:
        out[0] = ev->spoof_mac_vendor[0];
        out[1] = ev->spoof_mac_vendor[1];
        out[2] = ev->spoof_mac_vendor[2];
        out[3] = (uint8_t)(rand() & 0xff);
        out[4] = (uint8_t)(rand() & 0xff);
        out[5] = (uint8_t)(rand() & 0xff);
        return true;
    case NP_SPOOF_MAC_RANDOM:
        for (int i = 0; i < 6; i++)
            out[i] = (uint8_t)(rand() & 0xff);
        out[0] &= 0xFEu;
        out[0] |= 0x02u;
        return true;
    default:
        return false;
    }
}

