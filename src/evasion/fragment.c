#include "evasion/fragment.h"

#include <stdlib.h>

bool np_fragment_plan_ipv4(uint16_t ip_header_len,
                           uint16_t total_payload_len,
                           uint16_t mtu,
                           np_fragment_desc_t *out,
                           size_t *out_count,
                           size_t out_cap)
{
    if (!out || !out_count || out_cap == 0)
        return false;
    if (ip_header_len < 20 || (ip_header_len % 4) != 0)
        return false;
    if (total_payload_len == 0)
        return false;
    if (mtu <= ip_header_len)
        return false;

    uint16_t max_payload = (uint16_t)(mtu - ip_header_len);
    if (max_payload < 8)
        return false;

    size_t count = 0;
    uint16_t offset = 0;

    while (offset < total_payload_len)
    {
        if (count >= out_cap)
            return false;

        uint16_t remaining = (uint16_t)(total_payload_len - offset);
        bool last = (remaining <= max_payload);
        uint16_t payload_len = last ? remaining : max_payload;

        if (!last)
        {
            payload_len = (uint16_t)(payload_len & ~0x7u);
            if (payload_len == 0)
                return false;
        }

        if (offset == 0 && payload_len < 8)
            return false;

        out[count].payload_offset = offset;
        out[count].payload_len = payload_len;
        out[count].mf = !last;

        offset = (uint16_t)(offset + payload_len);
        count++;
    }

    *out_count = count;
    return true;
}

void np_fragment_shuffle(np_fragment_desc_t *frags, size_t count)
{
    if (!frags || count < 2)
        return;

    for (size_t i = count - 1; i > 0; i--)
    {
        size_t j = (size_t)(rand() % (int)(i + 1));
        np_fragment_desc_t tmp = frags[i];
        frags[i] = frags[j];
        frags[j] = tmp;
    }
}

