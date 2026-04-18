#ifndef NP_EVASION_FRAGMENT_H
#define NP_EVASION_FRAGMENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "evasion.h"

#define NP_MAX_FRAGMENTS 64

typedef struct {
    uint16_t payload_offset;
    uint16_t payload_len;
    bool mf;
} np_fragment_desc_t;

bool np_fragment_plan_ipv4(uint16_t ip_header_len,
                           uint16_t total_payload_len,
                           uint16_t mtu,
                           np_fragment_desc_t *out,
                           size_t *out_count,
                           size_t out_cap);

void np_fragment_shuffle(np_fragment_desc_t *frags, size_t count);

#endif
