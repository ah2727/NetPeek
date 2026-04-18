#ifndef NP_EVASION_DECOY_H
#define NP_EVASION_DECOY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "evasion.h"

bool np_decoy_parse_spec(np_evasion_t *ev, const char *spec);
bool np_decoy_is_reserved_ipv4(uint32_t addr_be);
size_t np_decoy_build_send_list(const np_evasion_t *ev,
                                uint32_t real_src_be,
                                uint32_t *out,
                                size_t cap);

#endif
