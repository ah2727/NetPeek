#ifndef NP_EVASION_SPOOF_H
#define NP_EVASION_SPOOF_H

#include <stdbool.h>
#include <stdint.h>

#include "evasion.h"

uint16_t np_spoof_pick_source_port(const np_evasion_t *ev, uint16_t fallback);
uint8_t np_spoof_pick_ttl(const np_evasion_t *ev, uint8_t fallback);
bool np_spoof_parse_mac(np_evasion_t *ev, const char *arg);
bool np_spoof_resolve_mac(const np_evasion_t *ev, uint8_t out[6]);

#endif
