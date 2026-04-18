#include "evasion.h"
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

void np_evasion_init(np_evasion_t *ev)
{
    memset(ev, 0, sizeof(*ev));
    ev->fragment_mtu = 0;
    ev->fragment_order = NP_FRAG_ORDER_INORDER;
    ev->ttl_value = 0;
    ev->ttl_set = false;
    ev->decoy_me_index = -1;
    ev->spoof_mac_mode = NP_SPOOF_MAC_NONE;
}

void np_evasion_apply_delay(const np_evasion_t *ev)
{
    if (ev->packet_delay_us > 0) {
        usleep(ev->packet_delay_us);
    }
}

uint8_t np_evasion_get_ttl(const np_evasion_t *ev, uint8_t default_ttl)
{
    if (!ev)
        return default_ttl;
    return ev->ttl_set ? ev->ttl_value : default_ttl;
}

void np_evasion_randomize_payload(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() & 0xFF;
    }
}
