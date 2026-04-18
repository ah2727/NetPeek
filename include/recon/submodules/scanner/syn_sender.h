#pragma once
#include <stdint.h>
#include "netpeek.h"

void np_syn_send(np_config_t *cfg,
                 const char *dst_ip,
                 uint16_t dst_port,
                 uint16_t src_port);
