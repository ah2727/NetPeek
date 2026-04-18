#ifndef NP_CORE_CHECKSUM_H
#define NP_CORE_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

uint16_t np_checksum16(const void *data, size_t len);

#endif
