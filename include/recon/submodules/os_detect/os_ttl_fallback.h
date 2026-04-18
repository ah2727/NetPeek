/* os_ttl_fallback.h */
#ifndef NP_OS_TTL_FALLBACK_H
#define NP_OS_TTL_FALLBACK_H

#include <stdint.h>

int         np_get_ttl_via_tcp(const char *target_ip, uint16_t port, int timeout_ms);
const char *np_os_family_from_ttl(int observed_ttl);
int         np_initial_ttl_from_observed(int observed_ttl);

#endif /* NP_OS_TTL_FALLBACK_H */
