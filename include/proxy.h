#ifndef NP_PROXY_H
#define NP_PROXY_H

#include "netpeek.h"

np_status_t np_proxy_parse(const char *url, np_proxy_t *proxy);

int np_proxy_connect(const np_proxy_t *proxy,
                     const char *target_host,
                     uint16_t target_port,
                     uint32_t timeout_ms);

#endif /* NP_PROXY_H */
