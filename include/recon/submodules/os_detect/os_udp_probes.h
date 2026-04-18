#ifndef OS_UDP_PROBES_H
#define OS_UDP_PROBES_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/* Pipeline context (pcap / raw socket wrapper) */
typedef struct
{
    int icmp_sock;
    int timeout_ms;
} np_pipeline_ctx_t;

/* Target definition */
typedef struct
{
    struct sockaddr_in addr;
    uint16_t closed_port;
} np_target_t;

/* ✅ U1 probe result */
typedef struct
{
    bool responded;
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint8_t ttl;
} np_udp_probe_result_t;

/* API */
void np_send_udp_u1(
    np_pipeline_ctx_t *ctx,
    const np_target_t *tgt,
    np_udp_probe_result_t *out);

#endif
