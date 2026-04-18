/*****************************************************************************
 * npe_lib_packet.h — Packet crafting and parsing utilities
 *****************************************************************************/

#ifndef NPE_LIB_PACKET_H
#define NPE_LIB_PACKET_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct npe_vm npe_vm_t;
typedef struct npe_context npe_context_t;
typedef struct npe_packet npe_packet_t;

/* =======================
 * Packet-layer protocol types
 * (DO NOT collide with npe_protocol_t)
 * ======================= */
typedef enum npe_packet_proto {

    NPE_PKT_PROTO_ETHERNET = 1,
    NPE_PKT_PROTO_IPV4     = 2,
    NPE_PKT_PROTO_IPV6     = 3,
    NPE_PKT_PROTO_TCP      = 4,
    NPE_PKT_PROTO_UDP      = 5,
    NPE_PKT_PROTO_ICMP     = 6,
    NPE_PKT_PROTO_RAW      = 7

} npe_packet_proto_t;

/* =======================
 * TCP flags
 * ======================= */
typedef enum npe_tcp_flag {

    NPE_TCP_FIN = 0x01,
    NPE_TCP_SYN = 0x02,
    NPE_TCP_RST = 0x04,
    NPE_TCP_PSH = 0x08,
    NPE_TCP_ACK = 0x10,
    NPE_TCP_URG = 0x20,
    NPE_TCP_ECE = 0x40,
    NPE_TCP_CWR = 0x80

} npe_tcp_flag_t;

/* =======================
 * Lifecycle
 * ======================= */
npe_error_t npe_packet_create(npe_packet_t **pkt);
void        npe_packet_destroy(npe_packet_t *pkt);

/* =======================
 * Header construction
 * ======================= */
npe_error_t npe_packet_set_ipv4(
    npe_packet_t *pkt,
    const char *src_ip,
    const char *dst_ip,
    uint8_t ttl);

npe_error_t npe_packet_set_tcp(
    npe_packet_t *pkt,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t flags,
    uint32_t seq,
    uint32_t ack);

npe_error_t npe_packet_set_udp(
    npe_packet_t *pkt,
    uint16_t src_port,
    uint16_t dst_port);

npe_error_t npe_packet_set_icmp_echo(
    npe_packet_t *pkt,
    uint16_t id,
    uint16_t seq);

/* =======================
 * Payload
 * ======================= */
npe_error_t npe_packet_set_payload(
    npe_packet_t *pkt,
    const void *data,
    size_t length);

/* =======================
 * Serialization
 * ======================= */
npe_error_t npe_packet_build(
    npe_packet_t *pkt,
    uint8_t **buffer,
    size_t *length);

/* =======================
 * Sending
 * ======================= */
npe_error_t npe_packet_send(
    npe_context_t *ctx,
    const uint8_t *packet,
    size_t length);

/* =======================
 * Parsing
 * ======================= */
typedef struct npe_packet_info {

    char     src_ip[64];
    char     dst_ip[64];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  ttl;
    size_t   payload_len;

} npe_packet_info_t;

npe_error_t npe_packet_parse(
    const uint8_t *data,
    size_t length,
    npe_packet_info_t *info);

/* =======================
 * Capture
 * ======================= */
typedef struct npe_packet_capture npe_packet_capture_t;

npe_error_t npe_packet_capture_open(
    const char *interface,
    npe_packet_capture_t **cap);

npe_error_t npe_packet_capture_next(
    npe_packet_capture_t *cap,
    uint8_t **packet,
    size_t *length,
    uint64_t *timestamp);

void npe_packet_capture_close(
    npe_packet_capture_t *cap);

/* =======================
 * Lua binding
 * ======================= */
npe_error_t npe_packet_register(npe_vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_PACKET_H */