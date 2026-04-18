#ifndef NP_PACKET_IP6_H
#define NP_PACKET_IP6_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>

uint16_t np_tcp6_checksum(const struct in6_addr *src,
                         const struct in6_addr *dst,
                         const void *tcp_seg,
                         size_t tcp_len);

uint16_t np_udp6_checksum(const struct in6_addr *src,
                         const struct in6_addr *dst,
                         const void *udp_seg,
                         size_t udp_len);

bool np_build_ipv6_tcp_packet(uint8_t *buf,
                              size_t buf_len,
                              const struct in6_addr *src,
                              const struct in6_addr *dst,
                              uint16_t src_port,
                              uint16_t dst_port,
                              uint8_t flags,
                              uint32_t seq,
                              uint16_t win,
                              uint8_t hop_limit,
                              uint32_t flow_label,
                              size_t *out_len);

#endif
