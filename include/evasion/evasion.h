#ifndef NP_EVASION_H
#define NP_EVASION_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#define NP_MAX_DECOYS 64

typedef enum {
    NP_FRAG_ORDER_INORDER = 0,
    NP_FRAG_ORDER_RANDOM
} np_frag_order_t;

typedef enum {
    NP_SPOOF_MAC_NONE = 0,
    NP_SPOOF_MAC_RANDOM,
    NP_SPOOF_MAC_EXPLICIT,
    NP_SPOOF_MAC_VENDOR
} np_spoof_mac_mode_t;

typedef struct {
    bool fragment_packets;
    uint16_t fragment_mtu;
    np_frag_order_t fragment_order;

    bool randomize_data;
    uint32_t packet_delay_us;

    uint8_t ttl_value;
    bool ttl_set;

    bool bad_checksum;

    char spoof_source[INET_ADDRSTRLEN];
    char decoy_ips[NP_MAX_DECOYS][INET_ADDRSTRLEN];
    uint8_t decoy_count;
    bool decoy_has_me;
    int8_t decoy_me_index;
    uint32_t decoy_ipv4[NP_MAX_DECOYS];

    bool source_port_set;
    uint16_t source_port;

    np_spoof_mac_mode_t spoof_mac_mode;
    bool spoof_mac_set;
    uint8_t spoof_mac[6];
    uint8_t spoof_mac_vendor[3];

    uint32_t scan_jitter_us;
    bool defeat_rst_ratelimit;

    bool randomize_hosts;

    uint16_t data_length;
} np_evasion_t;

void np_evasion_init(np_evasion_t *ev);
void np_evasion_apply_delay(const np_evasion_t *ev);
uint8_t np_evasion_get_ttl(const np_evasion_t *ev, uint8_t default_ttl);
void np_evasion_randomize_payload(uint8_t *buf, size_t len);

#endif
