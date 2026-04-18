#ifndef OS_TCP_PROBES_H
#define OS_TCP_PROBES_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

#define NP_MAX_TCP_PROBES 9
#define NP_PCAP_TIMEOUT_MS 800
#define NP_PCAP_SNAPLEN 65535

typedef enum
{
    NP_PROBE_T1  = 0,
    NP_PROBE_T2  = 1,
    NP_PROBE_T3  = 2,
    NP_PROBE_T4  = 3,
    NP_PROBE_T5  = 4,
    NP_PROBE_T6  = 5,
    NP_PROBE_T7  = 6,
    NP_PROBE_ECN = 7,
    NP_PROBE_IE  = 8
} np_tcp_probe_type_t;

typedef struct
{
    struct sockaddr_in target;
    uint16_t open_port;
    uint16_t closed_port;
    int timeout_ms;
} np_tcp_probe_cfg_t;

typedef struct
{
    np_tcp_probe_type_t type;

    bool responded;
    uint8_t ttl;
    uint16_t window;
    uint16_t ip_id;
    bool df;

    bool syn;
    bool ack;
    bool rst;
    uint8_t tcp_flags;
    uint32_t seq;
    uint32_t ack_seq;

    uint16_t mss;
    uint8_t wscale;
    bool sack;
    bool timestamp;
    uint32_t tsval;
    uint32_t tsecr;

    uint8_t opts_raw[64];
    uint8_t opts_len;

    bool ecn_supported;
    uint8_t ecn_flags;

    
} np_tcp_probe_result_t;

typedef struct
{
    np_tcp_probe_result_t probes[NP_MAX_TCP_PROBES];
} np_tcp_probe_set_t;

struct tcp_probe_reply {
    uint8_t received;
    uint8_t ttl;
    uint16_t win;
    uint8_t flags;
    uint16_t ipid;
    uint32_t seq;
    uint32_t ack;
    uint8_t options_len;
    uint8_t options[64];
};

int np_send_tcp_probe(
    const np_tcp_probe_cfg_t *cfg,
    np_tcp_probe_type_t type,
    np_tcp_probe_result_t *out);

int np_run_tcp_probes(
    const np_tcp_probe_cfg_t *cfg,
    np_tcp_probe_set_t *results);

void np_tcp_probe_print(
    const np_tcp_probe_set_t *set);

int os_tcp_send_probe(int sock,
                      const char *ifname,
                      const char *src_ip,
                      const char *dst_ip,
                      uint16_t sport,
                      uint16_t dport,
                      int syn_flag);

int os_tcp_run_probe(const char *ifname,
                     const char *src_ip,
                     const char *dst_ip,
                     uint16_t sport,
                     uint16_t dport,
                     int syn_flag,
                     struct tcp_probe_reply *out);

#endif
