#ifndef NP_TCP_FP_H
#define NP_TCP_FP_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "os_tcp_probes.h"

typedef enum
{
    NP_SEQ_CLASS_UNKNOWN = 0,
    NP_SEQ_CLASS_CONSTANT,
    NP_SEQ_CLASS_INCREMENTAL,
    NP_SEQ_CLASS_BROKEN_LITTLE_ENDIAN,
    NP_SEQ_CLASS_RANDOMIZED
} np_seq_class_t;

typedef struct
{
    uint32_t gcd;
    uint32_t isr;
    uint32_t sp;
    np_seq_class_t cls;
    uint8_t samples;
} np_seq_metrics_t;

typedef struct
{
    bool responded;
    uint8_t type;
    uint8_t code;
    uint8_t ttl;
} np_icmp_reply_t;

typedef struct
{
    struct sockaddr_in target;
    uint16_t open_port;
    uint16_t closed_port;
    int timeout_ms;
} np_tcp_fp_cfg_t;

typedef struct
{
    np_tcp_probe_set_t tcp;
    np_seq_metrics_t seq;

    np_icmp_reply_t u1;
    np_icmp_reply_t ie1;
    np_icmp_reply_t ie2;

    uint8_t ttl_observed;
    uint8_t ttl_initial;
    bool df;
    uint16_t window;
    uint16_t mss;
    uint8_t wscale;
    bool sack;
    bool ts;
    uint8_t options_order[64];
    uint8_t options_len;

    uint8_t ipid_behavior; /* 0 unknown, 1 sequential, 2 zero, 3 random */
    uint8_t response_count;
} np_tcp_fp_vector_t;

uint8_t np_tcp_fp_infer_initial_ttl(uint8_t observed_ttl);

int np_tcp_fp_run(const np_tcp_fp_cfg_t *cfg, np_tcp_fp_vector_t *out);

#endif
