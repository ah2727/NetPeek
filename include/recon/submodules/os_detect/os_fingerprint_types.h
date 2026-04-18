#ifndef NP_OS_FINGERPRINT_TYPES_H
#define NP_OS_FINGERPRINT_TYPES_H

#include <stdint.h>
#include <stdbool.h>

/*
 * Maximum TCP options stored from SYN‑ACK.
 * Typical SYN‑ACK contains: MSS, SACK, TS, NOP, WSCALE etc.
 */
#define NP_TCP_OPT_MAX 16
/* ================================================================
 *  Environmental Flags (Network Path Effects)
 * ================================================================ */
#define NP_ENV_PROXY      0x01
#define NP_ENV_NAT        0x02
#define NP_ENV_FIREWALL   0x04
#define NP_ENV_IDS        0x08
#define NP_ENV_LOADBAL    0x10

/*
 * TCP option identifiers (RFC values)
 */
typedef enum
{
    NP_TCP_OPT_EOL = 0,
    NP_TCP_OPT_NOP = 1,
    NP_TCP_OPT_MSS = 2,
    NP_TCP_OPT_WS  = 3,
    NP_TCP_OPT_SACK = 4,
    NP_TCP_OPT_TS  = 8
} np_tcp_option_kind_t;

/*
 * Observed TCP/IP fingerprint extracted from probes.
 */
typedef struct np_os_fingerprint
{
    /* IP layer */
    uint8_t  ttl;
    uint16_t total_length;
    uint16_t ip_id;

    /* TCP basic */
    uint16_t window_size;
    bool     df_bit;

    /* TCP options */
    uint16_t mss;
    uint8_t  window_scale;
    bool     sack_permitted;
    bool     timestamp;

    /* raw TCP option order */
    uint8_t tcp_options_order[NP_TCP_OPT_MAX];
    uint8_t tcp_options_count;

    /* TTL normalization */
    uint8_t ttl_initial;
    uint8_t ttl_hop_dist;

    /* behavioral response pattern */
    char     response_pattern[8];
    uint32_t probes_responded;

    /* per-probe arrays (7 TCP probes in deep pipeline) */
    bool     probe_responded[7];
    uint16_t probe_window[7];
    uint8_t  probe_ttl[7];
    bool     probe_df[7];
    bool     probe_rst[7];
    bool     probe_ack[7];

    /* derived classes */
    uint8_t  ipid_type;

    uint8_t  env_flags;
    bool     opt_rewritten;
    uint8_t  reliability; /* 0–100 */

    uint8_t  ipid_behavior; /* 0=unknown, 1=incremental, 2=random */
    uint32_t ts_rate;

    /* UDP closed-port probe (U1) */
    bool     u1_responded;
    uint8_t  u1_icmp_type;
    uint8_t  u1_icmp_code;
    uint8_t  u1_ttl;

} np_os_fingerprint_t;


#endif /* NP_OS_FINGERPRINT_TYPES_H */
