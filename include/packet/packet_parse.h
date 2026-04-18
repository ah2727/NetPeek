/*
 * NetPeek - Cross-Platform Packet Parser
 *
 * Parses raw captured packets from libpcap into structured
 * representations of IP, TCP, and TCP option fields.
 *
 * Supports link-layer types:
 *   - DLT_EN10MB   (Ethernet, Linux default)
 *   - DLT_NULL     (BSD loopback)
 *   - DLT_LOOP     (OpenBSD loopback)
 *   - DLT_RAW      (raw IP, no link header)
 *   - DLT_PKTAP    (macOS pktap)
 *   - DLT_LINUX_SLL (Linux cooked capture)
 *
 * Design:
 *   1. Determine link-layer header size from DLT type
 *   2. Parse IPv4 header (version, IHL, TTL, flags, etc.)
 *   3. Parse TCP header (ports, flags, window, data offset)
 *   4. Parse TCP options in order (MSS, SACK, TS, WScale, NOP)
 *   5. Fill np_os_fingerprint_t with extracted values
 *
 * All functions are stateless and thread-safe.
 */

#ifndef NP_PACKET_PARSER_H
#define NP_PACKET_PARSER_H
#include "packet/tcp_types.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ── Link-layer types we handle ──────────────────────── */
/*
 * These match pcap DLT_* constants.
 * We define our own to avoid requiring pcap.h in this header.
 */
#define NP_DLT_NULL        0    /* BSD loopback               */
#define NP_DLT_EN10MB      1    /* Ethernet                   */
#define NP_DLT_RAW         12   /* Raw IP (no link header)    */
#define NP_DLT_LOOP        108  /* OpenBSD loopback           */
#define NP_DLT_LINUX_SLL   113  /* Linux cooked capture       */
#define NP_DLT_PKTAP       258  /* macOS PKTAP                */

/* ── IP protocol numbers ─────────────────────────────── */
#define NP_IPPROTO_TCP     6
#define NP_IPPROTO_UDP     17
#define NP_IPPROTO_ICMP    1

/* ── TCP flags ───────────────────────────────────────── */
#define NP_TCP_FIN   0x01
#define NP_TCP_SYN   0x02
#define NP_TCP_RST   0x04
#define NP_TCP_PSH   0x08
#define NP_TCP_ACK   0x10
#define NP_TCP_URG   0x20
#define NP_TCP_ECE   0x40
#define NP_TCP_CWR   0x80

/* ── TCP option kinds ────────────────────────────────── */
#define NP_TCPOPT_EOL       0   /* End of Option List         */
#define NP_TCPOPT_NOP       1   /* No-Operation               */
#define NP_TCPOPT_MSS       2   /* Maximum Segment Size       */
#define NP_TCPOPT_WSCALE    3   /* Window Scale               */
#define NP_TCPOPT_SACKOK    4   /* SACK Permitted             */
#define NP_TCPOPT_SACK      5   /* SACK blocks                */
#define NP_TCPOPT_TIMESTAMP 8   /* Timestamps                 */

/* ── Maximum TCP options we track ────────────────────── */
#define NP_MAX_TCP_OPTIONS  16

/* ── Parsed IPv4 header ──────────────────────────────── */
typedef struct {
    uint8_t   version;         /* should be 4                  */
    uint8_t   ihl;             /* header length in 32-bit words*/
    uint8_t   ihl_bytes;       /* header length in bytes       */
    uint8_t   tos;             /* type of service / DSCP+ECN   */
    uint16_t  total_length;    /* total packet length          */
    uint16_t  identification;  /* IP ID                        */
    bool      df;              /* Don't Fragment flag           */
    bool      mf;              /* More Fragments flag           */
    uint16_t  frag_offset;     /* fragment offset               */
    uint8_t   ttl;             /* Time To Live                  */
    uint8_t   protocol;        /* next protocol (6=TCP)         */
    uint16_t  checksum;        /* header checksum               */
    uint32_t  src_addr;        /* source IP (network order)     */
    uint32_t  dst_addr;        /* dest IP (network order)       */

    /* source/dest as strings (filled by parser) */
    char      src_str[16];     /* "x.x.x.x"                    */
    char      dst_str[16];     /* "x.x.x.x"                    */

    /* pointer to raw header start in packet buffer */
    const uint8_t *raw;
    uint32_t       raw_len;
} np_ipv4_header_t;


/* ── Parsed TCP header ───────────────────────────────── */
typedef struct {
    uint16_t  src_port;
    uint16_t  dst_port;
    uint32_t  seq;
    uint32_t  ack;
    uint8_t   data_offset;     /* header length in 32-bit words */
    uint8_t   data_offset_bytes; /* header length in bytes      */
    uint8_t   flags;           /* raw flags byte                */

    /* individual flags for convenience */
    bool      flag_syn;
    bool      flag_ack;
    bool      flag_rst;
    bool      flag_fin;
    bool      flag_psh;
    bool      flag_urg;
    bool      flag_ece;
    bool      flag_cwr;

    uint16_t  window;          /* window size (unscaled)        */
    uint16_t  checksum;
    uint16_t  urgent_ptr;

    /* parsed options */
    np_tcp_option_t options[NP_MAX_TCP_OPTIONS];
    uint8_t         option_count;

    /* option order string (e.g., "MSTNW") */
    char            option_order[NP_MAX_TCP_OPTIONS + 1];

    /* quick-access option values */
    uint16_t  mss;             /* 0 if not present              */
    uint8_t   wscale;          /* 0 if not present              */
    bool      sack_permitted;
    bool      has_timestamp;
    uint32_t  ts_val;
    uint32_t  ts_ecr;

    /* pointer to raw header start in packet buffer */
    const uint8_t *raw;
    uint32_t       raw_len;
} np_tcp_header_t;

/* ── Complete parsed packet ──────────────────────────── */
typedef struct {
    /* link layer */
    int       dlt_type;        /* DLT_* constant               */
    uint32_t  link_hdr_len;    /* bytes to skip for IP header   */

    /* IP layer */
    np_ipv4_header_t ip;

    /* transport layer (only TCP for now) */
    np_tcp_header_t  tcp;

    /* overall packet info */
    const uint8_t   *raw_packet;   /* original packet buffer   */
    uint32_t         raw_length;   /* total captured length     */
    uint32_t         wire_length;  /* original on-wire length   */

    /* validity flags */
    bool      has_ip;
    bool      has_tcp;
    bool      is_synack;       /* SYN+ACK flags set            */
    bool      is_syn;          /* SYN only (no ACK)            */
    bool      is_rst;          /* RST flag set                 */
} np_parsed_packet_t;

/* ── Parser error codes ──────────────────────────────── */
typedef enum {
    NP_PARSE_OK = 0,
    NP_PARSE_ERR_NULL,         /* NULL input                    */
    NP_PARSE_ERR_TOO_SHORT,    /* packet too short              */
    NP_PARSE_ERR_NOT_IPV4,     /* not an IPv4 packet            */
    NP_PARSE_ERR_NOT_TCP,      /* not a TCP packet              */
    NP_PARSE_ERR_BAD_IHL,      /* invalid IP header length      */
    NP_PARSE_ERR_BAD_DOFF,     /* invalid TCP data offset       */
    NP_PARSE_ERR_TRUNCATED,    /* packet truncated              */
    NP_PARSE_ERR_UNKNOWN_DLT,  /* unsupported link-layer type   */
} np_parse_error_t;


/* ── Public API ──────────────────────────────────────── */

/**
 * Get the link-layer header size for a given DLT type.
 *
 * @param dlt_type   pcap datalink type (DLT_*)
 * @param out_len    receives header length in bytes
 *
 * @return  NP_PARSE_OK or NP_PARSE_ERR_UNKNOWN_DLT
 */
np_parse_error_t np_link_header_len(int dlt_type,
                                    uint32_t *out_len);

/**
 * Parse a raw packet buffer into structured fields.
 *
 * This is the main entry point. It:
 *   1. Determines link-layer offset
 *   2. Parses IPv4 header
 *   3. Parses TCP header + options
 *   4. Sets convenience flags (is_synack, etc.)
 *
 * @param raw_packet   Raw packet bytes from pcap
 * @param cap_len      Captured length (pcap_pkthdr.caplen)
 * @param wire_len     Wire length (pcap_pkthdr.len)
 * @param dlt_type     Link-layer type (pcap_datalink())
 * @param out          Receives parsed packet structure
 *
 * @return  NP_PARSE_OK on success, error code otherwise.
 *          Partial results may be available even on error
 *          (e.g., IP parsed but TCP truncated).
 */
np_parse_error_t np_parse_packet(const uint8_t      *raw_packet,
                                 uint32_t            cap_len,
                                 uint32_t            wire_len,
                                 int                 dlt_type,
                                 np_parsed_packet_t *out);

/**
 * Parse only the IPv4 header from a raw buffer.
 *
 * @param data      Pointer to start of IPv4 header
 * @param data_len  Available bytes
 * @param out       Receives parsed IPv4 header
 *
 * @return  NP_PARSE_OK or error
 */
np_parse_error_t np_parse_ipv4(const uint8_t    *data,
                               uint32_t          data_len,
                               np_ipv4_header_t *out);

/**
 * Parse only the TCP header + options from a raw buffer.
 *
 * @param data      Pointer to start of TCP header
 * @param data_len  Available bytes
 * @param out       Receives parsed TCP header
 *
 * @return  NP_PARSE_OK or error
 */
np_parse_error_t np_parse_tcp(const uint8_t   *data,
                              uint32_t         data_len,
                              np_tcp_header_t *out);

/**
 * Parse TCP options from the option region of a TCP header.
 *
 * @param opts_data  Pointer to first option byte
 *                   (TCP header + 20)
 * @param opts_len   Length of option region
 *                   (data_offset_bytes - 20)
 * @param out_opts   Array to fill (caller-allocated)
 * @param max_opts   Size of out_opts array
 * @param out_count  Receives number of options parsed
 * @param out_order  Receives option order string
 *                   (caller-allocated, at least max_opts+1)
 *
 * @return  NP_PARSE_OK or error
 */
np_parse_error_t np_parse_tcp_options(const uint8_t   *opts_data,
                                      uint32_t         opts_len,
                                      np_tcp_option_t *out_opts,
                                      uint8_t          max_opts,
                                      uint8_t         *out_count,
                                      char            *out_order);

/**
 * Extract OS fingerprint fields from a parsed SYN-ACK packet.
 *
 * Fills an np_os_fingerprint_t from the parsed packet.
 * Only meaningful if pkt->is_synack is true.
 *
 * @param pkt   Parsed packet (should be a SYN-ACK)
 * @param fp    Receives fingerprint fields
 *
 * @return  NP_PARSE_OK or error
 */
np_parse_error_t np_extract_fingerprint(
        const np_parsed_packet_t *pkt,
        void                     *fp);

/**
 * Check if a parsed packet is a SYN-ACK from a specific
 * source IP and port.
 *
 * @param pkt       Parsed packet
 * @param src_ip    Expected source IP (network order)
 * @param src_port  Expected source port (host order)
 *
 * @return  true if packet matches
 */
bool np_is_synack_from(const np_parsed_packet_t *pkt,
                       uint32_t src_ip,
                       uint16_t src_port);

/**
 * Return a human-readable string for a parse error code.
 */
const char *np_parse_strerror(np_parse_error_t err);

/**
 * Print a parsed packet summary to stderr (for debugging).
 */
void np_parsed_packet_print(const np_parsed_packet_t *pkt);

/**
 * Print TCP options in detail to stderr (for debugging).
 */
void np_tcp_options_print(const np_tcp_header_t *tcp);

#endif /* NP_PACKET_PARSER_H */