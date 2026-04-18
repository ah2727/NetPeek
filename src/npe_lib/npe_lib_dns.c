/*****************************************************************************
 * npe_lib_dns.c — DNS resolution library for NPE Lua scripts
 *
 * Implements A, AAAA, MX, NS, TXT, SRV, SOA, PTR, CNAME, and AXFR queries.
 * Uses raw UDP sockets to craft and send DNS packets, with fallback to TCP
 * for truncated responses and zone transfers.
 *
 * All functions are exposed under the "npe.dns" Lua namespace.
 *****************************************************************************/

#include "npe_lib_dns.h"
#include "npe_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
/* ═══════════════════════════════════════════════════════════════════════════
 * DNS Wire Format Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

#define DNS_HEADER_SIZE        12
#define DNS_MAX_PACKET_UDP     512
#define DNS_MAX_PACKET_TCP     65535
#define DNS_MAX_LABEL_LEN      63
#define DNS_CLASS_IN           1
#define DNS_TYPE_AXFR          252

/* DNS header flags. */
#define DNS_FLAG_QR            0x8000   /* Query/Response */
#define DNS_FLAG_AA            0x0400   /* Authoritative Answer */
#define DNS_FLAG_TC            0x0200   /* Truncated */
#define DNS_FLAG_RD            0x0100   /* Recursion Desired */
#define DNS_FLAG_RA            0x0080   /* Recursion Available */
#define DNS_RCODE_MASK         0x000F

/* DNS RCODE values. */
#define DNS_RCODE_NOERROR      0
#define DNS_RCODE_FORMERR      1
#define DNS_RCODE_SERVFAIL     2
#define DNS_RCODE_NXDOMAIN     3
#define DNS_RCODE_NOTIMP       4
#define DNS_RCODE_REFUSED      5

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Helpers: Time
 * ═══════════════════════════════════════════════════════════════════════════ */

static double
dns_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Helpers: Default Nameserver
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Parse /etc/resolv.conf for the first "nameserver" line.
 * Falls back to 8.8.8.8 on failure.
 */
static void
get_default_nameserver(char *out, size_t out_size)
{
    FILE *fp = fopen("/etc/resolv.conf", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            /* Skip comments. */
            if (line[0] == '#' || line[0] == ';')
                continue;

            if (strncmp(line, "nameserver", 10) == 0) {
                char *ns = line + 10;
                while (*ns == ' ' || *ns == '\t')
                    ns++;
                /* Trim trailing whitespace / newlines. */
                char *end = ns + strlen(ns) - 1;
                while (end > ns && (*end == '\n' || *end == '\r' ||
                                    *end == ' '  || *end == '\t'))
                    *end-- = '\0';

                if (strlen(ns) > 0) {
                    strncpy(out, ns, out_size - 1);
                    out[out_size - 1] = '\0';
                    fclose(fp);
                    return;
                }
            }
        }
        fclose(fp);
    }

    /* Fallback. */
    strncpy(out, "8.8.8.8", out_size - 1);
    out[out_size - 1] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Helpers: DNS Name Encoding
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Encode a domain name into DNS wire format (label-length encoding).
 * Example: "www.example.com" → \x03www\x07example\x03com\x00
 *
 * @return Number of bytes written, or -1 on error.
 */
static int
dns_encode_name(const char *name, uint8_t *buf, size_t buf_size)
{
    if (!name || !buf || buf_size == 0)
        return -1;

    size_t pos = 0;
    const char *p = name;

    while (*p) {
        const char *dot = strchr(p, '.');
        size_t label_len;

        if (dot)
            label_len = (size_t)(dot - p);
        else
            label_len = strlen(p);

        if (label_len == 0) {
            /* Consecutive dots or trailing dot — skip. */
            p++;
            continue;
        }

        if (label_len > DNS_MAX_LABEL_LEN)
            return -1;
        if (pos + 1 + label_len >= buf_size)
            return -1;

        buf[pos++] = (uint8_t)label_len;
        memcpy(buf + pos, p, label_len);
        pos += label_len;

        p += label_len;
        if (*p == '.')
            p++;
    }

    /* Root label (null terminator). */
    if (pos + 1 >= buf_size)
        return -1;
    buf[pos++] = 0;

    return (int)pos;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Helpers: DNS Name Decoding (with pointer compression)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Decode a DNS name from a packet supporting pointer compression.
 *
 * @param pkt       Start of the full DNS packet.
 * @param pkt_len   Total packet length.
 * @param offset    Current read offset (updated to point past the name).
 * @param out       Output buffer for the decoded name.
 * @param out_size  Size of the output buffer.
 * @return          0 on success, -1 on error.
 */
static int
dns_decode_name(const uint8_t *pkt, size_t pkt_len, size_t *offset,
                char *out, size_t out_size)
{
    if (!pkt || !offset || !out || out_size == 0)
        return -1;

    size_t pos       = *offset;
    size_t out_pos   = 0;
    bool   jumped    = false;
    size_t jump_save = 0;
    int    jumps     = 0;

    while (pos < pkt_len) {
        uint8_t len = pkt[pos];

        /* End of name. */
        if (len == 0) {
            pos++;
            break;
        }

        /* Pointer (compression). */
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= pkt_len)
                return -1;
            if (!jumped) {
                jump_save = pos + 2;
                jumped = true;
            }
            size_t ptr = ((size_t)(len & 0x3F) << 8) | pkt[pos + 1];
            if (ptr >= pkt_len)
                return -1;
            pos = ptr;
            if (++jumps > 256)
                return -1;  /* Infinite loop guard. */
            continue;
        }

        /* Regular label. */
        pos++;
        if (pos + len > pkt_len)
            return -1;

        /* Add separating dot. */
        if (out_pos > 0 && out_pos < out_size - 1)
            out[out_pos++] = '.';

        for (uint8_t i = 0; i < len && out_pos < out_size - 1; i++)
            out[out_pos++] = (char)pkt[pos + i];

        pos += len;
    }

    out[out_pos] = '\0';
    *offset = jumped ? jump_save : pos;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Helpers: DNS Packet Building
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Build a DNS query packet.
 *
 * @param name      Domain name to query.
 * @param qtype     Query type (A, AAAA, MX, etc.).
 * @param buf       Output buffer.
 * @param buf_size  Buffer capacity.
 * @param out_txid  Output: transaction ID used.
 * @return          Packet length, or -1 on error.
 */
static int
dns_build_query(const char *name, uint16_t qtype,
                uint8_t *buf, size_t buf_size, uint16_t *out_txid)
{
    if (!name || !buf || buf_size < DNS_HEADER_SIZE + NPE_DNS_MAX_NAME_LEN + 4)
        return -1;

    memset(buf, 0, buf_size);

    /* Transaction ID (pseudo-random). */
    uint16_t txid = (uint16_t)(rand() & 0xFFFF);
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
    if (out_txid)
        *out_txid = txid;

    /* Flags: standard query, recursion desired. */
    uint16_t flags = DNS_FLAG_RD;
    buf[2] = (uint8_t)(flags >> 8);
    buf[3] = (uint8_t)(flags & 0xFF);

    /* QDCOUNT = 1. */
    buf[4] = 0;
    buf[5] = 1;

    /* ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0. */

    /* Question section: QNAME + QTYPE + QCLASS. */
    size_t pos = DNS_HEADER_SIZE;
    int name_len = dns_encode_name(name, buf + pos, buf_size - pos);
    if (name_len < 0)
        return -1;
    pos += (size_t)name_len;

    if (pos + 4 > buf_size)
        return -1;

    /* QTYPE. */
    buf[pos++] = (uint8_t)(qtype >> 8);
    buf[pos++] = (uint8_t)(qtype & 0xFF);

    /* QCLASS = IN. */
    buf[pos++] = 0;
    buf[pos++] = (uint8_t)DNS_CLASS_IN;

    return (int)pos;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Helpers: DNS Response Parsing
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Read a 16-bit big-endian value from the packet.
 */
static inline uint16_t
dns_read_u16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

/**
 * Read a 32-bit big-endian value from the packet.
 */
static inline uint32_t
dns_read_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/**
 * Parse a single resource record starting at *offset.
 * Fills in `record` and advances *offset past the record.
 *
 * @return 0 on success, -1 on error.
 */
static int
dns_parse_rr(const uint8_t *pkt, size_t pkt_len, size_t *offset,
             npe_dns_record_t *record)
{
    if (!pkt || !offset || !record)
        return -1;

    memset(record, 0, sizeof(*record));

    /* Owner name. */
    if (dns_decode_name(pkt, pkt_len, offset, record->name,
                        sizeof(record->name)) < 0)
        return -1;

    size_t pos = *offset;
    if (pos + 10 > pkt_len)
        return -1;

    record->type = dns_read_u16(pkt + pos);
    uint16_t rclass = dns_read_u16(pkt + pos + 2);
    (void)rclass;
    record->ttl      = dns_read_u32(pkt + pos + 4);
    uint16_t rdlength = dns_read_u16(pkt + pos + 8);
    pos += 10;

    if (pos + rdlength > pkt_len)
        return -1;

    const uint8_t *rdata     = pkt + pos;
    size_t         rdata_off = pos;        /* Offset within the packet. */

    /* Parse RDATA based on type. */
    switch (record->type) {

    case NPE_DNS_A:
        if (rdlength == 4) {
            snprintf(record->value, sizeof(record->value),
                     "%u.%u.%u.%u",
                     rdata[0], rdata[1], rdata[2], rdata[3]);
        }
        break;

    case NPE_DNS_AAAA:
        if (rdlength == 16) {
            inet_ntop(AF_INET6, rdata,
                      record->value, sizeof(record->value));
        }
        break;

    case NPE_DNS_CNAME:
    case NPE_DNS_NS:
    case NPE_DNS_PTR: {
        size_t tmp_off = rdata_off;
        dns_decode_name(pkt, pkt_len, &tmp_off,
                        record->value, sizeof(record->value));
        break;
    }

    case NPE_DNS_MX: {
        if (rdlength < 3) break;
        record->priority = dns_read_u16(rdata);
        size_t mx_off = rdata_off + 2;
        char mx_host[NPE_DNS_MAX_NAME_LEN];
        if (dns_decode_name(pkt, pkt_len, &mx_off,
                            mx_host, sizeof(mx_host)) == 0) {
            snprintf(record->value, sizeof(record->value),
                     "%u %s", record->priority, mx_host);
            strncpy(record->target, mx_host, sizeof(record->target) - 1);
        }
        break;
    }

    case NPE_DNS_SRV: {
        if (rdlength < 7) break;
        record->priority = dns_read_u16(rdata);
        record->weight   = dns_read_u16(rdata + 2);
        record->port     = dns_read_u16(rdata + 4);
        size_t srv_off = rdata_off + 6;
        char srv_target[NPE_DNS_MAX_NAME_LEN];
        if (dns_decode_name(pkt, pkt_len, &srv_off,
                            srv_target, sizeof(srv_target)) == 0) {
            snprintf(record->value, sizeof(record->value),
                     "%u %u %u %s",
                     record->priority, record->weight,
                     record->port, srv_target);
            strncpy(record->target, srv_target, sizeof(record->target) - 1);
        }
        break;
    }

    case NPE_DNS_TXT: {
        /*
         * TXT RDATA: one or more <length><data> sequences.
         * We concatenate them.
         */
        size_t  vpos = 0;
        size_t  rd   = 0;
        while (rd < rdlength) {
            uint8_t tlen = rdata[rd++];
            if (rd + tlen > rdlength) break;
            for (uint8_t i = 0; i < tlen && vpos < sizeof(record->value) - 1; i++)
                record->value[vpos++] = (char)rdata[rd + i];
            rd += tlen;
        }
        record->value[vpos] = '\0';
        break;
    }

    case NPE_DNS_SOA: {
        /* MNAME, RNAME, then 5 × 32-bit fields. */
        size_t soa_off = rdata_off;
        char mname[NPE_DNS_MAX_NAME_LEN];
        char rname[NPE_DNS_MAX_NAME_LEN];

        if (dns_decode_name(pkt, pkt_len, &soa_off,
                            mname, sizeof(mname)) < 0)
            break;
        if (dns_decode_name(pkt, pkt_len, &soa_off,
                            rname, sizeof(rname)) < 0)
            break;

        if (soa_off + 20 > pkt_len) break;

        uint32_t serial  = dns_read_u32(pkt + soa_off);
        uint32_t refresh = dns_read_u32(pkt + soa_off + 4);
        uint32_t retry   = dns_read_u32(pkt + soa_off + 8);
        uint32_t expire  = dns_read_u32(pkt + soa_off + 12);
        uint32_t minimum = dns_read_u32(pkt + soa_off + 16);

        snprintf(record->value, sizeof(record->value),
                 "%s %s %u %u %u %u %u",
                 mname, rname, serial, refresh, retry, expire, minimum);

        strncpy(record->target, mname, sizeof(record->target) - 1);

        record->soa_serial  = serial;
        record->soa_refresh = refresh;
        record->soa_retry   = retry;
        record->soa_expire  = expire;
        record->soa_minimum = minimum;
        strncpy(record->soa_mname, mname, sizeof(record->soa_mname) - 1);
        strncpy(record->soa_rname, rname, sizeof(record->soa_rname) - 1);
        break;
    }

    default:
        /* Unknown type — store raw hex. */
        {
            size_t vpos = 0;
            for (uint16_t i = 0; i < rdlength && vpos + 3 < sizeof(record->value); i++) {
                snprintf(record->value + vpos, sizeof(record->value) - vpos,
                         "%02x", rdata[i]);
                vpos += 2;
            }
            record->value[vpos] = '\0';
        }
        break;
    }

    *offset = pos + rdlength;
    return 0;
}

/**
 * Skip over the Question section of a DNS packet.
 * There are `qdcount` questions to skip.
 */
static int
dns_skip_questions(const uint8_t *pkt, size_t pkt_len,
                   size_t *offset, uint16_t qdcount)
{
    for (uint16_t i = 0; i < qdcount; i++) {
        /* Skip QNAME. */
        char tmp[NPE_DNS_MAX_NAME_LEN];
        if (dns_decode_name(pkt, pkt_len, offset, tmp, sizeof(tmp)) < 0)
            return -1;
        /* Skip QTYPE + QCLASS (4 bytes). */
        if (*offset + 4 > pkt_len)
            return -1;
        *offset += 4;
    }
    return 0;
}

/**
 * Parse a complete DNS response packet.
 *
 * @param pkt       Packet data.
 * @param pkt_len   Packet length.
 * @param result    Output result structure.
 * @return          0 on success, -1 on error.
 */
static int
dns_parse_response(const uint8_t *pkt, size_t pkt_len,
                   npe_dns_result_t *result)
{
    if (!pkt || pkt_len < DNS_HEADER_SIZE || !result)
        return -1;

    /* Header fields. */
    uint16_t txid    = dns_read_u16(pkt);
    uint16_t flags   = dns_read_u16(pkt + 2);
    uint16_t qdcount = dns_read_u16(pkt + 4);
    uint16_t ancount = dns_read_u16(pkt + 6);
    uint16_t nscount = dns_read_u16(pkt + 8);
    uint16_t arcount = dns_read_u16(pkt + 10);

    (void)txid;
    (void)nscount;
    (void)arcount;

    result->rcode       = flags & DNS_RCODE_MASK;
    result->is_truncated = (flags & DNS_FLAG_TC) != 0;
    result->is_authoritative = (flags & DNS_FLAG_AA) != 0;

    /* Skip question section. */
    size_t offset = DNS_HEADER_SIZE;
    if (dns_skip_questions(pkt, pkt_len, &offset, qdcount) < 0)
        return -1;

    /* Parse answer RRs. */
    uint16_t total_rrs = ancount;
    if (total_rrs > NPE_DNS_MAX_RECORDS)
        total_rrs = NPE_DNS_MAX_RECORDS;

    result->records = calloc(total_rrs, sizeof(npe_dns_record_t));
    if (!result->records)
        return -1;

    result->record_count = 0;

    for (uint16_t i = 0; i < ancount && result->record_count < total_rrs; i++) {
        npe_dns_record_t rec;
        if (dns_parse_rr(pkt, pkt_len, &offset, &rec) < 0)
            break;
        result->records[result->record_count++] = rec;
    }

    /* Optionally parse authority and additional sections for completeness. */
    for (uint16_t i = 0; i < nscount; i++) {
        npe_dns_record_t rec;
        if (dns_parse_rr(pkt, pkt_len, &offset, &rec) < 0)
            break;
        /* We don't store authority records in the primary results,
         * but we consume them so offset stays correct. */
    }

    for (uint16_t i = 0; i < arcount; i++) {
        npe_dns_record_t rec;
        if (dns_parse_rr(pkt, pkt_len, &offset, &rec) < 0)
            break;
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal: UDP DNS Query
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Send a DNS query over UDP and receive the response.
 *
 * @param nameserver  IP address of the DNS server.
 * @param query_pkt   Query packet data.
 * @param query_len   Query packet length.
 * @param resp_buf    Output buffer for the response.
 * @param resp_cap    Response buffer capacity.
 * @param timeout_ms  Timeout in milliseconds.
 * @return            Number of bytes received, or -1 on error.
 */
static ssize_t
dns_query_udp(const char *nameserver,
              const uint8_t *query_pkt, size_t query_len,
              uint8_t *resp_buf, size_t resp_cap,
              uint32_t timeout_ms)
{
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(53);

    if (inet_pton(AF_INET, nameserver, &server_addr.sin_addr) != 1) {
        /* Try IPv6. */
        struct sockaddr_in6 server6;
        memset(&server6, 0, sizeof(server6));
        server6.sin6_family = AF_INET6;
        server6.sin6_port   = htons(53);

        if (inet_pton(AF_INET6, nameserver, &server6.sin6_addr) != 1)
            return -1;

        int fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (fd < 0) return -1;

        ssize_t sent = sendto(fd, query_pkt, query_len, 0,
                              (struct sockaddr *)&server6, sizeof(server6));
        if (sent < 0) {
            close(fd);
            return -1;
        }

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ret = poll(&pfd, 1, (int)timeout_ms);
        if (ret <= 0) {
            close(fd);
            errno = (ret == 0) ? ETIMEDOUT : errno;
            return -1;
        }

        ssize_t n = recvfrom(fd, resp_buf, resp_cap, 0, NULL, NULL);
        close(fd);
        return n;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    ssize_t sent = sendto(fd, query_pkt, query_len, 0,
                          (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (sent < 0) {
        close(fd);
        return -1;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ret = poll(&pfd, 1, (int)timeout_ms);
    if (ret <= 0) {
        close(fd);
        errno = (ret == 0) ? ETIMEDOUT : errno;
        return -1;
    }

    ssize_t n = recvfrom(fd, resp_buf, resp_cap, 0, NULL, NULL);
    close(fd);
    return n;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal: TCP DNS Query (for truncated responses and AXFR)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Send a DNS query over TCP and receive the response.
 * TCP DNS prepends a 2-byte length prefix.
 *
 * @param nameserver  IP address of the DNS server.
 * @param query_pkt   Query packet (without length prefix).
 * @param query_len   Query packet length.
 * @param resp_buf    Output buffer.
 * @param resp_cap    Buffer capacity.
 * @param timeout_ms  Timeout in milliseconds.
 * @return            Bytes received (excluding length prefix), or -1.
 */
static ssize_t
dns_query_tcp(const char *nameserver,
              const uint8_t *query_pkt, size_t query_len,
              uint8_t *resp_buf, size_t resp_cap,
              uint32_t timeout_ms)
{
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(53);

    if (inet_pton(AF_INET, nameserver, &server_addr.sin_addr) != 1)
        return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Set connect timeout via poll. */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    if (rc < 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int ret = poll(&pfd, 1, (int)timeout_ms);
        if (ret <= 0) {
            close(fd);
            return -1;
        }
        int sock_err = 0;
        socklen_t err_len = sizeof(sock_err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
        if (sock_err != 0) {
            close(fd);
            errno = sock_err;
            return -1;
        }
    }

    /* Restore blocking. */
    fcntl(fd, F_SETFL, flags);

    /* Send: 2-byte length prefix + query. */
    uint8_t tcp_buf[2 + DNS_MAX_PACKET_TCP];
    if (query_len + 2 > sizeof(tcp_buf)) {
        close(fd);
        return -1;
    }

    tcp_buf[0] = (uint8_t)((query_len >> 8) & 0xFF);
    tcp_buf[1] = (uint8_t)(query_len & 0xFF);
    memcpy(tcp_buf + 2, query_pkt, query_len);

    ssize_t sent = send(fd, tcp_buf, query_len + 2, MSG_NOSIGNAL);
    if (sent < 0) {
        close(fd);
        return -1;
    }

    /* Receive: 2-byte length prefix first. */
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ret = poll(&pfd, 1, (int)timeout_ms);
    if (ret <= 0) {
        close(fd);
        return -1;
    }

    uint8_t len_buf[2];
    ssize_t n = recv(fd, len_buf, 2, MSG_WAITALL);
    if (n != 2) {
        close(fd);
        return -1;
    }

    uint16_t resp_len = ((uint16_t)len_buf[0] << 8) | len_buf[1];
    if (resp_len > resp_cap) {
        close(fd);
        return -1;
    }

    /* Read the full response. */
    size_t total = 0;
    while (total < resp_len) {
        ret = poll(&pfd, 1, (int)timeout_ms);
        if (ret <= 0) break;

        n = recv(fd, resp_buf + total, resp_len - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
    }

    close(fd);
    return (ssize_t)total;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal: TCP AXFR Query (zone transfer — multiple messages)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Perform a DNS zone transfer (AXFR) over TCP.
 * AXFR returns multiple DNS messages; we collect all records until
 * we see a second SOA record.
 */
static int
dns_query_axfr(const char *nameserver, const char *domain,
               uint32_t timeout_ms, npe_dns_result_t *result)
{
    /* Build AXFR query. */
    uint8_t query_pkt[DNS_MAX_PACKET_UDP];
    uint16_t txid = 0;
    int query_len = dns_build_query(domain, DNS_TYPE_AXFR,
                                    query_pkt, sizeof(query_pkt), &txid);
    if (query_len < 0)
        return -1;

    /* Connect to nameserver. */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(53);

    if (inet_pton(AF_INET, nameserver, &server_addr.sin_addr) != 1)
        return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Non-blocking connect with timeout. */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (rc < 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, (int)timeout_ms) <= 0) {
            close(fd);
            return -1;
        }
        int sock_err = 0;
        socklen_t err_len = sizeof(sock_err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
        if (sock_err != 0) {
            close(fd);
            return -1;
        }
    }
    fcntl(fd, F_SETFL, flags);

    /* Send query with TCP length prefix. */
    uint8_t tcp_buf[2 + DNS_MAX_PACKET_UDP];
    tcp_buf[0] = (uint8_t)((query_len >> 8) & 0xFF);
    tcp_buf[1] = (uint8_t)(query_len & 0xFF);
    memcpy(tcp_buf + 2, query_pkt, (size_t)query_len);

    if (send(fd, tcp_buf, (size_t)query_len + 2, MSG_NOSIGNAL) < 0) {
        close(fd);
        return -1;
    }

    /* Collect records from multiple TCP DNS messages. */
    size_t records_cap = 256;
    result->records = calloc(records_cap, sizeof(npe_dns_record_t));
    if (!result->records) {
        close(fd);
        return -1;
    }
    result->record_count = 0;

    int soa_count = 0;
    bool done = false;

    while (!done) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, (int)timeout_ms) <= 0)
            break;

        /* Read 2-byte length. */
        uint8_t len_buf[2];
        ssize_t n = recv(fd, len_buf, 2, MSG_WAITALL);
        if (n != 2) break;

        uint16_t msg_len = ((uint16_t)len_buf[0] << 8) | len_buf[1];
        if (msg_len == 0 || msg_len > DNS_MAX_PACKET_TCP)
            break;

        uint8_t *msg_buf = malloc(msg_len);
        if (!msg_buf) break;

        /* Read full message. */
        size_t total = 0;
        while (total < msg_len) {
            if (poll(&pfd, 1, (int)timeout_ms) <= 0) break;
            n = recv(fd, msg_buf + total, msg_len - total, 0);
            if (n <= 0) break;
            total += (size_t)n;
        }
        if (total < msg_len) {
            free(msg_buf);
            break;
        }

        /* Parse the DNS message header. */
        if (msg_len < DNS_HEADER_SIZE) {
            free(msg_buf);
            break;
        }

        uint16_t resp_flags   = dns_read_u16(msg_buf + 2);
        uint16_t resp_qdcount = dns_read_u16(msg_buf + 4);
        uint16_t resp_ancount = dns_read_u16(msg_buf + 6);

        result->rcode = resp_flags & DNS_RCODE_MASK;
        if (result->rcode != DNS_RCODE_NOERROR) {
            free(msg_buf);
            break;
        }

        /* Skip questions. */
        size_t offset = DNS_HEADER_SIZE;
        if (dns_skip_questions(msg_buf, msg_len, &offset, resp_qdcount) < 0) {
            free(msg_buf);
            break;
        }

        /* Parse answer records. */
        for (uint16_t i = 0; i < resp_ancount; i++) {
            npe_dns_record_t rec;
            if (dns_parse_rr(msg_buf, msg_len, &offset, &rec) < 0)
                break;

            /* Track SOA records to detect end of AXFR. */
            if (rec.type == NPE_DNS_SOA) {
                soa_count++;
                if (soa_count >= 2) {
                    done = true;
                    break;
                }
            }

            /* Grow records array if needed. */
            if (result->record_count >= records_cap) {
                records_cap *= 2;
                npe_dns_record_t *new_recs = realloc(result->records,
                    records_cap * sizeof(npe_dns_record_t));
                if (!new_recs) {
                    done = true;
                    break;
                }
                result->records = new_recs;
            }

            result->records[result->record_count++] = rec;
        }

        free(msg_buf);
    }

    close(fd);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Core C-Level API: dns_query
 * ═══════════════════════════════════════════════════════════════════════════ */

int
npe_dns_query(const char *hostname, uint16_t qtype,
              const char *nameserver, uint32_t timeout_ms,
              npe_dns_result_t *result)
{
    if (!hostname || !result)
        return -1;

    memset(result, 0, sizeof(*result));
    result->qtype = qtype;
    strncpy(result->hostname, hostname, sizeof(result->hostname) - 1);

    if (timeout_ms == 0)
        timeout_ms = NPE_DNS_DEFAULT_TIMEOUT_MS;

    /* Determine nameserver. */
    char ns_buf[INET6_ADDRSTRLEN];
    if (nameserver && nameserver[0]) {
        strncpy(ns_buf, nameserver, sizeof(ns_buf) - 1);
        ns_buf[sizeof(ns_buf) - 1] = '\0';
    } else {
        get_default_nameserver(ns_buf, sizeof(ns_buf));
    }
    strncpy(result->nameserver, ns_buf, sizeof(result->nameserver) - 1);

    double start = dns_now_ms();

    /* Handle AXFR specially (always TCP). */
    if (qtype == DNS_TYPE_AXFR) {
        int rc = dns_query_axfr(ns_buf, hostname, timeout_ms, result);
        result->elapsed_ms = dns_now_ms() - start;
        return rc;
    }

    /* Build the query packet. */
    uint8_t query_pkt[DNS_MAX_PACKET_UDP];
    uint16_t txid = 0;
    int query_len = dns_build_query(hostname, qtype,
                                    query_pkt, sizeof(query_pkt), &txid);
    if (query_len < 0)
        return -1;

    /* Send via UDP. */
    uint8_t resp_buf[DNS_MAX_PACKET_TCP];
    ssize_t resp_len = dns_query_udp(ns_buf, query_pkt, (size_t)query_len,
                                     resp_buf, sizeof(resp_buf), timeout_ms);
    if (resp_len < DNS_HEADER_SIZE) {
        result->elapsed_ms = dns_now_ms() - start;
        return -1;
    }

    /* Check for truncation → fall back to TCP. */
    uint16_t resp_flags = dns_read_u16(resp_buf + 2);
    if (resp_flags & DNS_FLAG_TC) {
        resp_len = dns_query_tcp(ns_buf, query_pkt, (size_t)query_len,
                                 resp_buf, sizeof(resp_buf), timeout_ms);
        if (resp_len < DNS_HEADER_SIZE) {
            result->elapsed_ms = dns_now_ms() - start;
            return -1;
        }
        result->used_tcp = true;
    }

    /* Parse the response. */
    int rc = dns_parse_response(resp_buf, (size_t)resp_len, result);
    result->elapsed_ms = dns_now_ms() - start;
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Convenience C-Level Wrappers
 * ═══════════════════════════════════════════════════════════════════════════ */

int
npe_dns_resolve(const char *hostname, const char *nameserver,
                uint32_t timeout_ms, npe_dns_result_t *result)
{
    return npe_dns_query(hostname, NPE_DNS_A, nameserver, timeout_ms, result);
}

int
npe_dns_resolve6(const char *hostname, const char *nameserver,
                 uint32_t timeout_ms, npe_dns_result_t *result)
{
    return npe_dns_query(hostname, NPE_DNS_AAAA, nameserver, timeout_ms, result);
}

int
npe_dns_reverse(const char *ip, const char *nameserver,
                uint32_t timeout_ms, npe_dns_result_t *result)
{
    if (!ip || !result)
        return -1;

    char arpa_name[256];

    /* Check if IPv4. */
    struct in_addr addr4;
    if (inet_pton(AF_INET, ip, &addr4) == 1) {
        uint8_t *octets = (uint8_t *)&addr4.s_addr;
        snprintf(arpa_name, sizeof(arpa_name),
                 "%u.%u.%u.%u.in-addr.arpa",
                 octets[3], octets[2], octets[1], octets[0]);
    } else {
        /* IPv6 reverse. */
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, ip, &addr6) != 1)
            return -1;

        size_t pos = 0;
        for (int i = 15; i >= 0; i--) {
            pos += (size_t)snprintf(arpa_name + pos, sizeof(arpa_name) - pos,
                                     "%x.%x.",
                                     addr6.s6_addr[i] & 0x0F,
                                     (addr6.s6_addr[i] >> 4) & 0x0F);
        }
        snprintf(arpa_name + pos, sizeof(arpa_name) - pos, "ip6.arpa");
    }

    return npe_dns_query(arpa_name, NPE_DNS_PTR, nameserver, timeout_ms, result);
}

int
npe_dns_mx(const char *hostname, const char *nameserver,
           uint32_t timeout_ms, npe_dns_result_t *result)
{
    return npe_dns_query(hostname, NPE_DNS_MX, nameserver, timeout_ms, result);
}

int
npe_dns_ns(const char *hostname, const char *nameserver,
           uint32_t timeout_ms, npe_dns_result_t *result)
{
    return npe_dns_query(hostname, NPE_DNS_NS, nameserver, timeout_ms, result);
}

int
npe_dns_txt(const char *hostname, const char *nameserver,
            uint32_t timeout_ms, npe_dns_result_t *result)
{
    return npe_dns_query(hostname, NPE_DNS_TXT, nameserver, timeout_ms, result);
}

int
npe_dns_srv(const char *hostname, const char *nameserver,
            uint32_t timeout_ms, npe_dns_result_t *result)
{
    return npe_dns_query(hostname, NPE_DNS_SRV, nameserver, timeout_ms, result);
}

int
npe_dns_soa(const char *hostname, const char *nameserver,
            uint32_t timeout_ms, npe_dns_result_t *result)
{
    return npe_dns_query(hostname, NPE_DNS_SOA, nameserver, timeout_ms, result);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Result Cleanup
 * ═══════════════════════════════════════════════════════════════════════════ */

void
npe_dns_result_free(npe_dns_result_t *result)
{
    if (!result) return;
    free(result->records);
    result->records      = NULL;
    result->record_count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Lua Helpers: Push Result to Lua
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Convert an npe_dns_record_t to a Lua table and push it.
 */
static void
dns_push_record_lua(lua_State *L, const npe_dns_record_t *rec)
{
    lua_newtable(L);

    lua_pushstring(L, rec->name);
    lua_setfield(L, -2, "name");

    lua_pushinteger(L, rec->type);
    lua_setfield(L, -2, "type");

    /* Human-readable type name. */
    const char *type_name = "UNKNOWN";
    switch (rec->type) {
    case NPE_DNS_A:     type_name = "A";     break;
    case NPE_DNS_AAAA:  type_name = "AAAA";  break;
    case NPE_DNS_CNAME: type_name = "CNAME"; break;
    case NPE_DNS_MX:    type_name = "MX";    break;
    case NPE_DNS_NS:    type_name = "NS";    break;
    case NPE_DNS_PTR:   type_name = "PTR";   break;
    case NPE_DNS_SOA:   type_name = "SOA";   break;
    case NPE_DNS_SRV:   type_name = "SRV";   break;
    case NPE_DNS_TXT:   type_name = "TXT";   break;
    }
    lua_pushstring(L, type_name);
    lua_setfield(L, -2, "type_name");

    lua_pushinteger(L, (lua_Integer)rec->ttl);
    lua_setfield(L, -2, "ttl");

    lua_pushstring(L, rec->value);
    lua_setfield(L, -2, "value");

    /* Type-specific fields. */
    if (rec->type == NPE_DNS_MX) {
        lua_pushinteger(L, rec->priority);
        lua_setfield(L, -2, "priority");
        lua_pushstring(L, rec->target);
        lua_setfield(L, -2, "host");
    }

    if (rec->type == NPE_DNS_SRV) {
        lua_pushinteger(L, rec->priority);
        lua_setfield(L, -2, "priority");
        lua_pushinteger(L, rec->weight);
        lua_setfield(L, -2, "weight");
        lua_pushinteger(L, rec->port);
        lua_setfield(L, -2, "port");
        lua_pushstring(L, rec->target);
        lua_setfield(L, -2, "target");
    }

    if (rec->type == NPE_DNS_SOA) {
        lua_pushstring(L, rec->soa_mname);
        lua_setfield(L, -2, "mname");
        lua_pushstring(L, rec->soa_rname);
        lua_setfield(L, -2, "rname");
        lua_pushinteger(L, (lua_Integer)rec->soa_serial);
        lua_setfield(L, -2, "serial");
        lua_pushinteger(L, (lua_Integer)rec->soa_refresh);
        lua_setfield(L, -2, "refresh");
        lua_pushinteger(L, (lua_Integer)rec->soa_retry);
        lua_setfield(L, -2, "retry");
        lua_pushinteger(L, (lua_Integer)rec->soa_expire);
        lua_setfield(L, -2, "expire");
        lua_pushinteger(L, (lua_Integer)rec->soa_minimum);
        lua_setfield(L, -2, "minimum");
    }
}

/**
 * Push a full npe_dns_result_t to Lua as a table.
 */
static int
dns_push_result_lua(lua_State *L, const npe_dns_result_t *result)
{
    lua_newtable(L);

    /* hostname */
    lua_pushstring(L, result->hostname);
    lua_setfield(L, -2, "hostname");

    /* nameserver */
    lua_pushstring(L, result->nameserver);
    lua_setfield(L, -2, "nameserver");

    /* rcode */
    lua_pushinteger(L, result->rcode);
    lua_setfield(L, -2, "rcode");

    /* rcode_name */
    const char *rcode_name = "UNKNOWN";
    switch (result->rcode) {
    case DNS_RCODE_NOERROR:  rcode_name = "NOERROR";  break;
    case DNS_RCODE_FORMERR:  rcode_name = "FORMERR";  break;
    case DNS_RCODE_SERVFAIL: rcode_name = "SERVFAIL"; break;
    case DNS_RCODE_NXDOMAIN: rcode_name = "NXDOMAIN"; break;
    case DNS_RCODE_NOTIMP:   rcode_name = "NOTIMP";   break;
    case DNS_RCODE_REFUSED:  rcode_name = "REFUSED";  break;
    }
    lua_pushstring(L, rcode_name);
    lua_setfield(L, -2, "rcode_name");

    /* flags */
    lua_pushboolean(L, result->is_truncated);
    lua_setfield(L, -2, "truncated");

    lua_pushboolean(L, result->is_authoritative);
    lua_setfield(L, -2, "authoritative");

    lua_pushboolean(L, result->used_tcp);
    lua_setfield(L, -2, "used_tcp");

    /* elapsed_ms */
    lua_pushnumber(L, result->elapsed_ms);
    lua_setfield(L, -2, "elapsed_ms");

    /* records array */
    lua_newtable(L);
    for (size_t i = 0; i < result->record_count; i++) {
        dns_push_record_lua(L, &result->records[i]);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    lua_setfield(L, -2, "records");

    /* record_count */
    lua_pushinteger(L, (lua_Integer)result->record_count);
    lua_setfield(L, -2, "record_count");

    /*
     * For convenience, if there is exactly one record, expose its value
     * as "address" (for A/AAAA) or "host" (for PTR/CNAME).
     */
    if (result->record_count > 0) {
        const npe_dns_record_t *first = &result->records[0];
        if (first->type == NPE_DNS_A || first->type == NPE_DNS_AAAA) {
            lua_pushstring(L, first->value);
            lua_setfield(L, -2, "address");
        } else if (first->type == NPE_DNS_PTR || first->type == NPE_DNS_CNAME) {
            lua_pushstring(L, first->value);
            lua_setfield(L, -2, "host");
        }
    }

    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Lua Helper: Parse common arguments  (hostname [, nameserver [, timeout_ms]])
 * ═══════════════════════════════════════════════════════════════════════════ */

static void
dns_parse_lua_args(lua_State *L, const char **hostname,
                   const char **nameserver, uint32_t *timeout_ms)
{
    *hostname   = luaL_checkstring(L, 1);
    *nameserver = luaL_optstring(L, 2, NULL);
    *timeout_ms = (uint32_t)luaL_optinteger(L, 3, NPE_DNS_DEFAULT_TIMEOUT_MS);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Lua-C Binding: Generic query dispatcher
 * ═══════════════════════════════════════════════════════════════════════════ */

static int
dns_lua_do_query(lua_State *L, uint16_t qtype)
{
    const char *hostname;
    const char *nameserver;
    uint32_t    timeout_ms;
    dns_parse_lua_args(L, &hostname, &nameserver, &timeout_ms);

    npe_dns_result_t result;
    int rc = npe_dns_query(hostname, qtype, nameserver, timeout_ms, &result);
    if (rc < 0) {
        npe_dns_result_free(&result);
        lua_pushnil(L);
        lua_pushfstring(L, "DNS query failed for '%s'", hostname);
        return 2;
    }

    if (result.rcode != DNS_RCODE_NOERROR && result.record_count == 0) {
        const char *rcode_str = "unknown error";
        switch (result.rcode) {
        case DNS_RCODE_FORMERR:  rcode_str = "FORMERR";  break;
        case DNS_RCODE_SERVFAIL: rcode_str = "SERVFAIL"; break;
        case DNS_RCODE_NXDOMAIN: rcode_str = "NXDOMAIN"; break;
        case DNS_RCODE_NOTIMP:   rcode_str = "NOTIMP";   break;
        case DNS_RCODE_REFUSED:  rcode_str = "REFUSED";  break;
        }
        npe_dns_result_free(&result);
        lua_pushnil(L);
        lua_pushfstring(L, "DNS query returned %s for '%s'",
                        rcode_str, hostname);
        return 2;
    }

    dns_push_result_lua(L, &result);
    npe_dns_result_free(&result);
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Lua-C Bindings: Individual query types
 * ═══════════════════════════════════════════════════════════════════════════ */

/* -- npe.dns.resolve(hostname [, nameserver [, timeout_ms]]) -- */
int
npe_dns_l_resolve(lua_State *L)
{
    return dns_lua_do_query(L, NPE_DNS_A);
}

/* -- npe.dns.resolve6(hostname [, nameserver [, timeout_ms]]) -- */
int
npe_dns_l_resolve6(lua_State *L)
{
    return dns_lua_do_query(L, NPE_DNS_AAAA);
}

/* -- npe.dns.reverse(ip [, nameserver [, timeout_ms]]) -- */
int
npe_dns_l_reverse(lua_State *L)
{
    const char *ip = luaL_checkstring(L, 1);
    const char *nameserver = luaL_optstring(L, 2, NULL);
    uint32_t timeout_ms = (uint32_t)luaL_optinteger(L, 3, NPE_DNS_DEFAULT_TIMEOUT_MS);

    npe_dns_result_t result;
    int rc = npe_dns_reverse(ip, nameserver, timeout_ms, &result);
    if (rc < 0) {
        npe_dns_result_free(&result);
        lua_pushnil(L);
        lua_pushfstring(L, "Reverse DNS lookup failed for '%s'", ip);
        return 2;
    }

    dns_push_result_lua(L, &result);
    npe_dns_result_free(&result);
    return 1;
}

/* -- npe.dns.mx(hostname [, nameserver [, timeout_ms]]) -- */
int
npe_dns_l_mx(lua_State *L)
{
    return dns_lua_do_query(L, NPE_DNS_MX);
}

/* -- npe.dns.ns(hostname [, nameserver [, timeout_ms]]) -- */
int
npe_dns_l_ns(lua_State *L)
{
    return dns_lua_do_query(L, NPE_DNS_NS);
}

/* -- npe.dns.txt(hostname [, nameserver [, timeout_ms]]) -- */
int
npe_dns_l_txt(lua_State *L)
{
    return dns_lua_do_query(L, NPE_DNS_TXT);
}

/* -- npe.dns.srv(hostname [, nameserver [, timeout_ms]]) -- */
int
npe_dns_l_srv(lua_State *L)
{
    return dns_lua_do_query(L, NPE_DNS_SRV);
}

/* -- npe.dns.soa(hostname [, nameserver [, timeout_ms]]) -- */
int
npe_dns_l_soa(lua_State *L)
{
    return dns_lua_do_query(L, NPE_DNS_SOA);
}

/* -- npe.dns.axfr(nameserver, domain [, timeout_ms]) -- */
int
npe_dns_l_axfr(lua_State *L)
{
    const char *nameserver = luaL_checkstring(L, 1);
    const char *domain     = luaL_checkstring(L, 2);
    uint32_t timeout_ms    = (uint32_t)luaL_optinteger(L, 3, NPE_DNS_DEFAULT_TIMEOUT_MS);

    npe_dns_result_t result;
    int rc = npe_dns_query(domain, DNS_TYPE_AXFR, nameserver, timeout_ms, &result);
    if (rc < 0) {
        npe_dns_result_free(&result);
        lua_pushnil(L);
        lua_pushfstring(L, "AXFR failed for '%s' from '%s'",
                        domain, nameserver);
        return 2;
    }

    dns_push_result_lua(L, &result);
    npe_dns_result_free(&result);
    return 1;
}

/* -- npe.dns.query(hostname, type_str [, nameserver [, timeout_ms]]) -- */
int
npe_dns_l_query(lua_State *L)
{
    const char *hostname = luaL_checkstring(L, 1);
    const char *type_str = luaL_checkstring(L, 2);
    const char *nameserver = luaL_optstring(L, 3, NULL);
    uint32_t timeout_ms = (uint32_t)luaL_optinteger(L, 4, NPE_DNS_DEFAULT_TIMEOUT_MS);

    /* Map type string to numeric. */
    uint16_t qtype = 0;
    struct {
        const char *name;
        uint16_t    type;
    } type_map[] = {
        { "A",     NPE_DNS_A     },
        { "AAAA",  NPE_DNS_AAAA  },
        { "CNAME", NPE_DNS_CNAME },
        { "MX",    NPE_DNS_MX    },
        { "NS",    NPE_DNS_NS    },
        { "PTR",   NPE_DNS_PTR   },
        { "SOA",   NPE_DNS_SOA   },
        { "SRV",   NPE_DNS_SRV   },
        { "TXT",   NPE_DNS_TXT   },
        { "AXFR",  DNS_TYPE_AXFR },
        { NULL,    0             },
    };

    bool found = false;
    for (int i = 0; type_map[i].name; i++) {
        if (strcasecmp(type_str, type_map[i].name) == 0) {
            qtype = type_map[i].type;
            found = true;
            break;
        }
    }

    if (!found) {
        /* Try numeric. */
        char *endp;
        long val = strtol(type_str, &endp, 10);
        if (endp != type_str && *endp == '\0' && val > 0 && val <= 65535) {
            qtype = (uint16_t)val;
        } else {
            return luaL_error(L, "Unknown DNS record type: '%s'", type_str);
        }
    }

    npe_dns_result_t result;
    int rc = npe_dns_query(hostname, qtype, nameserver, timeout_ms, &result);
    if (rc < 0) {
        npe_dns_result_free(&result);
        lua_pushnil(L);
        lua_pushfstring(L, "DNS query (%s) failed for '%s'",
                        type_str, hostname);
        return 2;
    }

    dns_push_result_lua(L, &result);
    npe_dns_result_free(&result);
    return 1;
}

/* -- npe.dns.get_default_nameserver() → string -- */
int
npe_dns_l_get_default_nameserver(lua_State *L)
{
    char ns[INET6_ADDRSTRLEN];
    get_default_nameserver(ns, sizeof(ns));
    lua_pushstring(L, ns);
    return 1;
}

/* -- npe.dns.type_name(type_number) → string -- */
int
npe_dns_l_type_name(lua_State *L)
{
    int t = (int)luaL_checkinteger(L, 1);
    const char *name = "UNKNOWN";
    switch (t) {
    case NPE_DNS_A:     name = "A";     break;
    case NPE_DNS_AAAA:  name = "AAAA";  break;
    case NPE_DNS_CNAME: name = "CNAME"; break;
    case NPE_DNS_MX:    name = "MX";    break;
    case NPE_DNS_NS:    name = "NS";    break;
    case NPE_DNS_PTR:   name = "PTR";   break;
    case NPE_DNS_SOA:   name = "SOA";   break;
    case NPE_DNS_SRV:   name = "SRV";   break;
    case NPE_DNS_TXT:   name = "TXT";   break;
    case DNS_TYPE_AXFR: name = "AXFR";  break;
    }
    lua_pushstring(L, name);
    return 1;
}

/* -- npe.dns.type_number(type_name_str) → integer -- */
int
npe_dns_l_type_number(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);

    struct { const char *n; uint16_t v; } map[] = {
        {"A",     NPE_DNS_A},     {"AAAA",  NPE_DNS_AAAA},
        {"CNAME", NPE_DNS_CNAME}, {"MX",    NPE_DNS_MX},
        {"NS",    NPE_DNS_NS},    {"PTR",   NPE_DNS_PTR},
        {"SOA",   NPE_DNS_SOA},   {"SRV",   NPE_DNS_SRV},
        {"TXT",   NPE_DNS_TXT},   {"AXFR",  DNS_TYPE_AXFR},
        {NULL, 0}
    };

    for (int i = 0; map[i].n; i++) {
        if (strcasecmp(name, map[i].n) == 0) {
            lua_pushinteger(L, map[i].v);
            return 1;
        }
    }

    lua_pushnil(L);
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Module Registration
 * ═══════════════════════════════════════════════════════════════════════════ */

static const luaL_Reg dns_funcs[] = {
    { "resolve",                npe_dns_l_resolve                },
    { "resolve6",               npe_dns_l_resolve6               },
    { "reverse",                npe_dns_l_reverse                },
    { "mx",                     npe_dns_l_mx                     },
    { "ns",                     npe_dns_l_ns                     },
    { "txt",                    npe_dns_l_txt                    },
    { "srv",                    npe_dns_l_srv                    },
    { "soa",                    npe_dns_l_soa                    },
    { "axfr",                   npe_dns_l_axfr                   },
    { "query",                  npe_dns_l_query                  },
    { "get_default_nameserver", npe_dns_l_get_default_nameserver },
    { "type_name",              npe_dns_l_type_name              },
    { "type_number",            npe_dns_l_type_number            },
    { NULL, NULL }
};

int
luaopen_npe_dns(lua_State *L)
{
    /* Seed the random number generator for transaction IDs. */
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    luaL_newlib(L, dns_funcs);

    /* Export record type constants. */
    lua_pushinteger(L, NPE_DNS_A);     lua_setfield(L, -2, "A");
    lua_pushinteger(L, NPE_DNS_AAAA);  lua_setfield(L, -2, "AAAA");
    lua_pushinteger(L, NPE_DNS_CNAME); lua_setfield(L, -2, "CNAME");
    lua_pushinteger(L, NPE_DNS_MX);    lua_setfield(L, -2, "MX");
    lua_pushinteger(L, NPE_DNS_NS);    lua_setfield(L, -2, "NS");
    lua_pushinteger(L, NPE_DNS_PTR);   lua_setfield(L, -2, "PTR");
    lua_pushinteger(L, NPE_DNS_SOA);   lua_setfield(L, -2, "SOA");
    lua_pushinteger(L, NPE_DNS_SRV);   lua_setfield(L, -2, "SRV");
    lua_pushinteger(L, NPE_DNS_TXT);   lua_setfield(L, -2, "TXT");
    lua_pushinteger(L, DNS_TYPE_AXFR); lua_setfield(L, -2, "AXFR");

    return 1;
}
