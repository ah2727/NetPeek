/*
 * NetPeek - Cross-Platform Packet Parser
 *
 * Stateless, thread-safe packet parsing for libpcap captures.
 * Handles multiple link-layer types across Linux, macOS, and BSD.
 */

#include "packet_parse.h"
#include "core/error.h"
#include "recon/submodules/os_detect/os_detect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* ── Error strings ───────────────────────────────────── */

static const char *parse_error_strings[] = {
    [NP_PARSE_OK]              = "OK",
    [NP_PARSE_ERR_NULL]        = "NULL input",
    [NP_PARSE_ERR_TOO_SHORT]   = "Packet too short",
    [NP_PARSE_ERR_NOT_IPV4]    = "Not an IPv4 packet",
    [NP_PARSE_ERR_NOT_TCP]     = "Not a TCP packet",
    [NP_PARSE_ERR_BAD_IHL]     = "Invalid IP header length",
    [NP_PARSE_ERR_BAD_DOFF]    = "Invalid TCP data offset",
    [NP_PARSE_ERR_TRUNCATED]   = "Packet truncated",
    [NP_PARSE_ERR_UNKNOWN_DLT] = "Unknown link-layer type",
};

const char *np_parse_strerror(np_parse_error_t err)
{
    if (err >= 0 && (size_t)err < sizeof(parse_error_strings) /
                                  sizeof(parse_error_strings[0]))
    {
        return parse_error_strings[err];
    }
    return "Unknown error";
}

/* ── Link-layer header sizes ─────────────────────────── */

/*
 * PKTAP (macOS) has a variable-length header.
 * The first 4 bytes contain the header length as a uint32.
 * We handle this specially in np_link_header_len_pktap().
 */

np_parse_error_t np_link_header_len(int dlt_type,
                                    uint32_t *out_len)
{
    if (!out_len)
        return NP_PARSE_ERR_NULL;

    switch (dlt_type) {

    case NP_DLT_EN10MB:
        /* Ethernet: 6 dst + 6 src + 2 ethertype = 14 */
        *out_len = 14;
        return NP_PARSE_OK;

    case NP_DLT_NULL:
    case NP_DLT_LOOP:
        /* BSD/OpenBSD loopback: 4-byte protocol family */
        *out_len = 4;
        return NP_PARSE_OK;

    case NP_DLT_RAW:
        /* Raw IP: no link header */
        *out_len = 0;
        return NP_PARSE_OK;

    case NP_DLT_LINUX_SLL:
        /* Linux cooked capture v1: 16 bytes */
        *out_len = 16;
        return NP_PARSE_OK;

    case NP_DLT_PKTAP:
        /*
         * macOS PKTAP: variable length.
         * We return 0 here; the caller must read the
         * actual length from the first 4 bytes of the packet.
         * See np_pktap_header_len().
         */
        *out_len = 0;
        return NP_PARSE_OK;

    default:
        *out_len = 0;
        return NP_PARSE_ERR_UNKNOWN_DLT;
    }
}

/* ── PKTAP header length (macOS) ─────────────────────── */
/*
 * PKTAP header structure (simplified):
 *   offset 0: uint32_t pth_length  (total header length)
 *
 * The header is variable-length and includes interface name,
 * process info, etc. We only need pth_length to skip it.
 */
static uint32_t np_pktap_header_len(const uint8_t *raw,
                                    uint32_t cap_len)
{
    if (cap_len < 4)
        return 0;

    /* pth_length is at offset 0, host byte order on macOS */
    uint32_t pth_len;
    memcpy(&pth_len, raw, sizeof(pth_len));

    /* sanity check */
    if (pth_len < 4 || pth_len > cap_len)
        return 0;

    return pth_len;
}

/* ── Determine actual link header length ─────────────── */
/*
 * For most DLT types this is a fixed value.
 * For PKTAP we read it from the packet itself.
 */
static np_parse_error_t get_link_offset(int dlt_type,
                                        const uint8_t *raw,
                                        uint32_t cap_len,
                                        uint32_t *out_offset)
{
    if (dlt_type == NP_DLT_PKTAP) {
        uint32_t pktap_len = np_pktap_header_len(raw, cap_len);
        if (pktap_len == 0)
            return NP_PARSE_ERR_TRUNCATED;

        *out_offset = pktap_len;
        return NP_PARSE_OK;
    }

    return np_link_header_len(dlt_type, out_offset);
}

/* ── Validate link-layer protocol ────────────────────── */
/*
 * For Ethernet: check ethertype == 0x0800 (IPv4)
 * For BSD loopback: check family == AF_INET (2)
 * For Linux SLL: check protocol == 0x0800
 * For RAW/PKTAP: assume IPv4 (check version in IP parser)
 */
static bool validate_link_protocol(int dlt_type,
                                   const uint8_t *raw,
                                   uint32_t link_len)
{
    switch (dlt_type) {

    case NP_DLT_EN10MB:
        if (link_len < 14) return false;
        /* ethertype at offset 12, big-endian */
        return (raw[12] == 0x08 && raw[13] == 0x00);

    case NP_DLT_NULL:
    case NP_DLT_LOOP: {
        if (link_len < 4) return false;
        /* 4-byte host-order protocol family */
        uint32_t family;
        memcpy(&family, raw, sizeof(family));
        /* AF_INET = 2 on all platforms we care about */
        return (family == 2);
    }

    case NP_DLT_LINUX_SLL:
        if (link_len < 16) return false;
        /* protocol at offset 14, big-endian */
        return (raw[14] == 0x08 && raw[15] == 0x00);

    case NP_DLT_RAW:
    case NP_DLT_PKTAP:
        /* check IP version in the IP parser */
        return true;

    default:
        return false;
    }
}

/* ── IPv4 parser ─────────────────────────────────────── */

np_parse_error_t np_parse_ipv4(const uint8_t    *data,
                               uint32_t          data_len,
                               np_ipv4_header_t *out)
{
    if (!data || !out)
        return NP_PARSE_ERR_NULL;

    memset(out, 0, sizeof(*out));

    /* minimum IPv4 header: 20 bytes */
    if (data_len < 20)
        return NP_PARSE_ERR_TOO_SHORT;

    /* version + IHL */
    out->version   = (data[0] >> 4) & 0x0F;
    out->ihl       = data[0] & 0x0F;
    out->ihl_bytes = out->ihl * 4;

    if (out->version != 4)
        return NP_PARSE_ERR_NOT_IPV4;

    if (out->ihl < 5)
        return NP_PARSE_ERR_BAD_IHL;

    if (out->ihl_bytes > data_len)
        return NP_PARSE_ERR_TRUNCATED;

    /* TOS */
    out->tos = data[1];

    /* total length */
    out->total_length = ((uint16_t)data[2] << 8) | data[3];

    /* identification */
    out->identification = ((uint16_t)data[4] << 8) | data[5];

    /* flags + fragment offset */
    uint16_t flags_frag = ((uint16_t)data[6] << 8) | data[7];
    out->df          = (flags_frag & 0x4000) ? true : false;
    out->mf          = (flags_frag & 0x2000) ? true : false;
    out->frag_offset = flags_frag & 0x1FFF;

    /* TTL */
    out->ttl = data[8];

    /* protocol */
    out->protocol = data[9];

    /* checksum */
    out->checksum = ((uint16_t)data[10] << 8) | data[11];

    /* source address */
    memcpy(&out->src_addr, data + 12, 4);
    inet_ntop(AF_INET, &out->src_addr,
              out->src_str, sizeof(out->src_str));

    /* destination address */
    memcpy(&out->dst_addr, data + 16, 4);
    inet_ntop(AF_INET, &out->dst_addr,
              out->dst_str, sizeof(out->dst_str));

    /* raw pointer */
    out->raw     = data;
    out->raw_len = out->ihl_bytes;

    return NP_PARSE_OK;
}

/* ── TCP options parser ──────────────────────────────── */

np_parse_error_t np_parse_tcp_options(const uint8_t   *opts_data,
                                      uint32_t         opts_len,
                                      np_tcp_option_t *out_opts,
                                      uint8_t          max_opts,
                                      uint8_t         *out_count,
                                      char            *out_order)
{
    if (!opts_data || !out_opts || !out_count || !out_order)
        return NP_PARSE_ERR_NULL;

    *out_count = 0;
    out_order[0] = '\0';

    uint32_t i = 0;
    int      oidx = 0;

    while (i < opts_len && *out_count < max_opts) {

        uint8_t kind = opts_data[i];

        /* End of Option List */
        if (kind == NP_TCPOPT_EOL)
            break;

        /* NOP */
        if (kind == NP_TCPOPT_NOP) {
            if (oidx < max_opts)
                out_order[oidx++] = 'N';
            i++;
            continue;
        }

        /* all other options: kind(1) + length(1) + data */
        if (i + 1 >= opts_len)
            break;

        uint8_t olen = opts_data[i + 1];

        if (olen < 2 || i + olen > opts_len)
            break;

        np_tcp_option_t *opt = &out_opts[*out_count];
        memset(opt, 0, sizeof(*opt));

        opt->kind   = kind;
        opt->length = olen;

        switch (kind) {

        case NP_TCPOPT_MSS:
            if (olen >= 4) {
                opt->data.mss = ((uint16_t)opts_data[i+2] << 8) |
                                opts_data[i+3];
                if (oidx < max_opts)
                    out_order[oidx++] = 'M';
            }
            break;

        case NP_TCPOPT_WSCALE:
            if (olen >= 3) {
                opt->data.wscale = opts_data[i+2];
                if (oidx < max_opts)
                    out_order[oidx++] = 'W';
            }
            break;

        case NP_TCPOPT_SACKOK:
            if (oidx < max_opts)
                out_order[oidx++] = 'S';
            break;

        case NP_TCPOPT_TIMESTAMP:
            if (olen >= 10) {
                opt->data.timestamp.tsval =
                    ((uint32_t)opts_data[i+2] << 24) |
                    ((uint32_t)opts_data[i+3] << 16) |
                    ((uint32_t)opts_data[i+4] << 8)  |
                    opts_data[i+5];

                opt->data.timestamp.tsecr =
                    ((uint32_t)opts_data[i+6] << 24) |
                    ((uint32_t)opts_data[i+7] << 16) |
                    ((uint32_t)opts_data[i+8] << 8)  |
                    opts_data[i+9];

                if (oidx < max_opts)
                    out_order[oidx++] = 'T';
            }
            break;

        default:
            /* unknown option: copy raw data */
            if (olen > 2) {
                uint8_t copy_len = olen - 2;
                if (copy_len > sizeof(opt->data.raw))
                    copy_len = sizeof(opt->data.raw);
                memcpy(opt->data.raw, opts_data + i + 2,
                       copy_len);
            }
            break;
        }

        (*out_count)++;
        i += olen;
    }

    out_order[oidx] = '\0';

    return NP_PARSE_OK;
}

/* ── TCP header parser ───────────────────────────────── */

np_parse_error_t np_parse_tcp(const uint8_t   *data,
                              uint32_t         data_len,
                              np_tcp_header_t *out)
{
    if (!data || !out)
        return NP_PARSE_ERR_NULL;

    memset(out, 0, sizeof(*out));

    /* minimum TCP header: 20 bytes */
    if (data_len < 20)
        return NP_PARSE_ERR_TOO_SHORT;

    /* source port */
    out->src_port = ((uint16_t)data[0] << 8) | data[1];

    /* destination port */
    out->dst_port = ((uint16_t)data[2] << 8) | data[3];

    /* sequence number */
    out->seq = ((uint32_t)data[4]  << 24) |
               ((uint32_t)data[5]  << 16) |
               ((uint32_t)data[6]  << 8)  |
               data[7];

    /* acknowledgment number */
    out->ack = ((uint32_t)data[8]  << 24) |
               ((uint32_t)data[9]  << 16) |
               ((uint32_t)data[10] << 8)  |
               data[11];

    /* data offset (header length) */
    out->data_offset       = (data[12] >> 4) & 0x0F;
    out->data_offset_bytes = out->data_offset * 4;

    if (out->data_offset < 5)
        return NP_PARSE_ERR_BAD_DOFF;

    if (out->data_offset_bytes > data_len)
        return NP_PARSE_ERR_TRUNCATED;

    /* flags */
    out->flags = data[13];

    out->flag_fin = (out->flags & NP_TCP_FIN) ? true : false;
    out->flag_syn = (out->flags & NP_TCP_SYN) ? true : false;
    out->flag_rst = (out->flags & NP_TCP_RST) ? true : false;
    out->flag_psh = (out->flags & NP_TCP_PSH) ? true : false;
    out->flag_ack = (out->flags & NP_TCP_ACK) ? true : false;
    out->flag_urg = (out->flags & NP_TCP_URG) ? true : false;
    out->flag_ece = (out->flags & NP_TCP_ECE) ? true : false;
    out->flag_cwr = (out->flags & NP_TCP_CWR) ? true : false;

    /* window size */
    out->window = ((uint16_t)data[14] << 8) | data[15];

    /* checksum */
    out->checksum = ((uint16_t)data[16] << 8) | data[17];

    /* urgent pointer */
    out->urgent_ptr = ((uint16_t)data[18] << 8) | data[19];

    /* raw pointer */
    out->raw     = data;
    out->raw_len = out->data_offset_bytes;

    /* ── Parse TCP options ── */

    if (out->data_offset_bytes > 20) {

        uint32_t opts_len = out->data_offset_bytes - 20;
        const uint8_t *opts_start = data + 20;

        np_parse_tcp_options(opts_start, opts_len,
                             out->options,
                             NP_MAX_TCP_OPTIONS,
                             &out->option_count,
                             out->option_order);

        /* extract quick-access values from parsed options */
        for (uint8_t j = 0; j < out->option_count; j++) {

            np_tcp_option_t *opt = &out->options[j];

            switch (opt->kind) {

            case NP_TCPOPT_MSS:
                out->mss = opt->data.mss;
                break;

            case NP_TCPOPT_WSCALE:
                out->wscale = opt->data.wscale;
                break;

            case NP_TCPOPT_SACKOK:
                out->sack_permitted = true;
                break;

            case NP_TCPOPT_TIMESTAMP:
                out->has_timestamp = true;
                out->ts_val = opt->data.timestamp.tsval;
                out->ts_ecr = opt->data.timestamp.tsecr;
                break;

            default:
                break;
            }
        }
    }

    return NP_PARSE_OK;
}

/* ── Full packet parser ──────────────────────────────── */

np_parse_error_t np_parse_packet(const uint8_t      *raw_packet,
                                 uint32_t            cap_len,
                                 uint32_t            wire_len,
                                 int                 dlt_type,
                                 np_parsed_packet_t *out)
{
    if (!raw_packet || !out)
        return NP_PARSE_ERR_NULL;

    memset(out, 0, sizeof(*out));

    out->raw_packet  = raw_packet;
    out->raw_length  = cap_len;
    out->wire_length = wire_len;
    out->dlt_type    = dlt_type;

    /* ── Step 1: determine link-layer offset ── */

    uint32_t link_offset = 0;
    np_parse_error_t rc = get_link_offset(dlt_type, raw_packet,
                                          cap_len, &link_offset);
    if (rc != NP_PARSE_OK)
        return rc;

    out->link_hdr_len = link_offset;

    /* verify we have enough data */
    if (cap_len < link_offset + 20)
        return NP_PARSE_ERR_TOO_SHORT;

    /* ── Step 2: validate link-layer protocol ── */

    if (!validate_link_protocol(dlt_type, raw_packet, link_offset)) {
        /*
         * For RAW and PKTAP we skip this check and
         * rely on IP version validation below.
         */
        if (dlt_type != NP_DLT_RAW && dlt_type != NP_DLT_PKTAP)
            return NP_PARSE_ERR_NOT_IPV4;
    }

    /* ── Step 3: parse IPv4 header ── */

    const uint8_t *ip_start = raw_packet + link_offset;
    uint32_t       ip_avail = cap_len - link_offset;

    rc = np_parse_ipv4(ip_start, ip_avail, &out->ip);
    if (rc != NP_PARSE_OK)
        return rc;

    out->has_ip = true;

    /* ── Step 4: check for TCP ── */

    if (out->ip.protocol != NP_IPPROTO_TCP)
        return NP_PARSE_ERR_NOT_TCP;

    /* ── Step 5: parse TCP header ── */

    const uint8_t *tcp_start = ip_start + out->ip.ihl_bytes;
    uint32_t       tcp_avail = ip_avail - out->ip.ihl_bytes;

    if (tcp_avail < 20)
        return NP_PARSE_ERR_TRUNCATED;

    rc = np_parse_tcp(tcp_start, tcp_avail, &out->tcp);
    if (rc != NP_PARSE_OK)
        return rc;

    out->has_tcp = true;

    /* ── Step 6: set convenience flags ── */

    out->is_syn    = out->tcp.flag_syn && !out->tcp.flag_ack;
    out->is_synack = out->tcp.flag_syn && out->tcp.flag_ack;
    out->is_rst    = out->tcp.flag_rst;

    return NP_PARSE_OK;
}

/* ── Extract fingerprint from parsed SYN-ACK ─────────── */

np_parse_error_t np_extract_fingerprint(
        const np_parsed_packet_t *pkt,
        void                     *fp_ptr)
{
    if (!pkt || !fp_ptr)
        return NP_PARSE_ERR_NULL;

    np_os_fingerprint_t *fp = (np_os_fingerprint_t *)fp_ptr;
    memset(fp, 0, sizeof(*fp));

    if (!pkt->has_ip || !pkt->has_tcp)
        return NP_PARSE_ERR_NOT_TCP;

    /* IP fields */
    fp->ttl          = pkt->ip.ttl;
    fp->df_bit       = pkt->ip.df;
    fp->total_length = pkt->ip.total_length;

    /* TCP fields */
    fp->window_size    = pkt->tcp.window;
    fp->mss            = pkt->tcp.mss;
    fp->window_scale   = pkt->tcp.wscale;
    fp->sack_permitted = pkt->tcp.sack_permitted;
    fp->timestamp      = pkt->tcp.has_timestamp;

    /* TCP option order */
    size_t order_len = strlen(pkt->tcp.option_order);
    if (order_len > sizeof(fp->tcp_options_order) - 1)
        order_len = sizeof(fp->tcp_options_order) - 1;

    memcpy(fp->tcp_options_order, pkt->tcp.option_order,
           order_len);
    fp->tcp_options_order[order_len] = '\0';
    fp->tcp_options_count = pkt->tcp.option_count;

    return NP_PARSE_OK;
}

/* ── SYN-ACK source validation ───────────────────────── */

bool np_is_synack_from(const np_parsed_packet_t *pkt,
                       uint32_t src_ip,
                       uint16_t src_port)
{
    if (!pkt || !pkt->is_synack)
        return false;

    if (pkt->ip.src_addr != src_ip)
        return false;

    if (pkt->tcp.src_port != src_port)
        return false;

    return true;
}

/* ── Debug: print parsed packet ──────────────────────── */

void np_parsed_packet_print(const np_parsed_packet_t *pkt)
{
    if (!pkt) return;

    np_error(NP_ERR_RUNTIME, "\n=== Parsed Packet ===\n");
    np_error(NP_ERR_RUNTIME, "DLT type   : %d\n", pkt->dlt_type);
    np_error(NP_ERR_RUNTIME, "Link hdr   : %u bytes\n", pkt->link_hdr_len);
    np_error(NP_ERR_RUNTIME, "Cap length : %u bytes\n", pkt->raw_length);
    np_error(NP_ERR_RUNTIME, "Wire length: %u bytes\n", pkt->wire_length);

    if (pkt->has_ip) {
        np_error(NP_ERR_RUNTIME, "\n--- IPv4 Header ---\n");
        np_error(NP_ERR_RUNTIME, "Version    : %u\n", pkt->ip.version);
        np_error(NP_ERR_RUNTIME, "IHL        : %u (%u bytes)\n",
                pkt->ip.ihl, pkt->ip.ihl_bytes);
        np_error(NP_ERR_RUNTIME, "TOS        : 0x%02X\n", pkt->ip.tos);
        np_error(NP_ERR_RUNTIME, "Total len  : %u\n", pkt->ip.total_length);
        np_error(NP_ERR_RUNTIME, "IP ID      : 0x%04X\n",
                pkt->ip.identification);
        np_error(NP_ERR_RUNTIME, "DF         : %s\n",
                pkt->ip.df ? "yes" : "no");
        np_error(NP_ERR_RUNTIME, "MF         : %s\n",
                pkt->ip.mf ? "yes" : "no");
        np_error(NP_ERR_RUNTIME, "Frag off   : %u\n", pkt->ip.frag_offset);
        np_error(NP_ERR_RUNTIME, "TTL        : %u\n", pkt->ip.ttl);
        np_error(NP_ERR_RUNTIME, "Protocol   : %u\n", pkt->ip.protocol);
        np_error(NP_ERR_RUNTIME, "Src        : %s\n", pkt->ip.src_str);
        np_error(NP_ERR_RUNTIME, "Dst        : %s\n", pkt->ip.dst_str);
    }

    if (pkt->has_tcp) {
        np_error(NP_ERR_RUNTIME, "\n--- TCP Header ---\n");
        np_error(NP_ERR_RUNTIME, "Src port   : %u\n", pkt->tcp.src_port);
        np_error(NP_ERR_RUNTIME, "Dst port   : %u\n", pkt->tcp.dst_port);
        np_error(NP_ERR_RUNTIME, "Seq        : %u\n", pkt->tcp.seq);
        np_error(NP_ERR_RUNTIME, "Ack        : %u\n", pkt->tcp.ack);
        np_error(NP_ERR_RUNTIME, "Data off   : %u (%u bytes)\n",
                pkt->tcp.data_offset,
                pkt->tcp.data_offset_bytes);
        np_error(NP_ERR_RUNTIME, "Flags      : %s%s%s%s%s%s%s%s\n",
                pkt->tcp.flag_syn ? "SYN " : "",
                pkt->tcp.flag_ack ? "ACK " : "",
                pkt->tcp.flag_rst ? "RST " : "",
                pkt->tcp.flag_fin ? "FIN " : "",
                pkt->tcp.flag_psh ? "PSH " : "",
                pkt->tcp.flag_urg ? "URG " : "",
                pkt->tcp.flag_ece ? "ECE " : "",
                pkt->tcp.flag_cwr ? "CWR " : "");
        np_error(NP_ERR_RUNTIME, "Window     : %u\n", pkt->tcp.window);
        np_error(NP_ERR_RUNTIME, "MSS        : %u\n", pkt->tcp.mss);
        np_error(NP_ERR_RUNTIME, "WScale     : %u\n", pkt->tcp.wscale);
        np_error(NP_ERR_RUNTIME, "SACK ok    : %s\n",
                pkt->tcp.sack_permitted ? "yes" : "no");
        np_error(NP_ERR_RUNTIME, "Timestamp  : %s",
                pkt->tcp.has_timestamp ? "yes" : "no");
        if (pkt->tcp.has_timestamp) {
            np_error(NP_ERR_RUNTIME, " (val=%u ecr=%u)",
                    pkt->tcp.ts_val, pkt->tcp.ts_ecr);
        }
        np_error(NP_ERR_RUNTIME, "\n");
        np_error(NP_ERR_RUNTIME, "Opt order  : %s\n",
                pkt->tcp.option_order);
        np_error(NP_ERR_RUNTIME, "Opt count  : %u\n",
                pkt->tcp.option_count);

        /* packet type */
        np_error(NP_ERR_RUNTIME, "Type       : ");
        if (pkt->is_synack)
            np_error(NP_ERR_RUNTIME, "SYN-ACK\n");
        else if (pkt->is_syn)
            np_error(NP_ERR_RUNTIME, "SYN\n");
        else if (pkt->is_rst)
            np_error(NP_ERR_RUNTIME, "RST\n");
        else
            np_error(NP_ERR_RUNTIME, "other\n");
    }
}

/* ── Debug: print TCP options detail ─────────────────── */

void np_tcp_options_print(const np_tcp_header_t *tcp)
{
    if (!tcp) return;

    np_error(NP_ERR_RUNTIME, "\n--- TCP Options (%u) ---\n",
            tcp->option_count);

    for (uint8_t i = 0; i < tcp->option_count; i++) {

        const np_tcp_option_t *opt = &tcp->options[i];

        switch (opt->kind) {

        case NP_TCPOPT_MSS:
            np_error(NP_ERR_RUNTIME, "  [%u] MSS = %u\n",
                    i, opt->data.mss);
            break;

        case NP_TCPOPT_WSCALE:
            np_error(NP_ERR_RUNTIME, "  [%u] Window Scale = %u\n",
                    i, opt->data.wscale);
            break;

        case NP_TCPOPT_SACKOK:
            np_error(NP_ERR_RUNTIME, "  [%u] SACK Permitted\n", i);
            break;

        case NP_TCPOPT_TIMESTAMP:
            np_error(NP_ERR_RUNTIME, "  [%u] Timestamp val=%u ecr=%u\n",
                i,
                opt->data.timestamp.tsval,
                opt->data.timestamp.tsecr);
            break;

        default:
            np_error(NP_ERR_RUNTIME, "  [%u] Kind=%u Len=%u\n",
                    i, opt->kind, opt->length);
            break;
        }
    }

    np_error(NP_ERR_RUNTIME, "  Order: %s\n", tcp->option_order);
}