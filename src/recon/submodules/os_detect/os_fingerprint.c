/* ────────────────────────────────────────────────────────────────────────────
 *  src/os_detect/os_fingerprint.c – Active OS fingerprinting via TCP SYN
 *
 *  Part of NetPeek – lightweight network diagnostic toolkit
 * ──────────────────────────────────────────────────────────────────────────── */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <pcap/pcap.h>

#include "netpeek.h"
#include "recon/submodules/os_detect/os_detect.h"
#include "os_fingerprint_score.h"
#include "packet_parse.h"
#include "os_fingerprint.h"
#include "os_signatures.h"

/* ── Tunables ────────────────────────────────────────────────────────────── */

#define NP_SNAP_LEN          128
#define NP_PROMISC            0
#define NP_PCAP_TIMEOUT_MS   100
#define NP_DEFAULT_WAIT_SEC    5
#define NP_MAX_RETRIES         3
#define NP_MIN_CONFIDENCE     30

/*
 * Do NOT redefine NP_DLT_PKTAP here — it is already defined
 * in packet_parse.h (value 258).  Redefining it to 275 causes
 * a -Wmacro-redefined warning and uses the wrong value.
 */

/* ── Capture context (passed through pcap_dispatch) ──────────────────────── */

typedef struct {
    uint32_t            target_ip;
    uint16_t            target_port;
    int                 dlt;
    bool                verbose;
    bool                got_synack;
    np_os_fingerprint_t fp;
} capture_ctx_t;

/* ── Forward declarations ────────────────────────────────────────────────── */

static pcap_t *open_capture_device(const char *iface, bool verbose,
                                   char *errbuf);
static int     build_capture_filter(pcap_t *handle, uint32_t target_ip,
                                    uint16_t target_port, bool verbose);
static int     send_syn(uint32_t target_ip, uint16_t target_port,
                        bool verbose);
static void    packet_handler(u_char *user, const struct pcap_pkthdr *hdr,
                              const u_char *pkt);
static void    extract_tcp_options(const uint8_t *opt_ptr, uint32_t opt_len,
                                   np_os_fingerprint_t *fp);

/* ════════════════════════════════════════════════════════════════════════════
 *  Main fingerprinting entry point
 * ════════════════════════════════════════════════════════════════════════════ */

np_os_result_t np_os_fingerprint(const char *target_host,
                                 uint16_t    target_port,
                                 const char *iface,
                                 int         timeout_sec,
                                 bool        verbose,
                                 const np_os_fp_sig_t *sigs,
                                 uint32_t    sig_count)
{
    np_os_result_t result;
    memset(&result, 0, sizeof(result));
    snprintf(result.best_os,     sizeof(result.best_os),     "Unknown");
    snprintf(result.best_family, sizeof(result.best_family), "Unknown");
    result.best_confidence = 0.0;

    /* ── Resolve target to a network-order IPv4 address ── */

    struct in_addr target_addr;
    if (inet_pton(AF_INET, target_host, &target_addr) != 1) {
        if (verbose)
            np_error(NP_ERR_RUNTIME, "[netpeek] invalid target address: %s\n", target_host);
        return result;
    }

    if (timeout_sec <= 0)
        timeout_sec = NP_DEFAULT_WAIT_SEC;

    /* ── Open pcap capture ── */

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = open_capture_device(iface, verbose, errbuf);
    if (!handle)
        return result;

    int dlt = pcap_datalink(handle);

    if (build_capture_filter(handle, target_addr.s_addr,
                             target_port, verbose) < 0) {
        pcap_close(handle);
        return result;
    }

    /* ── Prepare capture context ── */

    capture_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.target_ip   = target_addr.s_addr;
    ctx.target_port = target_port;
    ctx.dlt         = dlt;
    ctx.verbose     = verbose;
    ctx.got_synack  = false;

    /* ── Send SYN probes and capture SYN-ACK ── */

    bool captured = false;

    for (int attempt = 0; attempt < NP_MAX_RETRIES && !captured; attempt++) {
        if (verbose)
            np_error(NP_ERR_RUNTIME, "[netpeek] SYN probe attempt %d/%d -> %s:%u\n",
                    attempt + 1, NP_MAX_RETRIES,
                    target_host, target_port);

        if (send_syn(target_addr.s_addr, target_port, verbose) < 0)
            continue;

        /* Poll for SYN-ACK */
        time_t deadline = time(NULL) + timeout_sec;
        while (!ctx.got_synack && time(NULL) < deadline) {
            int cnt = pcap_dispatch(handle, 1, packet_handler,
                                    (u_char *)&ctx);
            if (cnt < 0) {
                if (verbose)
                    np_error(NP_ERR_RUNTIME, "[netpeek] pcap_dispatch: %s\n",
                            pcap_geterr(handle));
                break;
            }
        }

        if (ctx.got_synack)
            captured = true;
    }

    pcap_close(handle);

    if (!captured) {
        if (verbose)
            np_error(NP_ERR_RUNTIME, "[netpeek] no SYN-ACK received after %d attempts\n",
                    NP_MAX_RETRIES);
        return result;
    }

    /* ── Store raw fingerprint in result ── */

    result.fingerprint = ctx.fp;
    result.fp_valid    = true;

    if (verbose) {
        np_error(NP_ERR_RUNTIME, "[netpeek] fingerprint captured: "
                "ttl=%u win=%u mss=%u df=%d sack=%d wscale=%d ts=%d "
                "opts_count=%u probes_responded=%u\n",
                ctx.fp.ttl,
                ctx.fp.window_size,
                ctx.fp.mss,
                ctx.fp.df_bit,
                ctx.fp.sack_permitted,
                ctx.fp.window_scale,
                ctx.fp.timestamp,
                ctx.fp.tcp_options_count,
                ctx.fp.probe_responded);
    }

    /* ── Match against signature database ── */

    if (sigs && sig_count > 0) {
        uint8_t  top_score    = 0;
        uint8_t  second_score = 0;
        int      top_idx      = -1;

        for (uint32_t i = 0; i < sig_count; i++) {
            /*
             * np_os_fp_score(fingerprint, signature) — correct order.
             * Returns uint8_t (0–100).
             */
            uint8_t score = np_os_fp_score(&ctx.fp, &sigs[i]);

            if (verbose && (i < 5 || score > 0)) {
                np_error(NP_ERR_RUNTIME, "[netpeek] sig[%u] os='%s' score=%u "
                        "(sig: ttl=%u win=%u mss=%u)\n",
                        i,
                        sigs[i].os_name ? sigs[i].os_name : "(null)",
                        score,
                        sigs[i].ttl,
                        sigs[i].window_size,
                        sigs[i].mss);
            }

            if (score > top_score) {
                second_score = top_score;
                top_score    = score;
                top_idx      = (int)i;
            } else if (score > second_score) {
                second_score = score;
            }
        }

        if (verbose) {
            np_error(NP_ERR_RUNTIME, "[netpeek] match result: top_score=%u second=%u "
                    "top_idx=%d sig_count=%u\n",
                    top_score, second_score, top_idx, sig_count);
        }

        if (top_idx >= 0 && top_score >= NP_MIN_CONFIDENCE) {
            snprintf(result.best_os, sizeof(result.best_os),
                     "%s", sigs[top_idx].os_name);
            snprintf(result.best_family, sizeof(result.best_family),
                     "%s", sigs[top_idx].os_family);

            /*
             * Confidence shaping: penalize when the gap between
             * best and runner-up is small (ambiguous match).
             */
            double confidence = (double)top_score;
            double delta = (double)(top_score - second_score);

            if (delta < 10.0)
                confidence *= 0.6;
            else if (delta < 25.0)
                confidence *= 0.8;

            if (confidence > 100.0)
                confidence = 100.0;

            result.best_confidence = confidence;

            if (verbose)
                np_error(NP_ERR_RUNTIME, "[netpeek] MATCH: os='%s' family='%s' "
                        "raw_score=%u delta=%u confidence=%.1f\n",
                        result.best_os,
                        result.best_family,
                        top_score,
                        top_score - second_score,
                        confidence);
        } else {
            if (verbose)
                np_error(NP_ERR_RUNTIME, "[netpeek] no match above threshold "
                        "(top_score=%u, min=%d)\n",
                        top_score, NP_MIN_CONFIDENCE);

            /*
             * Fallback: TTL heuristic when DB match fails
             */
            uint8_t norm_ttl = ctx.fp.ttl;
            if (norm_ttl <= 32)       norm_ttl = 32;
            else if (norm_ttl <= 64)  norm_ttl = 64;
            else if (norm_ttl <= 128) norm_ttl = 128;
            else                      norm_ttl = 255;

            const char *guess_os     = "Unknown";
            const char *guess_family = "Unknown";
            double      guess_conf   = 10.0;

            if (norm_ttl == 64) {
                if (ctx.fp.window_size >= 65535) {
                    guess_os     = "macOS / FreeBSD (heuristic)";
                    guess_family = "BSD";
                    guess_conf   = 20.0;
                } else {
                    guess_os     = "Linux (heuristic)";
                    guess_family = "Linux";
                    guess_conf   = 20.0;
                }
            } else if (norm_ttl == 128) {
                guess_os     = "Windows (heuristic)";
                guess_family = "Windows";
                guess_conf   = 20.0;
            } else if (norm_ttl == 255) {
                guess_os     = "Network Device (heuristic)";
                guess_family = "Embedded";
                guess_conf   = 15.0;
            }

            /* Only use heuristic if it beats current result */
            if (guess_conf > result.best_confidence) {
                snprintf(result.best_os, sizeof(result.best_os),
                         "%s", guess_os);
                snprintf(result.best_family, sizeof(result.best_family),
                         "%s", guess_family);
                result.best_confidence = guess_conf;
            }

            if (verbose)
                np_error(NP_ERR_RUNTIME, "[netpeek] TTL heuristic fallback: os='%s' "
                        "family='%s' conf=%.1f (norm_ttl=%u)\n",
                        result.best_os,
                        result.best_family,
                        result.best_confidence,
                        norm_ttl);
        }
    } else {
        if (verbose)
            np_error(NP_ERR_RUNTIME, "[netpeek] no signature database provided, "
                    "skipping match\n");

        /* No DB at all — pure TTL heuristic */
        uint8_t norm_ttl = ctx.fp.ttl;
        if (norm_ttl <= 32)       norm_ttl = 32;
        else if (norm_ttl <= 64)  norm_ttl = 64;
        else if (norm_ttl <= 128) norm_ttl = 128;
        else                      norm_ttl = 255;

        if (norm_ttl == 64) {
            if (ctx.fp.window_size >= 65535) {
                snprintf(result.best_os, sizeof(result.best_os),
                         "macOS / FreeBSD (heuristic)");
                snprintf(result.best_family, sizeof(result.best_family),
                         "BSD");
            } else {
                snprintf(result.best_os, sizeof(result.best_os),
                         "Linux (heuristic)");
                snprintf(result.best_family, sizeof(result.best_family),
                         "Linux");
            }
            result.best_confidence = 20.0;
        } else if (norm_ttl == 128) {
            snprintf(result.best_os, sizeof(result.best_os),
                     "Windows (heuristic)");
            snprintf(result.best_family, sizeof(result.best_family),
                     "Windows");
            result.best_confidence = 20.0;
        }
    }

    return result;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Pretty-print wrapper
 * ════════════════════════════════════════════════════════════════════════════ */

int np_os_fingerprint_print(const char *target_host,
                            uint16_t    target_port,
                            const char *iface,
                            int         timeout_sec,
                            bool        verbose,
                            const np_os_fp_sig_t *sigs,
                            uint32_t    sig_count)
{
    np_os_result_t r = np_os_fingerprint(
        target_host, target_port,
        iface, timeout_sec, verbose,
        sigs, sig_count
    );

    /*
     * No dedicated error field — treat zero confidence + zero TTL
     * as "nothing captured".
     */
    if (r.best_confidence == 0.0 && r.fingerprint.ttl == 0) {
        np_error(NP_ERR_RUNTIME, "[netpeek] error: fingerprinting failed\n");
        return -1;
    }

    /* ── Print result ── */

    printf("Target     : %s:%u\n",  target_host, target_port);
    printf("OS         : %s\n",     r.best_os);
    printf("Family     : %s\n",     r.best_family);
    printf("Confidence : %.0f%%\n", r.best_confidence);

    /* raw fingerprint */
    printf("\nFingerprint:\n");
    printf("  TTL        : %u\n",  r.fingerprint.ttl);
    printf("  Window     : %u\n",  r.fingerprint.window_size);
    printf("  MSS        : %u\n",  r.fingerprint.mss);
    printf("  DF         : %s\n",  r.fingerprint.df_bit ? "yes" : "no");
    printf("  Win Scale  : %u\n",  r.fingerprint.window_scale);
    printf("  SACK       : %s\n",  r.fingerprint.sack_permitted ? "yes" : "no");
    printf("  Timestamp  : %s\n",  r.fingerprint.timestamp ? "yes" : "no");
    printf("  Opt order  : %s\n",  (const char *)r.fingerprint.tcp_options_order);

    return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Internal helpers
 * ════════════════════════════════════════════════════════════════════════════ */

/* ── open_capture_device ─────────────────────────────────────────────────── */

static pcap_t *open_capture_device(const char *iface, bool verbose,
                                   char *errbuf)
{
    const char *dev = iface;

    if (!dev) {
        pcap_if_t *alldevs = NULL;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
            np_error(NP_ERR_RUNTIME, "[netpeek] pcap_findalldevs: %s\n", errbuf);
            return NULL;
        }
        dev = alldevs->name;
        if (verbose)
            np_error(NP_ERR_RUNTIME, "[netpeek] auto-selected interface: %s\n", dev);
    }

    pcap_t *handle = pcap_open_live(dev, NP_SNAP_LEN, NP_PROMISC,
                                    NP_PCAP_TIMEOUT_MS, errbuf);
    if (!handle) {
        np_error(NP_ERR_RUNTIME, "[netpeek] pcap_open_live(%s): %s\n", dev, errbuf);
    }

    return handle;
}

/* ── build_capture_filter ────────────────────────────────────────────────── */

static int build_capture_filter(pcap_t *handle, uint32_t target_ip,
                                uint16_t target_port, bool verbose)
{
    struct in_addr addr;
    addr.s_addr = target_ip;

    char filter_exp[256];
    snprintf(filter_exp, sizeof(filter_exp),
             "src host %s and src port %u and "
             "tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)",
             inet_ntoa(addr), target_port);

    if (verbose)
        np_error(NP_ERR_RUNTIME, "[netpeek] BPF filter: %s\n", filter_exp);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 1,
                     PCAP_NETMASK_UNKNOWN) == -1) {
        np_error(NP_ERR_RUNTIME, "[netpeek] pcap_compile: %s\n",
                pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        np_error(NP_ERR_RUNTIME, "[netpeek] pcap_setfilter: %s\n",
                pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }

    pcap_freecode(&fp);
    return 0;
}

/* ── send_syn ────────────────────────────────────────────────────────────── */

static int send_syn(uint32_t target_ip, uint16_t target_port,
                    bool verbose)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        if (verbose)
            np_error(NP_ERR_RUNTIME, "[netpeek] socket(): %s\n", strerror(errno));
        return -1;
    }

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = target_ip;
    dst.sin_port        = htons(target_port);

    /* connect sends SYN; we don't care about the result */
    connect(sock, (struct sockaddr *)&dst, sizeof(dst));
    close(sock);

    return 0;
}

/* ── extract_tcp_options ─────────────────────────────────────────────────── */

static void extract_tcp_options(const uint8_t *opt_ptr, uint32_t opt_len,
                                np_os_fingerprint_t *fp)
{
    /*
     * Build the option-order string in a local char buffer,
     * then copy into fp->tcp_options_order (which is uint8_t[16]).
     */
    char   order_buf[128];
    size_t order_off = 0;

    uint32_t i = 0;
    while (i < opt_len) {
        uint8_t kind = opt_ptr[i];

        if (kind == 0)                       /* End of options */
            break;

        if (kind == 1) {                     /* NOP */
            if (order_off < sizeof(order_buf) - 2)
                order_off += (size_t)snprintf(
                    order_buf + order_off,
                    sizeof(order_buf) - order_off, "N");
            ++i;
            continue;
        }

        if (i + 1 >= opt_len) break;
        uint8_t len = opt_ptr[i + 1];
        if (len < 2 || i + len > opt_len) break;

        switch (kind) {
        case 2:  /* MSS */
            if (len >= 4) {
                fp->mss = (uint16_t)(opt_ptr[i + 2] << 8 |
                                     opt_ptr[i + 3]);
                if (order_off < sizeof(order_buf) - 2)
                    order_off += (size_t)snprintf(
                        order_buf + order_off,
                        sizeof(order_buf) - order_off, "M");
            }
            break;
        case 3:  /* Window Scale */
            if (len >= 3) {
                fp->window_scale = opt_ptr[i + 2];
                if (order_off < sizeof(order_buf) - 2)
                    order_off += (size_t)snprintf(
                        order_buf + order_off,
                        sizeof(order_buf) - order_off, "W");
            }
            break;
        case 4:  /* SACK Permitted */
            fp->sack_permitted = true;
            if (order_off < sizeof(order_buf) - 2)
                order_off += (size_t)snprintf(
                    order_buf + order_off,
                    sizeof(order_buf) - order_off, "S");
            break;
        case 8:  /* Timestamp */
            fp->timestamp = true;
            if (order_off < sizeof(order_buf) - 2)
                order_off += (size_t)snprintf(
                    order_buf + order_off,
                    sizeof(order_buf) - order_off, "T");
            break;
        default:
            if (order_off < sizeof(order_buf) - 4)
                order_off += (size_t)snprintf(
                    order_buf + order_off,
                    sizeof(order_buf) - order_off, "?%u", kind);
            break;
        }

        i += len;
    }

    order_buf[order_off] = '\0';

    /*
     * Copy into the uint8_t array via memcpy to avoid the
     * -Wpointer-sign warning from snprintf(uint8_t*, ...).
     */
    size_t copy_len = order_off + 1; /* include NUL */
    if (copy_len > sizeof(fp->tcp_options_order))
        copy_len = sizeof(fp->tcp_options_order);
    memcpy(fp->tcp_options_order, order_buf, copy_len);
    fp->tcp_options_order[sizeof(fp->tcp_options_order) - 1] = '\0';
}

/* ── packet_handler (pcap callback) ──────────────────────────────────────── */

static void packet_handler(u_char *user,
                           const struct pcap_pkthdr *hdr,
                           const u_char *pkt)
{
    capture_ctx_t *ctx = (capture_ctx_t *)user;

    if (ctx->got_synack)
        return;

    /* ── Determine link-layer header length ── */

    uint32_t link_hdr_len = 0;

    if (ctx->dlt == NP_DLT_PKTAP) {
        /* PKTAP: first 4 bytes = header length (little-endian) */
        if (hdr->caplen < 4) return;
        link_hdr_len = (uint32_t)pkt[0]       |
                       (uint32_t)pkt[1] << 8   |
                       (uint32_t)pkt[2] << 16  |
                       (uint32_t)pkt[3] << 24;
        if (link_hdr_len > hdr->caplen) return;
    } else {
        np_parse_error_t perr = np_link_header_len(ctx->dlt,
                                                   &link_hdr_len);
        if (perr != NP_PARSE_OK) return;
    }

    if (hdr->caplen < link_hdr_len + 20)      /* min IP header */
        return;

    /* ── IP header ── */

    const uint8_t *ip_raw = pkt + link_hdr_len;
    uint8_t  ip_ver   = (ip_raw[0] >> 4) & 0x0F;
    if (ip_ver != 4) return;

    uint8_t  ip_ihl   = (ip_raw[0] & 0x0F) * 4u;
    uint8_t  ip_ttl   = ip_raw[8];
    uint8_t  ip_proto = ip_raw[9];
    bool     df_bit   = (ip_raw[6] & 0x40) != 0;

    if (ip_proto != IPPROTO_TCP) return;
    if (hdr->caplen < link_hdr_len + ip_ihl + 20)
        return;

    /* ── TCP header ── */

    const uint8_t *tcp_raw = ip_raw + ip_ihl;
    uint16_t src_port = (uint16_t)(tcp_raw[0] << 8 | tcp_raw[1]);
    uint8_t  tcp_off  = ((tcp_raw[12] >> 4) & 0x0F) * 4u;
    uint8_t  flags    = tcp_raw[13];
    uint16_t window   = (uint16_t)(tcp_raw[14] << 8 | tcp_raw[15]);

    /* Must be SYN+ACK */
    if ((flags & 0x12) != 0x12) return;

    /* ── Fill fingerprint ── */

    ctx->fp.ttl         = ip_ttl;
    ctx->fp.window_size = window;
    ctx->fp.df_bit      = df_bit;

    /* TCP options */
    if (tcp_off > 20) {
        uint32_t opt_len = tcp_off - 20;
        if (hdr->caplen >= link_hdr_len + ip_ihl + tcp_off)
            extract_tcp_options(tcp_raw + 20, opt_len, &ctx->fp);
    }

    ctx->got_synack = true;

    if (ctx->verbose) {
        struct in_addr sa;
        sa.s_addr = ctx->target_ip;
        np_error(NP_ERR_RUNTIME, "[netpeek] SYN-ACK from %s:%u  TTL=%u Win=%u\n",
                inet_ntoa(sa), src_port, ip_ttl, window);
    }
}
