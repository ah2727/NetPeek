#define _DEFAULT_SOURCE

#include "tcp_fp.h"
#include "os_udp_probes.h"

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static uint32_t gcd_u32(uint32_t a, uint32_t b)
{
    while (b != 0) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

uint8_t np_tcp_fp_infer_initial_ttl(uint8_t observed_ttl)
{
    static const uint8_t buckets[] = {32, 64, 128, 255};
    for (size_t i = 0; i < sizeof(buckets); i++)
        if (observed_ttl <= buckets[i])
            return buckets[i];
    return 255;
}

static void compute_seq_metrics(const uint32_t *seqs,
                                uint8_t seq_count,
                                np_seq_metrics_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!seqs || seq_count < 2)
        return;

    uint32_t diffs[6] = {0};
    uint8_t dcount = 0;
    bool monotonic = true;

    for (uint8_t i = 1; i < seq_count; i++) {
        uint32_t d = seqs[i] - seqs[i - 1];
        if (seqs[i] < seqs[i - 1])
            monotonic = false;
        diffs[dcount++] = d;
    }

    uint32_t g = diffs[0];
    uint64_t sum = 0;
    uint32_t min_d = diffs[0];
    uint32_t max_d = diffs[0];

    for (uint8_t i = 0; i < dcount; i++) {
        g = gcd_u32(g, diffs[i]);
        sum += diffs[i];
        if (diffs[i] < min_d)
            min_d = diffs[i];
        if (diffs[i] > max_d)
            max_d = diffs[i];
    }

    uint32_t avg = (uint32_t)(sum / dcount);
    uint32_t isr = avg * 10;
    uint32_t spread = max_d - min_d;

    out->samples = seq_count;
    out->gcd = g;
    out->isr = isr;
    out->sp = spread;

    if (max_d == 0) {
        out->cls = NP_SEQ_CLASS_CONSTANT;
    } else if (monotonic && g <= 8 && isr > 0 && spread < (avg + 1)) {
        out->cls = NP_SEQ_CLASS_INCREMENTAL;
    } else if (g > 0 && (isr / g) < 3) {
        out->cls = NP_SEQ_CLASS_BROKEN_LITTLE_ENDIAN;
    } else {
        out->cls = NP_SEQ_CLASS_RANDOMIZED;
    }
}

static uint8_t classify_ipid(const np_tcp_probe_set_t *set)
{
    uint16_t ids[NP_MAX_TCP_PROBES];
    uint8_t n = 0;

    for (int i = 0; i < NP_MAX_TCP_PROBES; i++) {
        if (!set->probes[i].responded)
            continue;
        ids[n++] = set->probes[i].ip_id;
    }

    if (n < 2)
        return 0;

    bool all_zero = true;
    int64_t delta_sum = 0;
    uint32_t jumpy = 0;

    for (uint8_t i = 1; i < n; i++) {
        if (ids[i] != 0 || ids[i - 1] != 0)
            all_zero = false;
        int32_t d = (int32_t)ids[i] - (int32_t)ids[i - 1];
        if (d < 0)
            d += 65536;
        delta_sum += d;
        if (d > 2000)
            jumpy++;
    }

    if (all_zero)
        return 2;

    uint32_t avg = (uint32_t)(delta_sum / (n - 1));
    if (jumpy == 0 && avg > 0 && avg < 1500)
        return 1;

    return 3;
}

static uint16_t csum16(const void *buf, size_t len)
{
    const uint16_t *w = (const uint16_t *)buf;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *w++;
        len -= 2;
    }
    if (len)
        sum += *(const uint8_t *)w;
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static void run_ie_probe(const np_tcp_fp_cfg_t *cfg,
                         uint8_t tos,
                         uint8_t code,
                         uint16_t ident,
                         np_icmp_reply_t *out)
{
    memset(out, 0, sizeof(*out));

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0)
        return;

    (void)setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    uint8_t pkt[64];
    memset(pkt, 0, sizeof(pkt));

#ifdef __linux__
    struct icmphdr *icmp = (struct icmphdr *)pkt;
    icmp->type = ICMP_ECHO;
    icmp->code = code;
    icmp->un.echo.id = htons(ident);
    icmp->un.echo.sequence = htons((uint16_t)(0x100 + tos));
    icmp->checksum = csum16(pkt, sizeof(struct icmphdr) + 16);
    size_t send_len = sizeof(struct icmphdr) + 16;
#else
    struct icmp *icmp = (struct icmp *)pkt;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = code;
    icmp->icmp_id = htons(ident);
    icmp->icmp_seq = htons((uint16_t)(0x100 + tos));
    icmp->icmp_cksum = csum16(pkt, ICMP_MINLEN + 16);
    size_t send_len = ICMP_MINLEN + 16;
#endif

    struct sockaddr_in dst = cfg->target;
    (void)sendto(s, pkt, send_len, 0,
                 (const struct sockaddr *)&dst, sizeof(dst));

    struct timeval tv;
    tv.tv_sec = cfg->timeout_ms / 1000;
    tv.tv_usec = (cfg->timeout_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t rbuf[1024];
    struct sockaddr_in src;
    socklen_t sl = sizeof(src);
    ssize_t n = recvfrom(s, rbuf, sizeof(rbuf), 0,
                         (struct sockaddr *)&src, &sl);
    close(s);

    if (n <= (ssize_t)sizeof(struct ip))
        return;

    struct ip *ip = (struct ip *)rbuf;
    uint8_t ihl = (uint8_t)(ip->ip_hl * 4);
    if (n <= ihl)
        return;

#ifdef __linux__
    struct icmphdr *ri = (struct icmphdr *)(rbuf + ihl);
    out->responded = true;
    out->type = ri->type;
    out->code = ri->code;
#else
    struct icmp *ri = (struct icmp *)(rbuf + ihl);
    out->responded = true;
    out->type = ri->icmp_type;
    out->code = ri->icmp_code;
#endif
    out->ttl = ip->ip_ttl;
}

int np_tcp_fp_run(const np_tcp_fp_cfg_t *cfg, np_tcp_fp_vector_t *out)
{
    if (!cfg || !out)
        return -1;

    memset(out, 0, sizeof(*out));

    np_tcp_probe_cfg_t tcfg;
    memset(&tcfg, 0, sizeof(tcfg));
    tcfg.target = cfg->target;
    tcfg.open_port = cfg->open_port;
    tcfg.closed_port = cfg->closed_port;
    tcfg.timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms : 300;

    uint32_t seqs[6] = {0};
    uint8_t seq_count = 0;

    for (int i = 0; i < 6; i++) {
        np_tcp_probe_result_t *p = &out->tcp.probes[NP_PROBE_T1];
        np_send_tcp_probe(&tcfg, NP_PROBE_T1, p);
        if (p->responded && seq_count < 6)
            seqs[seq_count++] = p->seq;
        usleep(100000);
    }

    np_send_tcp_probe(&tcfg, NP_PROBE_ECN, &out->tcp.probes[NP_PROBE_ECN]);
    np_send_tcp_probe(&tcfg, NP_PROBE_T2, &out->tcp.probes[NP_PROBE_T2]);
    np_send_tcp_probe(&tcfg, NP_PROBE_T3, &out->tcp.probes[NP_PROBE_T3]);
    np_send_tcp_probe(&tcfg, NP_PROBE_T4, &out->tcp.probes[NP_PROBE_T4]);
    np_send_tcp_probe(&tcfg, NP_PROBE_T5, &out->tcp.probes[NP_PROBE_T5]);
    np_send_tcp_probe(&tcfg, NP_PROBE_T6, &out->tcp.probes[NP_PROBE_T6]);
    np_send_tcp_probe(&tcfg, NP_PROBE_T7, &out->tcp.probes[NP_PROBE_T7]);

    np_pipeline_ctx_t uctx;
    memset(&uctx, 0, sizeof(uctx));
    uctx.timeout_ms = tcfg.timeout_ms;
    uctx.icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    np_target_t utgt;
    memset(&utgt, 0, sizeof(utgt));
    utgt.addr = cfg->target;
    utgt.closed_port = cfg->closed_port;

    np_udp_probe_result_t u1;
    memset(&u1, 0, sizeof(u1));
    if (uctx.icmp_sock >= 0) {
        np_send_udp_u1(&uctx, &utgt, &u1);
        close(uctx.icmp_sock);
    }
    out->u1.responded = u1.responded;
    out->u1.type = u1.icmp_type;
    out->u1.code = u1.icmp_code;
    out->u1.ttl = u1.ttl;

    run_ie_probe(cfg, 0x00, 0, 0xBEEF, &out->ie1);
    run_ie_probe(cfg, 0x10, 0, 0xBEEF, &out->ie2);

    compute_seq_metrics(seqs, seq_count, &out->seq);

    const np_tcp_probe_result_t *primary = NULL;
    for (int i = 0; i < NP_MAX_TCP_PROBES; i++) {
        if (out->tcp.probes[i].responded) {
            primary = &out->tcp.probes[i];
            out->response_count++;
        }
    }

    if (primary) {
        out->ttl_observed = primary->ttl;
        out->ttl_initial = np_tcp_fp_infer_initial_ttl(primary->ttl);
        out->df = primary->df;
        out->window = primary->window;
        out->mss = primary->mss;
        out->wscale = primary->wscale;
        out->sack = primary->sack;
        out->ts = primary->timestamp;
        out->options_len = primary->opts_len;
        memcpy(out->options_order, primary->opts_raw, primary->opts_len);
    }

    out->ipid_behavior = classify_ipid(&out->tcp);
    return 0;
}
