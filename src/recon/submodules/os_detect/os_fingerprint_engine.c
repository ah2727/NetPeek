/*
 * NetPeek - Multi‑Probe OS Fingerprint Engine
 *
 * Runs TCP probes (T1–T7), builds fingerprint,
 * and matches against OS signature database.
 */

#include "recon/submodules/os_detect/os_detect.h"
#include "os_tcp_probes.h"
#include "os_signatures.h"
#include "os_sigload.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>


#define FP_LOG(fmt, ...) \
    printf("[FP-DEBUG] " fmt "\n", ##__VA_ARGS__)

static const char *ipid_type_str(uint8_t t)
{
    switch (t)
    {
        case 1:  return "INCREMENTAL";
        case 2:  return "RANDOM";
        case 3:  return "ZERO";
        default: return "UNKNOWN";
    }
}

static const char *ipid_behavior_str(uint8_t b)
{
    switch (b)
    {
        case 1:  return "INCREMENTAL";
        case 2:  return "RANDOM";
        default: return "UNKNOWN";
    }
}

void np_fingerprint_debug(
        const np_os_fingerprint_t *fp)
{
    if (!fp)
    {
        FP_LOG("NULL fingerprint");
        return;
    }

    FP_LOG("========== OS FINGERPRINT ==========");

    /* ------------------------------------------------ */
    /* IP layer                                         */
    /* ------------------------------------------------ */

    FP_LOG("IP Layer:");
    FP_LOG("  TTL observed        : %u", fp->ttl);
    FP_LOG("  TTL initial (guess) : %u", fp->ttl_initial);
    FP_LOG("  Hop distance        : %u", fp->ttl_hop_dist);
    FP_LOG("  Total Length        : %u", fp->total_length);
    FP_LOG("  IP ID               : %u (%s)",
           fp->ip_id,
           ipid_type_str(fp->ipid_type));

    /* ------------------------------------------------ */
    /* TCP basics                                       */
    /* ------------------------------------------------ */

    FP_LOG("TCP Basic:");
    FP_LOG("  Window Size         : %u", fp->window_size);
    FP_LOG("  DF Bit              : %s",
           fp->df_bit ? "SET" : "CLEAR");

    /* ------------------------------------------------ */
    /* TCP options                                      */
    /* ------------------------------------------------ */

    FP_LOG("TCP Options:");
    FP_LOG("  MSS                 : %u", fp->mss);
    FP_LOG("  Window Scale        : %u", fp->window_scale);
    FP_LOG("  SACK Permitted      : %s",
           fp->sack_permitted ? "YES" : "NO");
    FP_LOG("  Timestamp           : %s",
           fp->timestamp ? "YES" : "NO");

    FP_LOG("  Option Order        :");
    if (fp->tcp_options_count == 0)
    {
        FP_LOG("    <none>");
    }
    else
    {
        for (uint8_t i = 0; i < fp->tcp_options_count; i++)
        {
            FP_LOG("    [%u] %u",
                   i,
                   fp->tcp_options_order[i]);
        }
    }

    /* ------------------------------------------------ */
    /* Behavioral pattern                               */
    /* ------------------------------------------------ */

    FP_LOG("Behavior:");
    FP_LOG("  Response Pattern    : %s",
           fp->response_pattern);
    FP_LOG("  Probes Responded    : %u",
           fp->probes_responded);

    /* ------------------------------------------------ */
    /* Per‑probe detail                                 */
    /* ------------------------------------------------ */

    FP_LOG("Per‑Probe Details:");
    for (int i = 0; i < 7; i++)
    {
        FP_LOG("  Probe T%d:", i + 1);
        FP_LOG("    Responded         : %s",
               fp->probe_responded[i] ? "YES" : "NO");
        FP_LOG("    Window            : %u",
               fp->probe_window[i]);
        FP_LOG("    TTL               : %u",
               fp->probe_ttl[i]);
        FP_LOG("    DF                : %s",
               fp->probe_df[i] ? "SET" : "CLEAR");
        FP_LOG("    RST               : %s",
               fp->probe_rst[i] ? "YES" : "NO");
        FP_LOG("    ACK               : %s",
               fp->probe_ack[i] ? "YES" : "NO");
    }

    /* ------------------------------------------------ */
    /* Derived behavior                                 */
    /* ------------------------------------------------ */

    FP_LOG("Derived:");
    FP_LOG("  IPID Behavior       : %s",
           ipid_behavior_str(fp->ipid_behavior));
    FP_LOG("  Timestamp Rate      : %u",
           fp->ts_rate);
    FP_LOG("  Options Rewritten   : %s",
           fp->opt_rewritten ? "YES" : "NO");
    FP_LOG("  Environment Flags   : 0x%02X",
           fp->env_flags);
    FP_LOG("  Reliability         : %u%%",
           fp->reliability);

    /* ------------------------------------------------ */
    /* UDP closed‑port probe                             */
    /* ------------------------------------------------ */

    FP_LOG("UDP Closed‑Port (U1):");
    FP_LOG("  Responded           : %s",
           fp->u1_responded ? "YES" : "NO");

    if (fp->u1_responded)
    {
        FP_LOG("  ICMP Type           : %u",
               fp->u1_icmp_type);
        FP_LOG("  ICMP Code           : %u",
               fp->u1_icmp_code);
        FP_LOG("  TTL                 : %u",
               fp->u1_ttl);
    }

    FP_LOG("========== END FINGERPRINT ==========");
}

/* ---------------------------------------------------- */
/* logging macro                                        */
/* ---------------------------------------------------- */

#define OS_LOG(fmt, ...) \
    printf("[OS-ENGINE] " fmt "\n", ##__VA_ARGS__)


/* from os_fingerprint_builder.c */
int np_build_fingerprint_from_probes(
        const np_tcp_probe_set_t *set,
        np_os_fingerprint_t *fp);

void np_fingerprint_debug(
        const np_os_fingerprint_t *fp);


/* ---------------------------------------------------- */
/* find closed port helper                              */
/* ---------------------------------------------------- */

static uint16_t guess_closed_port(uint16_t open_port)
{
    if (open_port > 1)
        return open_port - 1;

    return open_port + 1;
}


/* ---------------------------------------------------- */
/* run fingerprint engine                               */
/* ---------------------------------------------------- */

int np_os_fingerprint_engine(
        const char *target_ip,
        uint16_t open_port,
        const np_os_sigdb_t *db,
        np_os_result_t *result)
{
    if (!target_ip || !db || !result)
    {
        OS_LOG("Invalid arguments passed to engine");
        return -1;
    }

    OS_LOG("Starting fingerprint engine");
    OS_LOG("Target IP: %s", target_ip);
    OS_LOG("Open port: %u", open_port);
    OS_LOG("Signature count: %u", db->fp_count);

    memset(result, 0, sizeof(*result));

    /* ------------------------------------------------ */
    /* prepare probe config                             */
    /* ------------------------------------------------ */

    np_tcp_probe_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.target.sin_family = AF_INET;

    if (inet_pton(AF_INET, target_ip,
                  &cfg.target.sin_addr) != 1)
    {
        OS_LOG("Invalid IPv4 address: %s", target_ip);
        return -1;
    }

    cfg.open_port   = open_port;
    cfg.closed_port = guess_closed_port(open_port);
    cfg.timeout_ms  = 1000;

    OS_LOG("Probe config prepared (open=%u closed=%u timeout=%u ms)",
           cfg.open_port,
           cfg.closed_port,
           cfg.timeout_ms);


    /* ------------------------------------------------ */
    /* run probes                                       */
    /* ------------------------------------------------ */

    np_tcp_probe_set_t probes;

    OS_LOG("Running TCP probes (T1–T7) ...");

    if (np_run_tcp_probes(&cfg, &probes) != 0)
    {
        OS_LOG("Probe execution failed");
        return -1;
    }

    OS_LOG("Probes completed successfully");


    /* ------------------------------------------------ */
    /* build fingerprint                                */
    /* ------------------------------------------------ */

    OS_LOG("Building fingerprint from probe responses...");

    if (np_build_fingerprint_from_probes(
            &probes,
            &result->fingerprint) != 0)
    {
        OS_LOG("Fingerprint build failed");
        return -1;
    }

    OS_LOG("Fingerprint successfully built");
    np_fingerprint_debug(&result->fingerprint);


    /* ------------------------------------------------ */
    /* match against signatures                         */
    /* ------------------------------------------------ */

    uint8_t best_score = 0;
    const np_os_fp_sig_t *best_sig = NULL;

    OS_LOG("Matching fingerprint against %u signatures...",
           db->fp_count);

    for (uint32_t i = 0; i < db->fp_count; i++)
    {
        const np_os_fp_sig_t *sig = &db->fp_sigs[i];

        uint8_t score =
            np_fingerprint_score(
                &result->fingerprint,
                sig,
                NULL);

        OS_LOG("Candidate: %-30s | Raw Score: %3u | Weight: %3u",
               sig->os_name,
               score,
               sig->weight);

        if (score > best_score)
        {
            best_score = score;
            best_sig   = sig;
        }
    }


    /* ------------------------------------------------ */
    /* no match                                         */
    /* ------------------------------------------------ */

    if (!best_sig || best_score == 0)
    {
        OS_LOG("No matching signature found");

        snprintf(result->best_os,
                 sizeof(result->best_os),
                 "Unknown");

        result->best_confidence = 0;

        OS_LOG("Final Result: Unknown (confidence=0%%)");
        return 0;
    }


    /* ------------------------------------------------ */
    /* fill result                                      */
    /* ------------------------------------------------ */

    snprintf(result->best_os,
             sizeof(result->best_os),
             "%s",
             best_sig->os_name);

    snprintf(result->best_family,
             sizeof(result->best_family),
             "%s",
             best_sig->os_family ? best_sig->os_family : "");

    result->best_confidence =
        (best_score * best_sig->weight) / 100;

    OS_LOG("Best match: %s", result->best_os);
    OS_LOG("Raw score: %u", best_score);
    OS_LOG("Weight: %u", best_sig->weight);
    OS_LOG("Final confidence: %u%%",
           result->best_confidence);

    OS_LOG("Fingerprint engine finished successfully");

    return 0;
}
